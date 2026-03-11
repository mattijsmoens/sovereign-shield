"""
AdaptiveShield — Self-improving security filter.

All-in-one class that wraps SovereignShield's InputFilter with:
  - Local SQLite storage for scan history
  - Report endpoint for missed attacks
  - Sandbox replay to validate candidate rules
  - Auto-deployment of validated rules at runtime

Zero cloud dependencies. Works entirely offline.
"""

import os
import time
import uuid
import sqlite3
import threading
import logging
from typing import Optional, List, Set, Dict

from .input_filter import InputFilter, DEFAULT_BAD_SIGNALS

logger = logging.getLogger("adaptive_shield")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_log (
    scan_id TEXT PRIMARY KEY,
    input_text TEXT NOT NULL,
    allowed INTEGER NOT NULL,
    stage TEXT NOT NULL,
    reason TEXT NOT NULL,
    timestamp REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    reported_input TEXT NOT NULL,
    reason TEXT NOT NULL,
    timestamp REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS rules (
    rule_id TEXT PRIMARY KEY,
    pattern TEXT NOT NULL,
    source_report_id TEXT NOT NULL,
    false_positive_rate REAL NOT NULL DEFAULT 0,
    tested_against INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_allowed ON scan_log(allowed);
"""


class AdaptiveShield:
    """
    Self-improving input security filter.

    Args:
        db_path: Path to SQLite database file (default: ./data/adaptive.db)
        extra_keywords: Additional keywords to block on top of defaults
        fp_threshold: Max false positive rate for auto-approving rules (default: 1%)
        retention_days: How long to keep scan history (default: 30)
        auto_deploy: If True, validated rules deploy automatically.
                     If False, all rules go to 'pending' for manual review.
    """

    def __init__(
        self,
        db_path: str = os.path.join("data", "adaptive.db"),
        extra_keywords: Optional[List[str]] = None,
        fp_threshold: float = 0.01,
        retention_days: int = 30,
        auto_deploy: bool = True,
    ):
        self._db_path = db_path
        self._fp_threshold = fp_threshold
        self._retention_days = retention_days
        self._auto_deploy = auto_deploy
        self._lock = threading.Lock()

        # Built-in filter
        signals = list(DEFAULT_BAD_SIGNALS)
        if extra_keywords:
            signals.extend(extra_keywords)
        self._filter = InputFilter(bad_signals=signals)

        # Custom rules loaded from DB
        self._custom_rules: Set[str] = set()

        # Init database
        self._init_db()

        # Load any previously approved rules
        self._load_approved_rules()

        # Cleanup old entries
        self._cleanup(self._retention_days)

    # ------------------------------------------------------------------
    # DATABASE
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript(_SCHEMA)
        conn.commit()
        conn.close()

    def _load_approved_rules(self):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT pattern FROM rules WHERE status = 'approved'")
        for row in cur.fetchall():
            self._custom_rules.add(row["pattern"].lower())
        conn.close()
        if self._custom_rules:
            logger.info(f"Loaded {len(self._custom_rules)} custom rules from database.")

    def _cleanup(self, days: int):
        cutoff = time.time() - (days * 86400)
        conn = self._get_conn()
        conn.execute("DELETE FROM scan_log WHERE timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # SCAN
    # ------------------------------------------------------------------

    def scan(self, text: str) -> dict:
        """
        Scan input text through all security layers.

        Returns:
            dict with keys: scan_id, allowed, stage, reason, clean_input
        """
        scan_id = uuid.uuid4().hex[:12]
        start = time.perf_counter()

        # Layer 1: Built-in filter
        is_safe, result = self._filter.process(text)

        # Layer 2: Custom adaptive rules
        if is_safe and self._custom_rules:
            text_lower = text.lower()
            for rule in self._custom_rules:
                if rule in text_lower:
                    is_safe = False
                    result = f"Blocked by adaptive rule: matched '{rule}'"
                    break

        stage = "Approved" if is_safe else "InputFilter"
        reason = "Input is clean." if is_safe else result
        latency = (time.perf_counter() - start) * 1000

        # Record scan
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT INTO scan_log (scan_id, input_text, allowed, stage, reason, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, text, int(is_safe), stage, reason, time.time()),
            )
            conn.commit()
            conn.close()

        return {
            "scan_id": scan_id,
            "allowed": is_safe,
            "stage": stage,
            "reason": reason,
            "clean_input": result if is_safe else None,
            "latency_ms": round(latency, 2),
        }

    # ------------------------------------------------------------------
    # REPORT
    # ------------------------------------------------------------------

    def report(self, scan_id: str, reason: str) -> dict:
        """
        Report a missed attack (false negative).

        The system will:
        1. Look up the original input
        2. Sandbox-test the pattern against historical allowed scans
        3. Auto-deploy the rule if false positive rate is below threshold

        Args:
            scan_id: The scan_id from a previous scan() call
            reason: Why you believe this should have been blocked

        Returns:
            dict with: report_id, status, rule_created, sandbox_result, message
        """
        # Look up original scan
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT input_text, allowed FROM scan_log WHERE scan_id = ?",
            (scan_id,),
        )
        row = cur.fetchone()
        conn.close()

        if not row:
            return {"report_id": None, "status": "error", "rule_created": False,
                    "message": "Scan ID not found. It may have expired."}

        if not row["allowed"]:
            return {"report_id": None, "status": "error", "rule_created": False,
                    "message": "This scan was already blocked. Only allowed scans can be reported."}

        input_text = row["input_text"]
        if not input_text or len(input_text.strip()) < 5:
            return {"report_id": None, "status": "stored", "rule_created": False,
                    "message": "Input too short for automatic rule creation."}

        # Save report
        report_id = uuid.uuid4().hex[:12]
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT INTO reports (report_id, scan_id, reported_input, reason, timestamp, status) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (report_id, scan_id, input_text, reason, time.time(), "pending"),
            )
            conn.commit()
            conn.close()

        # Candidate pattern = full input lowercased
        pattern = input_text.strip().lower()

        # Sandbox replay (exclude the reported scan itself)
        sandbox = self._replay(pattern, exclude_scan_id=scan_id)

        rule_id = uuid.uuid4().hex[:12]
        passes_threshold = sandbox["false_positive_rate"] <= self._fp_threshold

        if passes_threshold and self._auto_deploy:
            # Auto-approve and deploy immediately
            self._save_rule(rule_id, pattern, report_id, sandbox, "approved")
            self._custom_rules.add(pattern)
            logger.info(f"Auto-approved rule '{pattern}' (FP: {sandbox['false_positive_rate']})")

            return {
                "report_id": report_id,
                "status": "auto_approved",
                "rule_created": True,
                "sandbox_result": sandbox,
                "message": f"Rule deployed. Pattern will now be blocked. "
                           f"Tested against {sandbox['total_tested']} scans, "
                           f"FP rate: {sandbox['false_positive_rate']*100:.1f}%.",
            }
        elif passes_threshold and not self._auto_deploy:
            # Passes threshold but user wants manual review
            self._save_rule(rule_id, pattern, report_id, sandbox, "pending")
            logger.info(f"Rule '{pattern}' ready for approval (auto_deploy=False)")

            return {
                "report_id": report_id,
                "status": "ready_for_approval",
                "rule_created": False,
                "sandbox_result": sandbox,
                "message": f"Rule passed validation (FP: {sandbox['false_positive_rate']*100:.1f}%). "
                           f"Call approve_rule('{rule_id}') to deploy it.",
            }
        else:
            # Too many false positives
            self._save_rule(rule_id, pattern, report_id, sandbox, "pending")
            logger.info(f"Rule '{pattern}' pending review (FP: {sandbox['false_positive_rate']})")

            return {
                "report_id": report_id,
                "status": "pending_review",
                "rule_created": False,
                "sandbox_result": sandbox,
                "message": f"Rule needs review. Would cause {sandbox['would_block']} "
                           f"false positives out of {sandbox['total_tested']} scans "
                           f"({sandbox['false_positive_rate']*100:.1f}% FP rate).",
            }

    # ------------------------------------------------------------------
    # SANDBOX REPLAY
    # ------------------------------------------------------------------

    def _replay(self, pattern: str, exclude_scan_id: str = "") -> dict:
        """Test a pattern against all historical allowed scans."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT input_text FROM scan_log WHERE allowed = 1 AND input_text != '' AND scan_id != ?",
            (exclude_scan_id,)
        )
        rows = cur.fetchall()
        conn.close()

        total = len(rows)
        if total == 0:
            return {"total_tested": 0, "would_block": 0, "false_positive_rate": 0.0}

        pattern_lower = pattern.lower()
        would_block = sum(1 for r in rows if pattern_lower in r["input_text"].lower())
        fp_rate = would_block / total

        return {
            "total_tested": total,
            "would_block": would_block,
            "false_positive_rate": round(fp_rate, 4),
        }

    def _save_rule(self, rule_id, pattern, report_id, sandbox, status):
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT INTO rules (rule_id, pattern, source_report_id, "
                "false_positive_rate, tested_against, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (rule_id, pattern, report_id, sandbox["false_positive_rate"],
                 sandbox["total_tested"], status, time.time()),
            )
            conn.commit()
            conn.close()

    # ------------------------------------------------------------------
    # ADMIN HELPERS
    # ------------------------------------------------------------------

    def get_rules(self, status: Optional[str] = None) -> List[dict]:
        """Get all rules, optionally filtered by status."""
        conn = self._get_conn()
        cur = conn.cursor()
        if status:
            cur.execute("SELECT * FROM rules WHERE status = ?", (status,))
        else:
            cur.execute("SELECT * FROM rules")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def approve_rule(self, rule_id: str) -> bool:
        """Manually approve a pending rule."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT pattern FROM rules WHERE rule_id = ?", (rule_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return False
        pattern = row["pattern"].lower()
        conn.execute("UPDATE rules SET status = 'approved' WHERE rule_id = ?", (rule_id,))
        conn.commit()
        conn.close()
        self._custom_rules.add(pattern)
        return True

    def reject_rule(self, rule_id: str) -> bool:
        """Manually reject a pending rule."""
        conn = self._get_conn()
        conn.execute("UPDATE rules SET status = 'rejected' WHERE rule_id = ?", (rule_id,))
        conn.commit()
        conn.close()
        return True

    def approve_all_pending(self) -> int:
        """Approve all pending rules that passed the FP threshold. Returns count approved."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT rule_id, pattern FROM rules WHERE status = 'pending' AND false_positive_rate <= ?",
            (self._fp_threshold,)
        )
        rows = cur.fetchall()
        count = 0
        for row in rows:
            conn.execute("UPDATE rules SET status = 'approved' WHERE rule_id = ?", (row["rule_id"],))
            self._custom_rules.add(row["pattern"].lower())
            count += 1
        conn.commit()
        conn.close()
        return count

    def get_reports(self) -> list[dict]:
        """Get all submitted reports."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM reports ORDER BY timestamp DESC")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    @property
    def pending_rules(self) -> list[dict]:
        """Get all rules waiting for approval."""
        return self.get_rules(status="pending")

    @property
    def active_rules(self) -> set[str]:
        """Currently active custom rules (read-only copy)."""
        return set(self._custom_rules)

    @property
    def stats(self) -> dict:
        """Quick stats about the adaptive system."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM scan_log")
        total_scans = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM reports")
        total_reports = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM rules WHERE status = 'approved'")
        approved = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM rules WHERE status = 'pending'")
        pending = cur.fetchone()["c"]
        conn.close()
        return {
            "total_scans": total_scans,
            "total_reports": total_reports,
            "approved_rules": approved,
            "pending_rules": pending,
            "active_custom_rules": len(self._custom_rules),
        }
