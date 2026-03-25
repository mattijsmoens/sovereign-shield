"""
TruthGuard — Factual Hallucination Detection Engine
=====================================================
Detects when an AI makes factual claims without verification through tools.
Scans LLM OUTPUT (not input) for unverified confidence markers.

Architecture:
    1. Session tool tracking — knows which verification tools were called
    2. Confidence marker detection — regex catches unverified factual claims
    3. Hedging detection — allows appropriately uncertain language
    4. Verification enforcement — blocks claims without tool verification
    5. Fact cache — stores verified facts with TTL for reuse

Toggle: Pass enabled=False to disable all checks (e.g. for SaaS mode).

Zero external dependencies. Pure Python stdlib.
"""

import hashlib
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from typing import Dict, List, Optional, Set

logger = logging.getLogger("sovereign_shield.truth_guard")

# ===================================================================
# PRE-COMPILED CONFIDENCE MARKER PATTERNS
# ===================================================================

# Temporal certainty — claims about current state
_TEMPORAL_MARKERS = re.compile(
    r'\b(currently|right now|as of (today|now|\d{4})|at this moment|'
    r'at the time of writing|today\'s|latest|up[- ]to[- ]date|real[- ]time)\b',
    re.IGNORECASE
)

# Statistical/numerical claims
_NUMERICAL_CLAIM = re.compile(
    r'(\$[\d,]+\.?\d*|'
    r'\b\d{1,3}(,\d{3})+(\.\d+)?\b|'
    r'\b\d+(\.\d+)?%|'
    r'\b\d+(\.\d+)?\s*(million|billion|trillion|thousand)\b)',
    re.IGNORECASE
)

# Citation hallucination — claiming sources without verification
_CITATION_MARKERS = re.compile(
    r'\b(according to|studies show|research (indicates|shows|suggests|proves)|'
    r'experts (say|agree|believe)|data (shows|indicates|suggests)|'
    r'statistics (show|indicate|prove)|surveys (show|indicate)|'
    r'it (has been|is) (proven|shown|demonstrated|established)|'
    r'peer[- ]reviewed|published in|reported by|'
    r'a recent (study|report|survey|analysis))\b',
    re.IGNORECASE
)

# False certainty — overconfident factual claims
_CERTAINTY_MARKERS = re.compile(
    r'\b(the (answer|fact|truth|reality) is|'
    r'it is (exactly|precisely|definitely|certainly|undeniably)|'
    r'I (know|can confirm|can verify) (that|for a fact)|'
    r'without (a )?doubt|there is no question|'
    r'I have (verified|confirmed|checked)|'
    r'the (exact|precise) (number|figure|amount|value) is)\b',
    re.IGNORECASE
)

# Hedging language — indicates appropriate uncertainty (GOOD behavior)
_HEDGE_MARKERS = re.compile(
    r'\b(I\'?m not (sure|certain)|I (think|believe|suspect)|'
    r'(maybe|perhaps|possibly|probably|likely|approximately|roughly|around|about)|'
    r'I don\'?t (know|have|remember)|'
    r'I\'?d need to (check|verify|look|search|confirm)|'
    r'I\'?m not (confident|able to confirm)|'
    r'(could|might|may) be|'
    r'if I (recall|remember) correctly|'
    r'I (can\'?t|cannot) (verify|confirm)|'
    r'to the best of my knowledge|as far as I know)\b',
    re.IGNORECASE
)

# Default verification tools
DEFAULT_VERIFICATION_TOOLS: Set[str] = {
    "SEARCH", "BROWSE", "READ_FILE", "LOOKUP", "QUERY",
    "WEB_SEARCH", "GOOGLE", "FETCH", "API_CALL",
}

# ===================================================================
# DATABASE SCHEMA
# ===================================================================

_SCHEMA = """
CREATE TABLE IF NOT EXISTS session_tools (
    session_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    query TEXT,
    result_summary TEXT,
    timestamp REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS verified_facts (
    fact_id TEXT PRIMARY KEY,
    claim_hash TEXT NOT NULL,
    claim_text TEXT NOT NULL,
    source TEXT NOT NULL,
    tool_used TEXT NOT NULL,
    verified_at REAL NOT NULL,
    ttl_days INTEGER NOT NULL DEFAULT 7
);

CREATE TABLE IF NOT EXISTS blocked_claims (
    claim_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    claim_text TEXT NOT NULL,
    confidence_markers TEXT NOT NULL,
    reason TEXT NOT NULL,
    timestamp REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS truth_checks (
    check_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    answer_text TEXT NOT NULL,
    had_markers INTEGER NOT NULL,
    had_verification INTEGER NOT NULL,
    allowed INTEGER NOT NULL,
    reason TEXT NOT NULL,
    timestamp REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fact_hash ON verified_facts(claim_hash);
CREATE INDEX IF NOT EXISTS idx_session ON session_tools(session_id);
CREATE INDEX IF NOT EXISTS idx_truth_session ON truth_checks(session_id);
"""


class TruthGuard:
    """
    Factual hallucination detection and verified fact caching.

    Tracks tool usage per session and detects when the AI makes
    factual claims without having verified them through tools.

    Toggle: Pass enabled=False to disable (e.g. SaaS stateless mode).

    Usage:
        guard = TruthGuard(db_path="./data/truth.db")
        guard.start_session("session-001")
        guard.record_tool_use("session-001", "SEARCH", "bitcoin price")
        ok, reason = guard.check_answer("session-001", "Bitcoin is currently $84,322")
    """

    def __init__(
        self,
        db_path: str = os.path.join("data", "truth_guard.db"),
        verification_tools: Optional[Set[str]] = None,
        fact_ttl_days: int = 7,
        static_fact_ttl_days: int = 90,
        retention_days: int = 30,
        enabled: bool = True,
    ):
        """
        Args:
            db_path: Path to SQLite database for fact cache and logs.
            verification_tools: Tool names that count as verification.
            fact_ttl_days: TTL for temporal facts (prices, dates, etc.).
            static_fact_ttl_days: TTL for static facts (definitions, etc.).
            retention_days: How long to keep check logs.
            enabled: If False, all checks return (True, "TruthGuard disabled").
        """
        self.enabled = enabled
        self._db_path = db_path
        self._verification_tools = verification_tools or DEFAULT_VERIFICATION_TOOLS
        self._fact_ttl_days = fact_ttl_days
        self._static_fact_ttl_days = static_fact_ttl_days
        self._retention_days = retention_days
        self._lock = threading.Lock()
        self._sessions: Dict[str, List[dict]] = {}

        if self.enabled:
            self._init_db()
            self._cleanup(self._retention_days)

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

    def _cleanup(self, days: int):
        cutoff = time.time() - (days * 86400)
        conn = self._get_conn()
        conn.execute("DELETE FROM truth_checks WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM blocked_claims WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM session_tools WHERE timestamp < ?", (cutoff,))
        conn.execute(
            "DELETE FROM verified_facts WHERE (verified_at + ttl_days * 86400) < ?",
            (time.time(),)
        )
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # SESSION MANAGEMENT
    # ------------------------------------------------------------------

    def start_session(self, session_id: str):
        """Start tracking a new session."""
        self._sessions[session_id] = []

    def end_session(self, session_id: str):
        """End and clean up a session from memory."""
        self._sessions.pop(session_id, None)

    def record_tool_use(self, session_id: str, tool_name: str,
                        query: str = "", result_summary: str = ""):
        """Record that a verification tool was used in this session."""
        if not self.enabled:
            return

        tool_upper = tool_name.upper()
        record = {
            "tool_name": tool_upper,
            "query": query,
            "result_summary": result_summary,
            "timestamp": time.time(),
        }

        if session_id not in self._sessions:
            self._sessions[session_id] = []
        self._sessions[session_id].append(record)

        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT INTO session_tools (session_id, tool_name, query, "
                "result_summary, timestamp) VALUES (?, ?, ?, ?, ?)",
                (session_id, tool_upper, query, result_summary, time.time()),
            )
            conn.commit()
            conn.close()

    def _session_has_verification(self, session_id: str) -> bool:
        """Check if any verification tool was used in this session."""
        if session_id in self._sessions:
            return any(
                t["tool_name"] in self._verification_tools
                for t in self._sessions[session_id]
            )
        conn = self._get_conn()
        cur = conn.cursor()
        placeholders = ",".join("?" for _ in self._verification_tools)
        cur.execute(
            f"SELECT COUNT(*) as c FROM session_tools "
            f"WHERE session_id = ? AND tool_name IN ({placeholders})",
            (session_id, *self._verification_tools),
        )
        count = cur.fetchone()["c"]
        conn.close()
        return count > 0

    # ------------------------------------------------------------------
    # CONFIDENCE MARKER DETECTION
    # ------------------------------------------------------------------

    @staticmethod
    def detect_confidence_markers(text: str) -> List[str]:
        """Scan text for confidence markers indicating factual claims."""
        markers = []
        if _TEMPORAL_MARKERS.search(text):
            markers.append("temporal")
        if _NUMERICAL_CLAIM.search(text):
            sentences = re.split(r'[.!?]', text)
            for sentence in sentences:
                if _NUMERICAL_CLAIM.search(sentence):
                    s_lower = sentence.lower().strip()
                    trivial = (
                        s_lower.startswith("step ") or
                        s_lower.startswith("option ") or
                        s_lower.startswith("item ") or
                        ("results" in s_lower and len(sentence) < 40)
                    )
                    if not trivial:
                        markers.append("numerical")
                        break
        if _CITATION_MARKERS.search(text):
            markers.append("citation")
        if _CERTAINTY_MARKERS.search(text):
            markers.append("certainty")
        return markers

    @staticmethod
    def has_hedging(text: str) -> bool:
        """Check if text contains hedging language (appropriate uncertainty)."""
        return bool(_HEDGE_MARKERS.search(text))

    # ------------------------------------------------------------------
    # FACT CACHE
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_claim(text: str) -> str:
        """Generate a normalized hash for a factual claim."""
        normalized = re.sub(r'[^\w\s]', '', text.lower()).strip()
        normalized = re.sub(r'\s+', ' ', normalized)
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def store_verified_fact(self, claim_text: str, source: str,
                           tool_used: str, ttl_days: Optional[int] = None):
        """Store a verified fact in the cache."""
        if not self.enabled:
            return

        if ttl_days is None:
            if _TEMPORAL_MARKERS.search(claim_text):
                ttl_days = self._fact_ttl_days
            else:
                ttl_days = self._static_fact_ttl_days

        fact_id = uuid.uuid4().hex[:12]
        claim_hash = self._hash_claim(claim_text)

        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT OR REPLACE INTO verified_facts "
                "(fact_id, claim_hash, claim_text, source, tool_used, verified_at, ttl_days) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (fact_id, claim_hash, claim_text, source, tool_used,
                 time.time(), ttl_days),
            )
            conn.commit()
            conn.close()

    def lookup_fact(self, claim_text: str) -> Optional[dict]:
        """Check if a fact has been previously verified and is still valid."""
        if not self.enabled:
            return None

        claim_hash = self._hash_claim(claim_text)
        now = time.time()
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM verified_facts WHERE claim_hash = ? "
            "AND (verified_at + ttl_days * 86400) > ?",
            (claim_hash, now),
        )
        row = cur.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None

    # ------------------------------------------------------------------
    # ANSWER VERIFICATION
    # ------------------------------------------------------------------

    def check_answer(self, session_id: str, answer_text: str) -> tuple:
        """
        Check if an answer contains unverified factual claims.

        Logic:
            1. Disabled → allow
            2. No markers → allow (opinion/chat)
            3. Markers + hedging → allow (appropriate uncertainty)
            4. Markers + tool used → allow (verified)
            5. Markers + cached fact → allow (previously verified)
            6. Otherwise → block (unverified factual claim)

        Returns:
            tuple: (allowed: bool, reason: str)
        """
        if not self.enabled:
            return True, "TruthGuard is disabled."

        check_id = uuid.uuid4().hex[:12]
        markers = self.detect_confidence_markers(answer_text)

        if not markers:
            self._log_check(check_id, session_id, answer_text,
                           had_markers=False, had_verification=False,
                           allowed=True, reason="No factual claims detected.")
            return True, "No factual claims detected."

        if self.has_hedging(answer_text):
            self._log_check(check_id, session_id, answer_text,
                           had_markers=True, had_verification=False,
                           allowed=True,
                           reason="Factual markers found but hedged with uncertainty.")
            return True, "Factual markers found but appropriately hedged."

        has_verification = self._session_has_verification(session_id)

        if has_verification:
            self._log_check(check_id, session_id, answer_text,
                           had_markers=True, had_verification=True,
                           allowed=True,
                           reason=f"Verified: tool used this session. Markers: {markers}")
            return True, "Verified: verification tool used this session."

        # Check fact cache
        sentences = re.split(r'[.!?]+', answer_text)
        cached = None
        for sentence in sentences:
            sentence = sentence.strip()
            if len(sentence) > 10:
                cached = self.lookup_fact(sentence)
                if cached:
                    break
        if cached:
            self._log_check(check_id, session_id, answer_text,
                           had_markers=True, had_verification=True,
                           allowed=True,
                           reason=f"Cached fact (verified {cached['tool_used']})")
            return True, f"Previously verified fact (cached from {cached['tool_used']})."

        # Block — unverified factual claim
        marker_str = ", ".join(markers)
        reason = (f"Unverified factual claim: {marker_str} markers detected, "
                  f"no verification tool used this session.")
        self._log_check(check_id, session_id, answer_text,
                       had_markers=True, had_verification=False,
                       allowed=False, reason=reason)
        self._log_blocked_claim(session_id, answer_text, marker_str, reason)
        logger.warning(f"[TruthGuard] BLOCKED: {reason}")
        return False, reason

    def _log_check(self, check_id, session_id, answer_text,
                   had_markers, had_verification, allowed, reason):
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT INTO truth_checks (check_id, session_id, answer_text, "
                "had_markers, had_verification, allowed, reason, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (check_id, session_id, answer_text[:500],
                 int(had_markers), int(had_verification),
                 int(allowed), reason, time.time()),
            )
            conn.commit()
            conn.close()

    def _log_blocked_claim(self, session_id, claim_text, markers, reason):
        claim_id = uuid.uuid4().hex[:12]
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT INTO blocked_claims (claim_id, session_id, claim_text, "
                "confidence_markers, reason, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (claim_id, session_id, claim_text[:500], markers, reason,
                 time.time()),
            )
            conn.commit()
            conn.close()

    @property
    def stats(self) -> dict:
        """Usage statistics."""
        if not self.enabled:
            return {"enabled": False}
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM truth_checks")
        total = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM truth_checks WHERE allowed = 1")
        allowed = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM truth_checks WHERE allowed = 0")
        blocked = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) as c FROM verified_facts")
        facts = cur.fetchone()["c"]
        conn.close()
        return {
            "enabled": True,
            "total_checks": total,
            "total_allowed": allowed,
            "total_blocked": blocked,
            "cached_facts": facts,
            "active_sessions": len(self._sessions),
        }
