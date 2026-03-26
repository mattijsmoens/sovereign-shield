"""
AdaptiveShield — Self-improving security filter.

All-in-one class that wraps SovereignShield's InputFilter with:
  - Local SQLite storage for scan history
  - Report endpoint for missed attacks
  - Category-based keyword extraction and classification
  - Sandbox replay to validate candidate rules
  - Auto-deployment of validated rules at runtime
  - Self-expanding minefield: one report blocks an entire attack class

Zero cloud dependencies. Works entirely offline.
"""

import os
import time
import uuid
import sqlite3
import threading
import logging
import json
from typing import Optional, List, Set, Dict

from .input_filter import InputFilter, DEFAULT_BAD_SIGNALS

logger = logging.getLogger("adaptive_shield")

# 1. Load the Safe Baseline (Common words in 15 languages)
# These words are NEVER stored as attack keywords during training.
_SAFE_BASELINE: Set[str] = set()
_baseline_path = os.path.join(os.path.dirname(__file__), "data", "common_words.json")
if os.path.exists(_baseline_path):
    try:
        with open(_baseline_path, 'r', encoding='utf-8') as f:
            _SAFE_BASELINE = set(json.load(f))
    except Exception as e:
        logger.error(f"Failed to load Safe Baseline: {e}")

# Unified Security Terms — keywords that are ALWAYS informative
_SECURITY_TERMS = {
    "bypass", "ignore", "reset", "system", "admin", "privileged",
    "access", "disable", "override", "instruction", "instructions",
    "prompt", "developer", "payload", "execute", "shell", "root",
    "sensitive", "hidden", "internal", "config", "debug", "token",
    "jailbreak", "pwned", "unfilter", "unrestricted", "security",
    "database", "drop", "delete", "format", "shutdown", "reboot",
    # Danger Action/Target expansion (Consistency with InputFilter)
    "safety", "rules", "file", "cat", "rm", "rf", "nuke", "lift",
    "skip", "show", "leak", "dump", "wipe", "revoke", "purge",
    "erase", "lift", "strip", "shred", "flush", "zero", "cat",
    "type", "show", "print", "read", "reveal", "output", "display",
    "limits", "chains", "filters", "bounds", "policies", "measures",
}

# Predefined attack category keyword clusters
ATTACK_CATEGORIES: Dict[str, List[str]] = {
    "exfiltration": [
        "extract", "dump", "reveal", "show", "leak", "expose", "export",
        "steal", "exfiltrate", "copy", "send", "transmit", "email",
    ],
    "injection": [
        "execute", "run", "eval", "system", "shell", "cmd", "exec",
        "subprocess", "popen", "os.system", "bash", "powershell",
    ],
    "impersonation": [
        "i am the admin", "override", "bypass", "emergency", "disable",
        "i am authorized", "maintenance mode", "superuser",
    ],
    "encoding_bypass": [
        "base64", "hex", "unicode", "encode", "decode", "rot13",
        "binary", "obfuscate", "encrypt",
    ],
    "data_access": [
        "password", "credential", "secret", "api key", "token",
        "config", "connection string", "private key", "certificate",
    ],
    "persistence": [
        "scheduled", "cron", "recurring", "backdoor", "persist",
        "reverse shell", "callback", "webhook",
    ],
    "destruction": [
        "delete", "drop", "truncate", "destroy", "wipe", "erase",
        "format", "rm -rf", "purge", "remove all",
    ],
}

# Comprehensive stopwords — never stored as attack keywords during training.
# Includes: articles, prepositions, pronouns, conjunctions, common verbs,
# greetings, everyday nouns, question words, and high-frequency words
# that appear equally in benign and attack inputs.
_STOPWORDS = {
    # Articles, prepositions, conjunctions
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "can", "shall", "to", "of", "in", "for",
    "on", "with", "at", "by", "from", "as", "into", "through", "about",
    "and", "but", "or", "nor", "not", "so", "yet", "both", "either",
    "neither", "this", "that", "these", "those", "it", "its", "my",
    "your", "his", "her", "our", "their", "me", "him", "us", "them",
    "i", "you", "he", "she", "we", "they", "what", "which", "who",
    "how", "when", "where", "why", "all", "each", "every", "some",
    "any", "no", "just", "also", "very", "too", "please", "then",
    "now", "here", "there", "up", "out", "if", "than", "after",
    "before", "above", "below", "between", "under", "over",
    # Greetings and polite words
    "hello", "hi", "hey", "goodbye", "bye", "thanks", "thank",
    "sorry", "welcome", "ok", "okay", "yes", "no", "yeah", "nope",
    # Common verbs (too generic to be attack signals)
    "get", "got", "give", "gave", "make", "made", "take", "took",
    "come", "came", "go", "went", "gone", "see", "saw", "seen",
    "know", "knew", "known", "think", "thought", "want", "need",
    "like", "look", "looked", "find", "found", "tell", "told",
    "ask", "asked", "try", "tried", "use", "used", "work", "worked",
    "call", "called", "keep", "kept", "let", "help", "helped",
    "start", "started", "show", "showed", "hear", "heard",
    "play", "played", "move", "moved", "live", "lived",
    "believe", "bring", "brought", "happen", "happened",
    "write", "wrote", "written", "read", "provide", "provided",
    "set", "put", "mean", "meant", "become", "became",
    "leave", "left", "begin", "began", "seem", "seemed",
    "follow", "followed", "create", "created", "speak", "spoke",
    "allow", "allowed", "add", "added", "grow", "grew",
    "open", "opened", "walk", "walked", "offer", "offered",
    "remember", "consider", "appear", "appeared", "serve", "served",
    "expect", "expected", "suggest", "suggested",
    # Common everyday nouns
    "world", "people", "time", "year", "day", "way", "man", "woman",
    "child", "thing", "life", "hand", "part", "place", "case",
    "week", "company", "group", "problem", "fact",
    "good", "great", "new", "old", "big", "small", "long", "short",
    "right", "left", "best", "last", "first", "next", "other",
    "name", "word", "number", "line", "point", "home", "water",
    "room", "area", "money", "story", "book", "answer", "question",
    "side", "head", "house", "game", "example", "food",
    # Tech words too generic to signal attacks
    "code", "data", "file", "user", "test", "type", "text",
    "list", "sort", "page", "link", "site", "web", "app",
    "program", "function", "class", "method", "object", "value",
    "result", "output", "input", "error", "message",
    "save", "load", "send", "stop", "using", "like",
    # More high-frequency benign words
    "more", "most", "much", "many", "well", "back", "even",
    "still", "own", "same", "different", "such", "only", "really",
    "always", "never", "often", "sometimes", "already", "sure",
    "must", "should", "ought", "might", "may", "can", "could",
    "absolutely", "entirely", "completely", "fully", "totally", "partially", "slightly",
    "sentence", "sentences", "translate", "french", "english", "spanish",
    "german", "language", "meaning", "define", "explain",
    "character", "characters", "letter", "letters", "word", "words",
    "today", "tomorrow", "yesterday", "morning", "night",
    "many", "most", "several", "much", "very", "too", "enough",
    "everything", "something", "anything", "nothing", "around",
    "specifically", "basically", "clearly", "possibly", "usually",
    "often", "always", "sometimes", "already", "sure",
    "edit", "reveal", "describe", "explain", "summarize", "spelling", "grammar",
    "mistake", "mistakes", "check", "checks", "verify", "correct", "improve",
    "improvement", "text", "write", "provide", "setting", "settings",
}

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

CREATE TABLE IF NOT EXISTS attack_categories (
    category TEXT NOT NULL,
    keyword TEXT NOT NULL,
    source_report_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (category, keyword)
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
        allow_pruning: bool = True,
    ):
        self._db_path = db_path
        self._fp_threshold = fp_threshold
        self._retention_days = retention_days
        self._auto_deploy = auto_deploy
        self._allow_pruning = allow_pruning
        self._lock = threading.Lock()

        # Built-in filter
        signals = list(DEFAULT_BAD_SIGNALS)
        if extra_keywords:
            signals.extend(extra_keywords)
        self._filter = InputFilter(bad_signals=signals)

        # Custom rules loaded from DB (legacy exact-match patterns)
        self._custom_rules: Set[str] = set()

        # Category keywords loaded from DB (v2 self-expanding minefield)
        self._category_keywords: Dict[str, Set[str]] = {}

        # Init database
        self._init_db()

        # Load any previously approved rules
        self._load_approved_rules()

        # Load learned category keywords
        self._load_category_keywords()

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

    def _auto_seed(self):
        """On first run (empty DB), auto-import bundled training data."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM rules")
        rule_count = cur.fetchone()[0]
        conn.close()

        if rule_count > 0:
            return  # DB already has data

        # Look for bundled trained_rules.json next to this module
        json_path = os.path.join(os.path.dirname(__file__), "trained_rules.json")
        if os.path.exists(json_path):
            self.import_rules_json(json_path)
            logger.info(f"Auto-seeded from bundled training data: {json_path}")

    def import_rules_json(self, path: str):
        """
        Import rules and keywords from a JSON file into the database.

        Expects format: {"category_keywords": {...}, "approved_rules": [...]}
        """
        import json

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        conn = self._get_conn()
        now = time.time()

        # Batch import approved rules
        rule_rows = [
            (r["rule_id"], r["pattern"], "imported", 0.0, 0, "approved", now)
            for r in data.get("approved_rules", [])
        ]
        if rule_rows:
            conn.executemany(
                "INSERT OR IGNORE INTO rules (rule_id, pattern, source_report_id, "
                "false_positive_rate, tested_against, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                rule_rows,
            )

        # Batch import category keywords
        kw_rows = [
            (cat, kw, "imported", now)
            for cat, keywords in data.get("category_keywords", {}).items()
            for kw in keywords
        ]
        if kw_rows:
            conn.executemany(
                "INSERT OR IGNORE INTO attack_categories "
                "(category, keyword, source_report_id, created_at) "
                "VALUES (?, ?, ?, ?)",
                kw_rows,
            )

        conn.commit()
        conn.close()
        logger.info(f"Imported {len(rule_rows)} rules and {len(kw_rows)} keywords from {path}")

    def _load_approved_rules(self):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT pattern FROM rules WHERE status = 'approved'")
        for row in cur.fetchall():
            self._custom_rules.add(row["pattern"].lower())
        conn.close()
        if self._custom_rules:
            logger.info(f"Loaded {len(self._custom_rules)} custom rules from database.")

    def _load_category_keywords(self):
        """Load learned category keywords from the database."""
        conn = self._get_conn()
        cur = conn.cursor()
        try:
            cur.execute("SELECT category, keyword FROM attack_categories")
            for row in cur.fetchall():
                cat = row["category"]
                kw = row["keyword"].lower()
                if cat not in self._category_keywords:
                    self._category_keywords[cat] = set()
                self._category_keywords[cat].add(kw)
        except sqlite3.OperationalError:
            pass  # Table may not exist yet on first run
        conn.close()
        total = sum(len(v) for v in self._category_keywords.values())
        if total:
            logger.info(f"Loaded {total} category keywords across {len(self._category_keywords)} categories.")

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

        # Layer 1: Built-in filter (includes multi-decode + multilingual)
        is_safe, result = self._filter.process(text)

        # Layer 2a: Custom adaptive rules (require 2+ matches to reduce FP)
        if is_safe and self._custom_rules:
            text_lower = text.lower()
            matched_rules = []
            for rule in self._custom_rules:
                if rule in text_lower:
                    # Phrase Immunity: Phrases are always high-integrity
                    if ' ' in rule:
                        matched_rules.append(rule)
                    # Heuristic for single-word custom rules
                    is_sec = rule in _SECURITY_TERMS
                    is_long = len(rule) >= 7
                    is_special = any(ord(c) > 0x024F for c in rule)
                    is_safe = rule.lower() in _SAFE_BASELINE
                    
                    if (is_sec or is_long or is_special) and not is_safe:
                        matched_rules.append(rule)

            if len(matched_rules) >= 2:
                is_safe = False
                result = f"Blocked by adaptive rules: matched {matched_rules[:3]}"

        # Layer 2b: Category keyword matching (v2 self-expanding minefield)
        # Merge predefined categories with learned keywords for full coverage
        if is_safe and self._category_keywords:
            text_lower = text.lower()
            for category, learned_kws in self._category_keywords.items():
                # Combine predefined + learned keywords for this category
                all_kws = learned_kws | set(ATTACK_CATEGORIES.get(category, []))
                # Apply Informative Heuristic to all category matching (predefined + learned)
                matched = []
                for kw in all_kws:
                    if kw in text_lower:
                        # Phrase Immunity: Phrases are always high-integrity
                        if ' ' in kw:
                            matched.append(kw)
                            continue
                        
                        # Apply Informative Heuristic to single-word signals
                        # Skip if in baseline OR if it's an uninformative generic word
                        is_sec = kw in _SECURITY_TERMS
                        is_tech = '-' in kw or '_' in kw or not kw.isalnum()
                        is_long = len(kw) >= 7
                        is_special = any(ord(c) > 0x024F for c in kw)
                        is_safe = kw.lower() in _SAFE_BASELINE or kw.lower() in _STOPWORDS
                        
                        if (is_sec or is_tech or is_long or is_special) and not is_safe:
                            matched.append(kw)

                if len(matched) >= 3:  # Require 3+ keyword matches to reduce FP
                    is_safe = False
                    result = (f"Blocked by category '{category}': "
                              f"matched {matched[:3]}")
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

        # --- V2: Keyword extraction + category classification ---
        keywords = self._extract_keywords(input_text)
        category, matched_cat_keywords = self._classify_attack(keywords)

        # Save keywords to category — with autonomous FP validation
        new_keywords = []
        rejected_keywords = []
        if category:
            # Validate each keyword against historical benign traffic
            validated = []
            for kw in keywords:
                kw_lower = kw.lower()
                if kw_lower in self._category_keywords.get(category, set()):
                    continue  # already known
                fp_result = self._validate_keyword(kw_lower, exclude_scan_id=scan_id)
                if fp_result["safe"]:
                    validated.append(kw_lower)
                else:
                    rejected_keywords.append(kw_lower)
                    logger.info(
                        f"Rejected keyword '{kw_lower}' — would FP on "
                        f"{fp_result['would_block']}/{fp_result['total_tested']} "
                        f"benign scans ({fp_result['fp_rate']*100:.1f}%)")

            if validated:
                with self._lock:
                    conn = self._get_conn()
                    for kw_lower in validated:
                        try:
                            conn.execute(
                                "INSERT OR IGNORE INTO attack_categories "
                                "(category, keyword, source_report_id, created_at) "
                                "VALUES (?, ?, ?, ?)",
                                (category, kw_lower, report_id, time.time()),
                            )
                            new_keywords.append(kw_lower)
                        except sqlite3.IntegrityError:
                            pass
                    conn.commit()
                    conn.close()

                # Update in-memory category keywords
                if category not in self._category_keywords:
                    self._category_keywords[category] = set()
                for kw_lower in validated:
                    self._category_keywords[category].add(kw_lower)

        # Legacy: also store as exact-match rule for backward compatibility
        pattern = input_text.strip().lower()
        sandbox = self._replay(pattern, exclude_scan_id=scan_id)

        rule_id = uuid.uuid4().hex[:12]
        passes_threshold = sandbox["false_positive_rate"] <= self._fp_threshold

        cat_info = (f" Category: '{category}', "
                    f"{len(new_keywords)} new keywords added.") if category else ""

        if passes_threshold and self._auto_deploy:
            self._save_rule(rule_id, pattern, report_id, sandbox, "approved")
            self._custom_rules.add(pattern)
            logger.info(f"Auto-approved rule + category '{category}' "
                        f"(FP: {sandbox['false_positive_rate']})")

            rej_info = (f" Rejected {len(rejected_keywords)} keywords "
                        f"(would cause FPs).") if rejected_keywords else ""

            return {
                "report_id": report_id,
                "status": "auto_approved",
                "rule_created": True,
                "category": category,
                "new_keywords": new_keywords,
                "rejected_keywords": rejected_keywords,
                "sandbox_result": sandbox,
                "message": f"Rule deployed.{cat_info}{rej_info} "
                           f"Tested against {sandbox['total_tested']} scans, "
                           f"FP rate: {sandbox['false_positive_rate']*100:.1f}%.",
            }
        elif passes_threshold and not self._auto_deploy:
            self._save_rule(rule_id, pattern, report_id, sandbox, "pending")
            logger.info(f"Rule '{pattern}' ready for approval (auto_deploy=False)")

            return {
                "report_id": report_id,
                "status": "ready_for_approval",
                "rule_created": False,
                "category": category,
                "new_keywords": new_keywords,
                "sandbox_result": sandbox,
                "message": f"Rule passed validation.{cat_info} "
                           f"FP: {sandbox['false_positive_rate']*100:.1f}%. "
                           f"Call approve_rule('{rule_id}') to deploy it.",
            }
        else:
            self._save_rule(rule_id, pattern, report_id, sandbox, "pending")
            logger.info(f"Rule '{pattern}' pending review "
                        f"(FP: {sandbox['false_positive_rate']})")

            return {
                "report_id": report_id,
                "status": "pending_review",
                "rule_created": False,
                "category": category,
                "new_keywords": new_keywords,
                "sandbox_result": sandbox,
                "message": f"Rule needs review.{cat_info} "
                           f"Would cause {sandbox['would_block']} FPs "
                           f"({sandbox['false_positive_rate']*100:.1f}% rate).",
            }

    # ------------------------------------------------------------------
    # REPORT FALSE POSITIVE (self-pruning)
    # ------------------------------------------------------------------

    def report_false_positive(self, scan_id: str, reason: str = "") -> dict:
        """
        Report a false positive (a clean input that was wrongly blocked).

        The system will:
        1. Look up the original blocked scan
        2. Identify which LEARNED category keywords caused the block
        3. Remove those keywords from the category (DB + memory)
        4. Predefined ATTACK_CATEGORIES keywords are NEVER removed

        Args:
            scan_id: The scan_id from a previous scan() call that was blocked
            reason: Why this was a false positive (optional, for logging)

        Returns:
            dict with: status, pruned_keywords, category, message
        """
        # Block pruning if disabled or in manual mode
        if not self._allow_pruning or not self._auto_deploy:
            # Still log the false positive report for admin review
            with self._lock:
                conn = self._get_conn()
                conn.execute(
                    "INSERT INTO reports (report_id, scan_id, reported_input, reason, timestamp, status) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (uuid.uuid4().hex[:12], scan_id, "",
                     f"FALSE_POSITIVE_PENDING: {reason}" if reason else "FALSE_POSITIVE_PENDING",
                     time.time(), "pending_prune"),
                )
                conn.commit()
                conn.close()
            return {
                "status": "pending_review",
                "pruned_keywords": [],
                "category": None,
                "message": "Manual mode is active. False positive logged for admin review. "
                           "Use approve_prune(scan_id) to execute the pruning.",
            }

        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT input_text, allowed, reason FROM scan_log WHERE scan_id = ?",
            (scan_id,),
        )
        row = cur.fetchone()
        conn.close()

        if not row:
            return {"status": "error", "pruned_keywords": [],
                    "message": "Scan ID not found."}

        if row["allowed"]:
            return {"status": "error", "pruned_keywords": [],
                    "message": "This scan was allowed. Only blocked scans can be reported as false positives."}

        input_text = row["input_text"]
        block_reason = row["reason"]

        # Find which category keywords caused the block
        text_lower = input_text.lower()
        pruned = []
        pruned_category = None

        for category, learned_kws in list(self._category_keywords.items()):
            # Get predefined keywords for this category (these are NEVER removed)
            predefined = set(ATTACK_CATEGORIES.get(category, []))

            # Find all keywords that matched in this input using Informative Heuristic
            all_kws = learned_kws | predefined
            matched = []
            for kw in all_kws:
                if kw in text_lower:
                    if ' ' in kw:
                        matched.append(kw)
                        continue
                    is_sec = kw in _SECURITY_TERMS
                    is_tech = '-' in kw or '_' in kw or not kw.isalnum()
                    is_long = len(kw) >= 7
                    is_special = any(ord(c) > 0x024F for c in kw)
                    is_safe = kw.lower() in _SAFE_BASELINE or kw.lower() in _STOPWORDS
                    
                    if (is_sec or is_tech or is_long or is_special) and not is_safe:
                        matched.append(kw)

            if len(matched) >= 3:
                # This is the category that caused the block
                pruned_category = category

                # Only prune LEARNED keywords that matched, NOT predefined ones
                to_prune = [kw for kw in matched if kw in learned_kws and kw not in predefined]

                if to_prune:
                    with self._lock:
                        conn = self._get_conn()
                        for kw in to_prune:
                            conn.execute(
                                "DELETE FROM attack_categories WHERE category = ? AND keyword = ?",
                                (category, kw),
                            )
                            learned_kws.discard(kw)
                            pruned.append(kw)
                        conn.commit()
                        conn.close()

                    # Clean up empty categories
                    if not learned_kws:
                        del self._category_keywords[category]

                    logger.info(
                        f"Pruned {len(to_prune)} keywords from '{category}': {to_prune}"
                    )
                break

        # Log the false positive report
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT INTO reports (report_id, scan_id, reported_input, reason, timestamp, status) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (uuid.uuid4().hex[:12], scan_id, input_text,
                 f"FALSE_POSITIVE: {reason}" if reason else "FALSE_POSITIVE",
                 time.time(), "false_positive"),
            )
            conn.commit()
            conn.close()

        if pruned:
            return {
                "status": "pruned",
                "pruned_keywords": pruned,
                "category": pruned_category,
                "message": f"Removed {len(pruned)} learned keywords from '{pruned_category}': "
                           f"{pruned}. Predefined keywords were preserved.",
            }
        else:
            return {
                "status": "no_action",
                "pruned_keywords": [],
                "category": pruned_category,
                "message": "Block was caused by predefined keywords (not learned). "
                           "No keywords were removed — predefined rules are immutable.",
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

    def _validate_keyword(self, keyword: str, exclude_scan_id: str = "") -> dict:
        """
        Autonomously validate a keyword against historical benign traffic.

        Tests whether adding this keyword would cause false positives
        on inputs that were previously allowed. No human needed —
        the system's own scan history is the benign baseline.

        Returns:
            {"safe": bool, "total_tested": int, "would_block": int, "fp_rate": float}
        """
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT input_text FROM scan_log WHERE allowed = 1 "
            "AND input_text != '' AND scan_id != ?",
            (exclude_scan_id,),
        )
        rows = cur.fetchall()
        conn.close()

        total = len(rows)
        if total == 0:
            # No history yet — allow keyword but with lower confidence
            return {"safe": True, "total_tested": 0, "would_block": 0, "fp_rate": 0.0}

        # Count how many allowed inputs contain this keyword
        kw_lower = keyword.lower()
        would_block = sum(
            1 for r in rows if kw_lower in r["input_text"].lower()
        )
        fp_rate = would_block / total

        # Reject if >5% of benign traffic contains this keyword
        safe = fp_rate <= self._fp_threshold

        return {
            "safe": safe,
            "total_tested": total,
            "would_block": would_block,
            "fp_rate": round(fp_rate, 4),
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
    # KEYWORD EXTRACTION + CLASSIFICATION
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_keywords(text: str) -> List[str]:
        """
        Robustly extracts the most informative security-relevant keywords.
        Focuses on instructions (verbs) and targets (nouns).
        """
        words = text.lower().split()
        candidates = []
        seen = set()
        
        for word in words:
            # Clean punctuation (excluding dashes/underscores for tech terms)
            clean = word.strip('.,!?;:\'"()[]{}/')
            
            # Apply Informative Heuristic (using module-level _SECURITY_TERMS and _SAFE_BASELINE)
            is_sec = clean in _SECURITY_TERMS
            is_tech = '-' in clean or '_' in clean or not clean.isalnum()
            is_long = len(clean) >= 7
            is_special = any(ord(c) > 0x024F for c in clean)
            is_safe = clean in _STOPWORDS or clean in _SAFE_BASELINE or clean in seen
            
            if (is_sec or is_tech or is_long or is_special) and not is_safe:
                candidates.append(clean)
                seen.add(clean)
        
        if not candidates:
            return []
            
        # Rank: Security terms > Length
        candidates.sort(key=lambda x: (x in _SECURITY_TERMS, len(x)), reverse=True)
        return candidates[:5]

    @staticmethod
    def _classify_attack(keywords: List[str]) -> tuple:
        """
        Classify extracted keywords into an attack category.

        Matches keywords against predefined ATTACK_CATEGORIES.
        Returns (category_name, matched_keywords) or (None, []) if
        no category matches.

        If no existing category matches, creates a dynamic category
        name from the first two keywords.
        """
        best_cat = None
        best_matches: List[str] = []
        best_score = 0

        for cat, cat_keywords in ATTACK_CATEGORIES.items():
            matches = [kw for kw in keywords if kw in cat_keywords]
            if len(matches) > best_score:
                best_score = len(matches)
                best_cat = cat
                best_matches = matches

        if best_score >= 1:
            return best_cat, best_matches

        # No known category matched — create a new dynamic one
        if len(keywords) >= 2:
            dynamic_cat = f"learned_{keywords[0]}_{keywords[1]}"
            return dynamic_cat, []
        elif keywords:
            dynamic_cat = f"learned_{keywords[0]}"
            return dynamic_cat, []

        return None, []

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

    def get_reports(self) -> List[dict]:
        """Get all submitted reports."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM reports ORDER BY timestamp DESC")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    @property
    def pending_rules(self) -> List[dict]:
        """Get all rules waiting for approval."""
        return self.get_rules(status="pending")

    @property
    def active_rules(self) -> Set[str]:
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
