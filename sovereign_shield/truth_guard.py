"""
TruthGuard — Factual Hallucination Detection Engine
=====================================================
Detects when an AI agent makes factual claims without having verified them
through tools, and builds a self-improving verified fact cache over time.

Architecture:
    1. Session tool tracking — knows which verification tools were called
    2. Confidence marker detection — pre-compiled regex catches unverified claims
    3. Verification enforcement — blocks factual claims without tool verification
    4. Verified fact cache — stores verified facts with TTL for reuse

Same self-improving pattern as AdaptiveShield:
    - Starts with zero cached facts
    - Every verified answer adds to the cache
    - Cache grows over time, reducing unnecessary tool calls
    - Expired facts require re-verification

Zero external dependencies. Pure Python stdlib.

Copyright (c) 2026 Mattijs Moens. All rights reserved.
Patent Pending — Truth Adapter Validation System.
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
# These detect when an AI claims factual knowledge in its output.
# ===================================================================

# Temporal certainty — claims about current state
_TEMPORAL_MARKERS = re.compile(
    r'\b(currently|right now|as of (today|now|\d{4})|at this moment|'
    r'at the time of writing|today\'s|latest|up[- ]to[- ]date|real[- ]time)\b',
    re.IGNORECASE
)

# Statistical/numerical claims in factual context
# Matches: "$84,322", "67 million", "99.7%", "3.14159", etc.
_NUMERICAL_CLAIM = re.compile(
    r'(\$[\d,]+\.?\d*|'                          # Dollar amounts
    r'\b\d{1,3}(,\d{3})+(\.\d+)?\b|'             # Large numbers with commas
    r'\b\d+(\.\d+)?%|'                            # Percentages
    r'\b\d+(\.\d+)?\s*(million|billion|trillion|thousand)\b)',  # Named magnitudes
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

# Hedging language — indicates the AI knows it's uncertain (GOOD behavior)
# If these are present, we DON'T flag the answer
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

# Default verification tools — these count as "doing the work"
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

    Self-improving: verified facts are cached in SQLite with TTL,
    building a growing knowledge base over time.

    Usage:
        guard = TruthGuard(db_path="./data/truth.db")

        # Start a session
        guard.start_session("session-001")

        # Record tool usage (if any)
        guard.record_tool_use("session-001", "SEARCH", "bitcoin price")

        # Check an answer before it leaves
        ok, reason = guard.check_answer("session-001", "Bitcoin is currently $84,322")
        # → (True, "Verified: SEARCH tool was used this session")

        # Without tool use:
        guard.start_session("session-002")
        ok, reason = guard.check_answer("session-002", "Bitcoin is currently $84,322")
        # → (False, "Unverified factual claim: temporal + numerical markers detected, no verification tool used")
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
        Initialize the TruthGuard engine.

        Args:
            db_path: Path to SQLite database file.
            verification_tools: Set of tool names that count as verification.
                              Defaults to SEARCH, BROWSE, READ_FILE, LOOKUP, etc.
            fact_ttl_days: Default TTL for time-sensitive cached facts (days).
            static_fact_ttl_days: TTL for static/general knowledge facts (days).
            retention_days: How long to keep check history (days).
            enabled: Whether TruthGuard is active. Can be toggled at runtime
                    via `guard.enabled = True/False`. When disabled,
                    check_answer() always returns allowed.
        """
        self.enabled = enabled
        self._db_path = db_path
        self._verification_tools = verification_tools or DEFAULT_VERIFICATION_TOOLS
        self._fact_ttl_days = fact_ttl_days
        self._static_fact_ttl_days = static_fact_ttl_days
        self._retention_days = retention_days
        self._lock = threading.Lock()

        # In-memory session tracking for fast lookup
        self._sessions: Dict[str, List[dict]] = {}

        # Initialize database
        self._init_db()

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

    def _cleanup(self, days: int):
        cutoff = time.time() - (days * 86400)
        conn = self._get_conn()
        conn.execute("DELETE FROM truth_checks WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM blocked_claims WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM session_tools WHERE timestamp < ?", (cutoff,))
        # Clean expired facts
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
        """
        Start tracking a new session.

        Call this at the beginning of each AI interaction turn/conversation.

        Args:
            session_id: Unique identifier for this session/turn.
        """
        self._sessions[session_id] = []
        logger.debug(f"[TruthGuard] Session started: {session_id}")

    def end_session(self, session_id: str):
        """
        End and clean up a session from memory.

        The tool usage records remain in the database for audit purposes.

        Args:
            session_id: The session to end.
        """
        self._sessions.pop(session_id, None)
        logger.debug(f"[TruthGuard] Session ended: {session_id}")

    def record_tool_use(self, session_id: str, tool_name: str,
                        query: str = "", result_summary: str = ""):
        """
        Record that a verification tool was used in this session.

        No-op if TruthGuard is disabled.

        Args:
            session_id: The active session ID.
            tool_name: Name of the tool (e.g., "SEARCH", "BROWSE").
            query: What was queried/searched for.
            result_summary: Brief summary of the result (for fact caching).
        """
        if not self.enabled:
            return

        tool_upper = tool_name.upper()
        record = {
            "tool_name": tool_upper,
            "query": query,
            "result_summary": result_summary,
            "timestamp": time.time(),
        }

        # In-memory tracking
        if session_id not in self._sessions:
            self._sessions[session_id] = []
        self._sessions[session_id].append(record)

        # Persist to database
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT INTO session_tools (session_id, tool_name, query, "
                "result_summary, timestamp) VALUES (?, ?, ?, ?, ?)",
                (session_id, tool_upper, query, result_summary, time.time()),
            )
            conn.commit()
            conn.close()

        logger.debug(f"[TruthGuard] Tool recorded: {tool_upper} in {session_id}")

    def _session_has_verification(self, session_id: str) -> bool:
        """Check if any verification tool was used in this session."""
        # Check in-memory first (fast path)
        if session_id in self._sessions:
            return any(
                t["tool_name"] in self._verification_tools
                for t in self._sessions[session_id]
            )

        # Fall back to database
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
        """
        Scan text for confidence markers that indicate factual claims.

        Returns a list of marker categories found (e.g., ["temporal", "numerical"]).
        An empty list means no factual claims were detected.

        Args:
            text: The answer text to scan.

        Returns:
            List of marker category strings found.
        """
        markers = []

        if _TEMPORAL_MARKERS.search(text):
            markers.append("temporal")

        if _NUMERICAL_CLAIM.search(text):
            # Only flag numerical claims if they appear in a factual context
            # (not just "I found 3 results" or "step 2 of 5")
            # Check if it's near factual language
            sentences = re.split(r'[.!?]', text)
            for sentence in sentences:
                if _NUMERICAL_CLAIM.search(sentence):
                    # Skip trivial numbers in non-factual context
                    s_lower = sentence.lower().strip()
                    trivial = (
                        s_lower.startswith("step ") or
                        s_lower.startswith("option ") or
                        s_lower.startswith("item ") or
                        "results" in s_lower and len(sentence) < 40
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
        """
        Check if the text contains hedging language indicating uncertainty.

        Hedging is GOOD behavior — the AI is expressing appropriate uncertainty.
        When hedging is present, we relax the verification requirement.

        Args:
            text: The answer text to check.

        Returns:
            True if hedging language is found.
        """
        return bool(_HEDGE_MARKERS.search(text))

    # ------------------------------------------------------------------
    # FACT CACHE
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_claim(text: str) -> str:
        """Generate a normalized hash for a factual claim."""
        # Normalize: lowercase, strip whitespace, remove punctuation
        normalized = re.sub(r'[^\w\s]', '', text.lower()).strip()
        normalized = re.sub(r'\s+', ' ', normalized)
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def store_verified_fact(self, claim_text: str, source: str,
                           tool_used: str, ttl_days: Optional[int] = None):
        """
        Store a verified fact in the cache.

        Args:
            claim_text: The factual claim that was verified.
            source: Where the fact was verified from (URL, file, etc.).
            tool_used: Which tool was used to verify it.
            ttl_days: How long this fact should be cached. Defaults to fact_ttl_days.
        """
        if ttl_days is None:
            # Use longer TTL for non-temporal facts
            if _TEMPORAL_MARKERS.search(claim_text):
                ttl_days = self._fact_ttl_days
            else:
                ttl_days = self._static_fact_ttl_days

        fact_id = uuid.uuid4().hex[:12]
        claim_hash = self._hash_claim(claim_text)

        with self._lock:
            conn = self._get_conn()
            # Upsert: replace if same claim hash exists
            conn.execute(
                "INSERT OR REPLACE INTO verified_facts "
                "(fact_id, claim_hash, claim_text, source, tool_used, verified_at, ttl_days) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (fact_id, claim_hash, claim_text, source, tool_used,
                 time.time(), ttl_days),
            )
            conn.commit()
            conn.close()

        logger.info(f"[TruthGuard] Fact cached: {claim_text[:50]}... (TTL: {ttl_days}d)")

    def lookup_fact(self, claim_text: str) -> Optional[dict]:
        """
        Check if a fact has been previously verified and is still valid.

        Args:
            claim_text: The factual claim to look up.

        Returns:
            dict with fact details if found and not expired, None otherwise.
        """
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
    # ANSWER VERIFICATION (Core Check)
    # ------------------------------------------------------------------

    def check_answer(self, session_id: str, answer_text: str) -> tuple:
        """
        Check if an answer contains unverified factual claims.

        This is the main entry point. Call this before allowing an AI answer
        to be delivered to the user.

        Logic:
            1. Detect confidence markers in the answer
            2. If no markers → allow (opinion/general chat)
            3. If markers found but AI is hedging → allow (appropriate uncertainty)
            4. If markers found → check if verification tool was used
            5. If tool was used → allow (verified)
            6. If fact exists in cache → allow (previously verified)
            7. Otherwise → block (unverified factual claim)

        Args:
            session_id: The active session ID.
            answer_text: The AI's proposed answer text.

        Returns:
            tuple: (allowed: bool, reason: str)
        """
        # Short-circuit if disabled
        if not self.enabled:
            return True, "TruthGuard is disabled."

        check_id = uuid.uuid4().hex[:12]

        # Step 1: Detect confidence markers
        markers = self.detect_confidence_markers(answer_text)

        # Step 2: No markers → allow (not a factual claim)
        if not markers:
            self._log_check(check_id, session_id, answer_text,
                           had_markers=False, had_verification=False,
                           allowed=True, reason="No factual claims detected.")
            return True, "No factual claims detected."

        # Step 3: Has hedging → allow (appropriate uncertainty)
        if self.has_hedging(answer_text):
            self._log_check(check_id, session_id, answer_text,
                           had_markers=True, had_verification=False,
                           allowed=True,
                           reason="Factual markers found but hedged with uncertainty.")
            return True, "Factual markers found but appropriately hedged."

        # Step 4: Check if verification tool was used this session
        has_verification = self._session_has_verification(session_id)

        if has_verification:
            self._log_check(check_id, session_id, answer_text,
                           had_markers=True, had_verification=True,
                           allowed=True,
                           reason=f"Verified: tool used this session. Markers: {markers}")
            return True, f"Verified: verification tool used this session."

        # Step 5: Check fact cache
        cached = self.lookup_fact(answer_text)
        if cached:
            self._log_check(check_id, session_id, answer_text,
                           had_markers=True, had_verification=True,
                           allowed=True,
                           reason=f"Cached fact (verified {cached['tool_used']} "
                                  f"on {time.ctime(cached['verified_at'])})")
            return True, (f"Previously verified fact "
                         f"(cached from {cached['tool_used']}).")

        # Step 6: Block — unverified factual claim
        marker_str = ", ".join(markers)
        reason = (f"Unverified factual claim: {marker_str} markers detected, "
                  f"no verification tool used this session.")

        self._log_check(check_id, session_id, answer_text,
                       had_markers=True, had_verification=False,
                       allowed=False, reason=reason)

        # Log the blocked claim for training data
        self._log_blocked_claim(session_id, answer_text, marker_str, reason)

        logger.warning(f"[TruthGuard] BLOCKED: {reason}")
        return False, reason

    # ------------------------------------------------------------------
    # LOGGING
    # ------------------------------------------------------------------

    def _log_check(self, check_id: str, session_id: str, answer_text: str,
                   had_markers: bool, had_verification: bool,
                   allowed: bool, reason: str):
        """Log a truth check to the database."""
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

    def _log_blocked_claim(self, session_id: str, claim_text: str,
                           markers: str, reason: str):
        """Log a blocked claim for future training data."""
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

    # ------------------------------------------------------------------
    # STATISTICS & ADMIN
    # ------------------------------------------------------------------

    @property
    def stats(self) -> dict:
        """Quick stats about the TruthGuard system."""
        conn = self._get_conn()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) as c FROM truth_checks")
        total_checks = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) as c FROM truth_checks WHERE allowed = 1")
        total_allowed = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) as c FROM truth_checks WHERE allowed = 0")
        total_blocked = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) as c FROM verified_facts")
        cached_facts = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) as c FROM blocked_claims")
        blocked_claims = cur.fetchone()["c"]

        conn.close()
        return {
            "total_checks": total_checks,
            "total_allowed": total_allowed,
            "total_blocked": total_blocked,
            "cached_facts": cached_facts,
            "blocked_claims_logged": blocked_claims,
            "active_sessions": len(self._sessions),
        }

    def get_blocked_claims(self, limit: int = 50) -> List[dict]:
        """Get recent blocked claims (useful for training data export)."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM blocked_claims ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def get_cached_facts(self) -> List[dict]:
        """Get all currently cached (non-expired) facts."""
        now = time.time()
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM verified_facts WHERE (verified_at + ttl_days * 86400) > ? "
            "ORDER BY verified_at DESC",
            (now,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
