"""
TruthGuard Test Suite
======================
Tests for the factual hallucination detection engine.

Covers:
    - Clean answers (no factual claims)
    - Verified factual answers (tool was used)
    - Unverified factual answers (blocked)
    - Hedged answers (allowed despite markers)
    - Fact caching with TTL
    - Session isolation
    - Stats tracking
    - Confidence marker detection

Copyright (c) 2026 Mattijs Moens. All rights reserved.
"""

import unittest
import os
import sys
import shutil

# Ensure we import from this directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_test_truth_data")
TEST_DB = os.path.join(TEST_DATA_DIR, "test_truth.db")


class TestTruthGuardImport(unittest.TestCase):
    """Verify TruthGuard is importable from the package."""

    def test_import(self):
        from sovereign_shield import TruthGuard
        self.assertIsNotNone(TruthGuard)


class TestConfidenceMarkerDetection(unittest.TestCase):
    """Test the regex-based confidence marker detection."""

    @classmethod
    def setUpClass(cls):
        from sovereign_shield.truth_guard import TruthGuard
        cls.TG = TruthGuard

    def test_no_markers_in_generic_text(self):
        markers = self.TG.detect_confidence_markers("Hello, how can I help you today?")
        self.assertEqual(markers, [])

    def test_no_markers_in_opinion(self):
        markers = self.TG.detect_confidence_markers("I think Python is a great language.")
        self.assertEqual(markers, [])

    def test_temporal_marker_detected(self):
        markers = self.TG.detect_confidence_markers(
            "Bitcoin is currently trading at a high price."
        )
        self.assertIn("temporal", markers)

    def test_numerical_marker_detected(self):
        markers = self.TG.detect_confidence_markers(
            "The population of France is 67 million people."
        )
        self.assertIn("numerical", markers)

    def test_citation_marker_detected(self):
        markers = self.TG.detect_confidence_markers(
            "According to recent studies, coffee improves focus."
        )
        self.assertIn("citation", markers)

    def test_certainty_marker_detected(self):
        markers = self.TG.detect_confidence_markers(
            "The fact is that this approach is the best one."
        )
        self.assertIn("certainty", markers)

    def test_multiple_markers_detected(self):
        markers = self.TG.detect_confidence_markers(
            "According to research, the price is currently $84,322."
        )
        self.assertTrue(len(markers) >= 2)

    def test_dollar_amount_detected(self):
        markers = self.TG.detect_confidence_markers(
            "The total revenue was $1,500,000 last quarter."
        )
        self.assertIn("numerical", markers)

    def test_percentage_detected(self):
        markers = self.TG.detect_confidence_markers(
            "The success rate is 99.7% across all trials."
        )
        self.assertIn("numerical", markers)


class TestHedgeDetection(unittest.TestCase):
    """Test hedging language detection."""

    @classmethod
    def setUpClass(cls):
        from sovereign_shield.truth_guard import TruthGuard
        cls.TG = TruthGuard

    def test_hedging_detected(self):
        self.assertTrue(self.TG.has_hedging("I'm not sure, but I think it might be around 50."))

    def test_maybe_detected(self):
        self.assertTrue(self.TG.has_hedging("Maybe the answer is 42."))

    def test_no_hedging_in_confident_text(self):
        self.assertFalse(self.TG.has_hedging("The answer is exactly 42."))

    def test_need_to_check_detected(self):
        self.assertTrue(self.TG.has_hedging("I'd need to check that for you."))


class TestCheckAnswer(unittest.TestCase):
    """Test the core check_answer logic."""

    @classmethod
    def setUpClass(cls):
        os.makedirs(TEST_DATA_DIR, exist_ok=True)
        from sovereign_shield.truth_guard import TruthGuard
        cls.guard = TruthGuard(db_path=TEST_DB)

    def setUp(self):
        """Start a fresh session for each test."""
        self._session = f"test-{id(self)}"
        self.guard.start_session(self._session)

    def test_clean_answer_passes(self):
        """Generic answers with no factual claims should always pass."""
        ok, reason = self.guard.check_answer(
            self._session, "Hello! How can I help you today?"
        )
        self.assertTrue(ok)
        self.assertIn("No factual claims", reason)

    def test_verified_answer_passes(self):
        """Factual claims with tool verification should pass."""
        self.guard.record_tool_use(self._session, "SEARCH", "bitcoin price")
        ok, reason = self.guard.check_answer(
            self._session,
            "Bitcoin is currently trading at $84,322."
        )
        self.assertTrue(ok)
        self.assertIn("verification tool used", reason)

    def test_unverified_answer_blocked(self):
        """Factual claims without tool verification should be blocked."""
        ok, reason = self.guard.check_answer(
            self._session,
            "Bitcoin is currently trading at $84,322."
        )
        self.assertFalse(ok)
        self.assertIn("Unverified", reason)

    def test_hedged_answer_passes(self):
        """Factual claims with hedging language should pass."""
        ok, reason = self.guard.check_answer(
            self._session,
            "I'm not sure, but I think Bitcoin might be around $84,000."
        )
        self.assertTrue(ok)
        self.assertIn("hedged", reason)

    def test_citation_without_source_blocked(self):
        """Citation claims without verification should be blocked."""
        ok, reason = self.guard.check_answer(
            self._session,
            "According to recent studies, this treatment is 95% effective."
        )
        self.assertFalse(ok)
        self.assertIn("Unverified", reason)

    def test_browse_counts_as_verification(self):
        """BROWSE tool should count as fact verification."""
        self.guard.record_tool_use(self._session, "BROWSE", "https://example.com")
        ok, _ = self.guard.check_answer(
            self._session,
            "According to the website, the price is $500."
        )
        self.assertTrue(ok)

    def test_read_file_counts_as_verification(self):
        """READ_FILE tool should count as fact verification."""
        self.guard.record_tool_use(self._session, "READ_FILE", "data.csv")
        ok, _ = self.guard.check_answer(
            self._session,
            "The exact figure is 1,234,567 units."
        )
        self.assertTrue(ok)


class TestSessionIsolation(unittest.TestCase):
    """Verify that sessions don't leak into each other."""

    @classmethod
    def setUpClass(cls):
        os.makedirs(TEST_DATA_DIR, exist_ok=True)
        from sovereign_shield.truth_guard import TruthGuard
        cls.guard = TruthGuard(db_path=TEST_DB)

    def test_sessions_isolated(self):
        """Tool use in session A should NOT verify claims in session B."""
        self.guard.start_session("session-A")
        self.guard.start_session("session-B")

        # Record tool use only in session A
        self.guard.record_tool_use("session-A", "SEARCH", "bitcoin price")

        # Session A should pass
        ok_a, _ = self.guard.check_answer(
            "session-A", "Bitcoin is currently $84,322."
        )
        self.assertTrue(ok_a)

        # Session B should be blocked (no tool use)
        ok_b, _ = self.guard.check_answer(
            "session-B", "Bitcoin is currently $84,322."
        )
        self.assertFalse(ok_b)


class TestFactCache(unittest.TestCase):
    """Test the verified fact caching system."""

    @classmethod
    def setUpClass(cls):
        os.makedirs(TEST_DATA_DIR, exist_ok=True)
        from sovereign_shield.truth_guard import TruthGuard
        cls.guard = TruthGuard(db_path=TEST_DB, fact_ttl_days=7)

    def test_cached_fact_passes_without_tool(self):
        """Previously verified facts should pass without re-verification."""
        # Store a verified fact (must contain confidence markers to trigger check)
        claim = "The population of France is currently 67 million people."
        self.guard.store_verified_fact(claim, "https://example.com", "SEARCH")

        # New session, no tool use
        session = "cache-test-1"
        self.guard.start_session(session)

        # Should pass because the claim is cached
        ok, reason = self.guard.check_answer(session, claim)
        self.assertTrue(ok)
        self.assertIn("Previously verified", reason)

    def test_lookup_returns_none_for_unknown(self):
        """Uncached facts should return None."""
        result = self.guard.lookup_fact("Something completely random and unique 12345")
        self.assertIsNone(result)

    def test_cached_facts_retrievable(self):
        """get_cached_facts should return stored facts."""
        facts = self.guard.get_cached_facts()
        self.assertIsInstance(facts, list)


class TestStats(unittest.TestCase):
    """Test statistics tracking."""

    @classmethod
    def setUpClass(cls):
        os.makedirs(TEST_DATA_DIR, exist_ok=True)
        from sovereign_shield.truth_guard import TruthGuard
        cls.guard = TruthGuard(db_path=TEST_DB)

    def test_stats_returns_dict(self):
        stats = self.guard.stats
        self.assertIsInstance(stats, dict)
        self.assertIn("total_checks", stats)
        self.assertIn("total_allowed", stats)
        self.assertIn("total_blocked", stats)
        self.assertIn("cached_facts", stats)

    def test_blocked_claims_retrievable(self):
        claims = self.guard.get_blocked_claims()
        self.assertIsInstance(claims, list)


class TestTeardown(unittest.TestCase):
    """Clean up test data."""

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(TEST_DATA_DIR):
            shutil.rmtree(TEST_DATA_DIR)


if __name__ == "__main__":
    unittest.main(verbosity=2)
