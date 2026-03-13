"""
LoRA Exporter + TruthGuard Toggle Tests
========================================
Tests for the LoRA training data exporter and TruthGuard enable/disable toggle.

Copyright (c) 2026 Mattijs Moens. All rights reserved.
"""

import unittest
import os
import sys
import shutil
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_test_lora_data")
TEST_DB = os.path.join(TEST_DATA_DIR, "test_truth.db")
TEST_JSONL = os.path.join(TEST_DATA_DIR, "test_output.jsonl")


class TestLoRAImport(unittest.TestCase):
    """Verify LoRAExporter is importable."""

    def test_import(self):
        from sovereign_shield import LoRAExporter
        self.assertIsNotNone(LoRAExporter)


class TestLoRAExporter(unittest.TestCase):
    """Test the LoRA training data export pipeline."""

    @classmethod
    def setUpClass(cls):
        os.makedirs(TEST_DATA_DIR, exist_ok=True)
        from sovereign_shield.truth_guard import TruthGuard
        from sovereign_shield.lora_export import LoRAExporter

        # Create a TruthGuard instance and seed it with test data
        cls.guard = TruthGuard(db_path=TEST_DB)

        # Seed blocked claims (negative examples)
        cls.guard.start_session("lora-test-1")
        cls.guard.check_answer(
            "lora-test-1", "Bitcoin is currently trading at $84,322."
        )  # Will be blocked — no tool used

        # Seed verified answers (positive examples)
        cls.guard.start_session("lora-test-2")
        cls.guard.record_tool_use("lora-test-2", "SEARCH", "bitcoin price")
        cls.guard.check_answer(
            "lora-test-2", "Bitcoin is currently trading at $84,322."
        )  # Will pass — tool used

        # Seed hedged answers (positive examples)
        cls.guard.start_session("lora-test-3")
        cls.guard.check_answer(
            "lora-test-3",
            "I'm not sure, but I think Bitcoin might be around $84,000."
        )  # Will pass — hedged

        # Seed verified facts
        cls.guard.store_verified_fact(
            "The population of France is 67 million",
            "https://example.com/france",
            "SEARCH"
        )

        cls.exporter = LoRAExporter(db_path=TEST_DB)

    def test_stats_returns_dict(self):
        stats = self.exporter.stats
        self.assertIsInstance(stats, dict)
        self.assertIn("total_training_pairs", stats)
        self.assertIn("blocked_claims", stats)
        self.assertIn("verified_checks", stats)
        self.assertIn("verified_facts", stats)

    def test_stats_has_data(self):
        stats = self.exporter.stats
        self.assertGreater(stats["total_training_pairs"], 0)

    def test_compile_returns_list(self):
        pairs = self.exporter.compile_dataset()
        self.assertIsInstance(pairs, list)
        self.assertGreater(len(pairs), 0)

    def test_training_pairs_have_messages_format(self):
        pairs = self.exporter.compile_dataset()
        for pair in pairs:
            self.assertIn("messages", pair)
            self.assertIsInstance(pair["messages"], list)
            # Must have system, user, assistant
            roles = [m["role"] for m in pair["messages"]]
            self.assertIn("system", roles)
            self.assertIn("user", roles)
            self.assertIn("assistant", roles)

    def test_export_jsonl_creates_file(self):
        result = self.exporter.export_jsonl(TEST_JSONL)
        self.assertTrue(os.path.exists(TEST_JSONL))
        self.assertGreater(result["exported"], 0)

    def test_jsonl_is_valid(self):
        self.exporter.export_jsonl(TEST_JSONL)
        with open(TEST_JSONL, "r", encoding="utf-8") as f:
            for line in f:
                data = json.loads(line.strip())
                self.assertIn("messages", data)

    def test_export_without_meta(self):
        self.exporter.export_jsonl(TEST_JSONL, include_meta=False)
        with open(TEST_JSONL, "r", encoding="utf-8") as f:
            for line in f:
                data = json.loads(line.strip())
                self.assertNotIn("_meta", data)

    def test_export_with_meta(self):
        self.exporter.export_jsonl(TEST_JSONL, include_meta=True)
        with open(TEST_JSONL, "r", encoding="utf-8") as f:
            for line in f:
                data = json.loads(line.strip())
                self.assertIn("_meta", data)

    def test_hedge_claim(self):
        hedged = self.exporter._hedge_claim("Bitcoin is currently $84,322")
        self.assertNotEqual(hedged, "Bitcoin is currently $84,322")
        # Should have replaced "currently" with hedging language
        self.assertNotIn("currently", hedged.lower())


class TestTruthGuardToggle(unittest.TestCase):
    """Test TruthGuard's enable/disable toggle."""

    @classmethod
    def setUpClass(cls):
        os.makedirs(TEST_DATA_DIR, exist_ok=True)
        from sovereign_shield.truth_guard import TruthGuard
        cls.TG = TruthGuard

    def test_disabled_check_always_allows(self):
        guard = self.TG(db_path=TEST_DB, enabled=False)
        guard.start_session("disabled-test")
        ok, reason = guard.check_answer(
            "disabled-test", "Bitcoin is currently $84,322."
        )
        self.assertTrue(ok)
        self.assertIn("disabled", reason.lower())

    def test_runtime_toggle_off(self):
        guard = self.TG(db_path=TEST_DB, enabled=True)
        guard.start_session("toggle-test")

        # Should block when enabled
        ok, _ = guard.check_answer(
            "toggle-test", "Bitcoin is currently $84,322."
        )
        self.assertFalse(ok)

        # Disable at runtime
        guard.enabled = False
        ok, reason = guard.check_answer(
            "toggle-test", "Bitcoin is currently $84,322."
        )
        self.assertTrue(ok)

    def test_runtime_toggle_on(self):
        guard = self.TG(db_path=TEST_DB, enabled=False)
        guard.start_session("toggle-on-test")

        # Should allow when disabled
        ok, _ = guard.check_answer(
            "toggle-on-test", "Bitcoin is currently $84,322."
        )
        self.assertTrue(ok)

        # Enable at runtime
        guard.enabled = True
        ok, _ = guard.check_answer(
            "toggle-on-test", "Bitcoin is currently $84,322."
        )
        self.assertFalse(ok)


class TestLoraTeardown(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        if os.path.exists(TEST_DATA_DIR):
            shutil.rmtree(TEST_DATA_DIR)


if __name__ == "__main__":
    unittest.main(verbosity=2)
