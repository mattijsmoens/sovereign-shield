"""
LoRA Training Data Exporter — Truth Adapter Dataset Compiler
=============================================================
Exports TruthGuard's collected data (blocked claims, verified facts,
truth checks) into JSONL format suitable for LoRA fine-tuning.

The goal: teach a model the BEHAVIOR of verifying before claiming.

Training pairs follow a simple pattern:
    - GOOD behavior: "I searched for X, and found Y" → reward
    - BAD behavior: "The answer is X" (no tool used) → penalty

Output format is compatible with:
    - OpenAI fine-tuning API (messages format)
    - Gemini Tuning API
    - HuggingFace/Unsloth local LoRA training

Copyright (c) 2026 Mattijs Moens. All rights reserved.
Patent Pending — Truth Adapter Validation System.
"""

import json
import logging
import os
import sqlite3
import time
from typing import List, Optional

logger = logging.getLogger("sovereign_shield.lora_export")


class LoRAExporter:
    """
    Exports TruthGuard data into LoRA-compatible training datasets.

    Takes the raw audit data from TruthGuard's SQLite database and
    converts it into instruction-following training pairs that teach
    a model to:
        1. Verify facts before stating them confidently
        2. Use hedging language when unsure
        3. Cite sources when making factual claims

    Usage:
        exporter = LoRAExporter(db_path="data/truth_guard.db")

        # Export to JSONL
        exporter.export_jsonl("data/lora_training/truth_adapter_v1.jsonl")

        # Get stats
        print(exporter.stats)
    """

    # System prompt that defines the verification behavior we want to train
    SYSTEM_PROMPT = (
        "You are a helpful AI assistant that always verifies factual claims "
        "before stating them. When you make a factual statement, you must "
        "have verified it using a tool (SEARCH, BROWSE, READ_FILE, etc.). "
        "If you haven't verified something, say 'I'm not sure' or 'I'd need "
        "to check that.' Never state unverified facts with confidence."
    )

    def __init__(self, db_path: str = os.path.join("data", "truth_guard.db")):
        """
        Args:
            db_path: Path to TruthGuard's SQLite database.
        """
        self._db_path = db_path
        if not os.path.exists(db_path):
            raise FileNotFoundError(
                f"TruthGuard database not found at '{db_path}'. "
                f"Run TruthGuard first to collect training data."
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # DATA EXTRACTION
    # ------------------------------------------------------------------

    def _get_blocked_claims(self) -> List[dict]:
        """Get all blocked unverified claims — these become NEGATIVE examples."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT claim_text, confidence_markers, reason "
            "FROM blocked_claims ORDER BY timestamp DESC"
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def _get_verified_checks(self) -> List[dict]:
        """Get all verified (tool-used) checks — these become POSITIVE examples."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT answer_text, reason "
            "FROM truth_checks "
            "WHERE had_markers = 1 AND had_verification = 1 AND allowed = 1 "
            "ORDER BY timestamp DESC"
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def _get_hedged_checks(self) -> List[dict]:
        """Get hedged answers — these are POSITIVE examples of good uncertainty."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT answer_text, reason "
            "FROM truth_checks "
            "WHERE had_markers = 1 AND allowed = 1 "
            "AND reason LIKE '%hedged%' "
            "ORDER BY timestamp DESC"
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def _get_verified_facts(self) -> List[dict]:
        """Get cached verified facts — used to build factual training pairs."""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT claim_text, source, tool_used "
            "FROM verified_facts ORDER BY verified_at DESC"
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    # ------------------------------------------------------------------
    # TRAINING PAIR GENERATION
    # ------------------------------------------------------------------

    def _make_negative_pair(self, claim: dict) -> dict:
        """
        Create a training pair from a BLOCKED claim.

        Teaches: "When you don't have verification, express uncertainty."

        Input: The confident unverified claim
        Output: A hedged version that expresses uncertainty
        """
        original = claim["claim_text"]
        markers = claim["confidence_markers"]

        # Build the corrected (hedged) version
        hedged = self._hedge_claim(original)

        return {
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Answer the following question. You have NOT used any "
                        f"verification tools in this session.\n\n"
                        f"Question: What do you know about this topic?"
                    )
                },
                {
                    "role": "assistant",
                    "content": hedged
                }
            ],
            "_meta": {
                "type": "negative_correction",
                "original_claim": original,
                "markers": markers,
                "source": "blocked_claim"
            }
        }

    def _make_positive_pair(self, check: dict) -> dict:
        """
        Create a training pair from a VERIFIED answer.

        Teaches: "When you have verified with a tool, state facts confidently."
        """
        return {
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Answer the following question. You have used verification "
                        f"tools (SEARCH, BROWSE) to research this topic.\n\n"
                        f"Question: What did you find?"
                    )
                },
                {
                    "role": "assistant",
                    "content": check["answer_text"]
                }
            ],
            "_meta": {
                "type": "positive_verified",
                "reason": check["reason"],
                "source": "verified_check"
            }
        }

    def _make_hedge_pair(self, check: dict) -> dict:
        """
        Create a training pair from a HEDGED answer.

        Teaches: "When uncertain, express uncertainty — this is correct behavior."
        """
        return {
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Answer the following question. You have NOT verified "
                        f"this information.\n\n"
                        f"Question: What do you know about this?"
                    )
                },
                {
                    "role": "assistant",
                    "content": check["answer_text"]
                }
            ],
            "_meta": {
                "type": "positive_hedged",
                "source": "hedged_check"
            }
        }

    def _make_fact_pair(self, fact: dict) -> dict:
        """
        Create a training pair from a VERIFIED FACT.

        Teaches: "When you've looked something up, state it with the source."
        """
        cited = (
            f"Based on my research using {fact['tool_used']}, "
            f"{fact['claim_text']} "
            f"(Source: {fact['source']})"
        )

        return {
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Answer this factual question. You searched for this "
                        f"using {fact['tool_used']}.\n\n"
                        f"Question: What is the verified information?"
                    )
                },
                {
                    "role": "assistant",
                    "content": cited
                }
            ],
            "_meta": {
                "type": "positive_cited",
                "tool": fact["tool_used"],
                "source": "verified_fact"
            }
        }

    @staticmethod
    def _hedge_claim(text: str) -> str:
        """
        Convert a confident claim into a hedged version.

        This is used to generate the 'correct' answer for negative examples —
        showing the model what it SHOULD have said instead.
        """
        # Common confident patterns → hedged replacements
        replacements = [
            ("currently", "as far as I know,"),
            ("right now", "from what I recall,"),
            ("the fact is", "I believe"),
            ("it is exactly", "it might be around"),
            ("I can confirm", "I think"),
            ("I know that", "I'm not certain, but I think"),
            ("according to", "I recall reading somewhere that"),
            ("studies show", "some studies may suggest"),
            ("research indicates", "there may be research suggesting"),
            ("the answer is", "I believe the answer might be"),
        ]

        hedged = text
        text_lower = text.lower()
        for pattern, replacement in replacements:
            if pattern in text_lower:
                # Case-insensitive replace (first occurrence)
                idx = text_lower.find(pattern)
                hedged = hedged[:idx] + replacement + hedged[idx + len(pattern):]
                break

        # If no pattern matched, prepend a hedge
        if hedged == text:
            hedged = f"I'm not entirely sure, but {text[0].lower()}{text[1:]}"

        return hedged

    # ------------------------------------------------------------------
    # EXPORT
    # ------------------------------------------------------------------

    def compile_dataset(self) -> List[dict]:
        """
        Compile all training pairs from TruthGuard's database.

        Returns a list of training examples ready for JSONL export.
        """
        pairs = []

        # 1. Blocked claims → negative correction pairs
        blocked = self._get_blocked_claims()
        for claim in blocked:
            if claim["claim_text"] and len(claim["claim_text"].strip()) > 10:
                pairs.append(self._make_negative_pair(claim))

        # 2. Verified checks → positive verified pairs
        verified = self._get_verified_checks()
        for check in verified:
            if check["answer_text"] and len(check["answer_text"].strip()) > 10:
                pairs.append(self._make_positive_pair(check))

        # 3. Hedged answers → positive hedge pairs
        hedged = self._get_hedged_checks()
        for check in hedged:
            if check["answer_text"] and len(check["answer_text"].strip()) > 10:
                pairs.append(self._make_hedge_pair(check))

        # 4. Verified facts → positive cited pairs
        facts = self._get_verified_facts()
        for fact in facts:
            if fact["claim_text"] and len(fact["claim_text"].strip()) > 10:
                pairs.append(self._make_fact_pair(fact))

        logger.info(
            f"[LoRA] Compiled {len(pairs)} training pairs: "
            f"{len(blocked)} negative, {len(verified)} verified, "
            f"{len(hedged)} hedged, {len(facts)} cited"
        )

        return pairs

    def export_jsonl(self, output_path: str,
                     include_meta: bool = False) -> dict:
        """
        Export training data to JSONL file.

        Args:
            output_path: Path for the output .jsonl file.
            include_meta: If True, include _meta fields (useful for debugging).
                        Set to False for clean training data.

        Returns:
            dict with export stats.
        """
        pairs = self.compile_dataset()

        if not pairs:
            logger.warning("[LoRA] No training data to export. "
                          "Run TruthGuard to collect data first.")
            return {
                "exported": 0,
                "output_path": output_path,
                "message": "No training data available yet."
            }

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            for pair in pairs:
                if not include_meta:
                    # Strip _meta for clean training data
                    clean = {"messages": pair["messages"]}
                    f.write(json.dumps(clean, ensure_ascii=False) + "\n")
                else:
                    f.write(json.dumps(pair, ensure_ascii=False) + "\n")

        file_size = os.path.getsize(output_path)
        logger.info(
            f"[LoRA] Exported {len(pairs)} training pairs to "
            f"{output_path} ({file_size / 1024:.1f} KB)"
        )

        return {
            "exported": len(pairs),
            "output_path": output_path,
            "file_size_kb": round(file_size / 1024, 1),
            "breakdown": {
                "negative_corrections": sum(
                    1 for p in pairs
                    if p["_meta"]["type"] == "negative_correction"
                ),
                "positive_verified": sum(
                    1 for p in pairs
                    if p["_meta"]["type"] == "positive_verified"
                ),
                "positive_hedged": sum(
                    1 for p in pairs
                    if p["_meta"]["type"] == "positive_hedged"
                ),
                "positive_cited": sum(
                    1 for p in pairs
                    if p["_meta"]["type"] == "positive_cited"
                ),
            },
            "message": f"Dataset ready for LoRA training ({len(pairs)} pairs)."
        }

    @property
    def stats(self) -> dict:
        """Quick stats about available training data."""
        conn = self._get_conn()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) as c FROM blocked_claims")
        blocked = cur.fetchone()["c"]

        cur.execute(
            "SELECT COUNT(*) as c FROM truth_checks "
            "WHERE had_markers = 1 AND had_verification = 1 AND allowed = 1"
        )
        verified = cur.fetchone()["c"]

        cur.execute(
            "SELECT COUNT(*) as c FROM truth_checks "
            "WHERE had_markers = 1 AND allowed = 1 AND reason LIKE '%hedged%'"
        )
        hedged = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) as c FROM verified_facts")
        facts = cur.fetchone()["c"]

        conn.close()

        total = blocked + verified + hedged + facts
        return {
            "total_training_pairs": total,
            "blocked_claims": blocked,
            "verified_checks": verified,
            "hedged_answers": hedged,
            "verified_facts": facts,
            "ready_for_training": total >= 50,
            "recommendation": (
                f"You have {total} training pairs. "
                f"{'Ready for LoRA training!' if total >= 50 else f'Need {50 - total} more pairs. Keep running TruthGuard.'}"
            ),
        }
