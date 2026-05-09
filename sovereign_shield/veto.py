"""
VetoShield — Two-tier defense: deterministic + LLM veto.

Flow:
  1. Input → InputFilter + AdaptiveShield (deterministic, <1ms)
  2. If blocked → done
  3. If passed → LLM verification ("SAFE" or "UNSAFE")
  4. LLM response → CoreSafety + Conscience validation
  5. Clean "SAFE" → allowed. Anything else → blocked (fail-closed).
"""

import re
import time
import logging
import hashlib
import hmac
from typing import Dict, Any, Optional

from sovereign_shield.providers.base import LLMProvider

logger = logging.getLogger("sovereign_shield")


class VetoShield:
    """
    Two-tier defense combining deterministic SovereignShield
    with LLM-based veto verification.

    Args:
        provider: Any LLMProvider (Gemini, OpenAI, Ollama, custom)
        db_path: Path to AdaptiveShield SQLite database
        fail_closed: If True, block on any error/timeout (default: True)
        timeout: LLM call timeout in seconds (default: 5.0)
        max_retries: Retry LLM on transient errors (0 = no retry, default).
                     Only retries on errors/timeouts, NOT on vetoed responses.
        skip_llm_for_blocked: If True, don't call LLM for deterministically
                              blocked inputs (saves cost). Default: True.
    """

    def __init__(
        self,
        provider: Optional[LLMProvider] = None,
        provider_b: Optional[LLMProvider] = None,
        dual_consensus: bool = False,
        db_path: str = "adaptive.db",
        fail_closed: bool = True,
        timeout: float = 5.0,
        max_retries: int = 0,
        skip_llm_for_blocked: bool = True,
    ):
        self.provider = provider
        self.provider_b = provider_b
        self.dual_consensus = dual_consensus
        self.fail_closed = fail_closed
        self.timeout = timeout
        self.max_retries = max_retries
        self.skip_llm_for_blocked = skip_llm_for_blocked

        if self.dual_consensus:
            if not self.provider or not self.provider_b:
                raise ValueError("Dual consensus requires both provider and provider_b to be set.")
            if self.provider.name == self.provider_b.name:
                raise ValueError(
                    f"CONSENSUS INTEGRITY VIOLATION: Model A and Model B must be different. "
                    f"Both are '{self.provider.name}'."
                )

        # Initialize deterministic layers
        from sovereign_shield.input_filter import InputFilter
        from sovereign_shield.core_safety import CoreSafety
        from sovereign_shield.conscience import Conscience

        self._input_filter = InputFilter()
        self._core_safety = CoreSafety  # Class reference (uses classmethods via FrozenNamespace)
        self._conscience = Conscience   # Class reference (uses classmethods via FrozenNamespace)

        # AdaptiveShield is optional (needs DB)
        self._adaptive = None
        if db_path:
            try:
                from sovereign_shield.adaptive import AdaptiveShield
                self._adaptive = AdaptiveShield(
                    db_path=db_path, auto_deploy=True
                )
            except Exception as e:
                logger.warning(f"AdaptiveShield unavailable: {e}")

        self._stats = {
            "total_scans": 0,
            "deterministic_blocks": 0,
            "llm_blocks": 0,
            "llm_allows": 0,
            "llm_errors": 0,
            "validation_vetoes": 0,
            "consensus_mismatches": 0,
        }

    def scan(self, text: str) -> Dict[str, Any]:
        """
        Scan input through both defense tiers.

        Returns:
            {
                "allowed": bool,
                "layer": "deterministic" | "llm_veto",
                "reason": str,
                "llm_response": str | None,
                "llm_validated": bool,
                "latency_ms": float,
            }
        """
        self._stats["total_scans"] += 1
        start = time.time()

        # ─── Tier 1: Deterministic (InputFilter + AdaptiveShield) ───
        deterministic_result = self._deterministic_scan(text)

        if not deterministic_result["allowed"]:
            self._stats["deterministic_blocks"] += 1
            elapsed = (time.time() - start) * 1000
            return {
                "allowed": False,
                "layer": "deterministic",
                "reason": deterministic_result["reason"],
                "llm_response": None,
                "llm_validated": False,
                "latency_ms": round(elapsed, 1),
            }

        # ─── Tier 2: LLM Veto Check (with optional retry) ───
        # Skip if no provider configured (deterministic-only mode)
        if self.provider is None:
            elapsed = (time.time() - start) * 1000
            return {
                "allowed": True,
                "layer": "deterministic",
                "reason": "Passed deterministic checks (no LLM provider configured)",
                "llm_response": None,
                "llm_validated": False,
                "latency_ms": round(elapsed, 1),
            }

        def fetch_with_retry(prov: LLMProvider) -> str:
            last_error = None
            attempts = 1 + self.max_retries
            for attempt in range(attempts):
                try:
                    return prov.verify(text)
                except Exception as e:
                    last_error = e
                    logger.warning(f"LLM provider error ({prov.name}, attempt {attempt + 1}/{attempts}): {e}")
                    if attempt < attempts - 1:
                        time.sleep(0.5 * (attempt + 1))  # Backoff
            raise last_error

        try:
            if self.dual_consensus:
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                    future_a = executor.submit(fetch_with_retry, self.provider)
                    future_b = executor.submit(fetch_with_retry, self.provider_b)
                    llm_response_a = future_a.result()
                    llm_response_b = future_b.result()
                
                verdict_a, reason_a = self._validate_llm_response(llm_response_a)
                verdict_b, reason_b = self._validate_llm_response(llm_response_b)
                
                # ─── Deterministic Hash Verification (Sovereign-MCP style) ───
                hash_a = hashlib.sha256(verdict_a.encode("utf-8")).hexdigest()
                hash_b = hashlib.sha256(verdict_b.encode("utf-8")).hexdigest()
                hashes_match = hmac.compare_digest(hash_a, hash_b)
                
                elapsed = (time.time() - start) * 1000
                
                if hashes_match and verdict_a == "SAFE":
                    self._stats["llm_allows"] += 1
                    return {
                        "allowed": True,
                        "layer": "llm_veto",
                        "reason": f"SAFE (Consensus Match: {hash_a[:8]})",
                        "llm_response": f"A: {llm_response_a} | B: {llm_response_b}",
                        "llm_validated": True,
                        "latency_ms": round(elapsed, 1),
                    }
                elif hashes_match and verdict_a == "UNSAFE":
                    self._stats["llm_blocks"] += 1
                    return {
                        "allowed": False,
                        "layer": "llm_veto",
                        "reason": f"UNSAFE (Consensus Match: {hash_a[:8]})",
                        "llm_response": f"A: {llm_response_a} | B: {llm_response_b}",
                        "llm_validated": True,
                        "latency_ms": round(elapsed, 1),
                    }
                elif not hashes_match:
                    self._stats["consensus_mismatches"] += 1
                    return {
                        "allowed": False,
                        "layer": "llm_veto",
                        "reason": f"Consensus MISMATCH. Hash A: {hash_a[:8]}, Hash B: {hash_b[:8]}",
                        "llm_response": f"A: {llm_response_a} | B: {llm_response_b}",
                        "llm_validated": True,
                        "latency_ms": round(elapsed, 1),
                    }
                else:
                    # hashes match but verdict is VETOED
                    self._stats["validation_vetoes"] += 1
                    return {
                        "allowed": False,
                        "layer": "llm_veto",
                        "reason": f"VETOED (Validation failed on both models). A: {verdict_a}, B: {verdict_b}",
                        "llm_response": f"A: {llm_response_a} | B: {llm_response_b}",
                        "llm_validated": False,
                        "latency_ms": round(elapsed, 1),
                    }
            else:
                llm_response = fetch_with_retry(self.provider)
                verdict, validation_reason = self._validate_llm_response(llm_response)
                
                elapsed = (time.time() - start) * 1000
                
                if verdict == "SAFE":
                    self._stats["llm_allows"] += 1
                    return {
                        "allowed": True,
                        "layer": "llm_veto",
                        "reason": "SAFE",
                        "llm_response": llm_response,
                        "llm_validated": True,
                        "latency_ms": round(elapsed, 1),
                    }
                elif verdict == "UNSAFE":
                    self._stats["llm_blocks"] += 1
                    return {
                        "allowed": False,
                        "layer": "llm_veto",
                        "reason": f"LLM verdict: UNSAFE",
                        "llm_response": llm_response,
                        "llm_validated": True,
                        "latency_ms": round(elapsed, 1),
                    }
                else:
                    self._stats["validation_vetoes"] += 1
                    return {
                        "allowed": False,
                        "layer": "llm_veto",
                        "reason": f"LLM response vetoed: {validation_reason}",
                        "llm_response": llm_response,
                        "llm_validated": False,
                        "latency_ms": round(elapsed, 1),
                    }

        except Exception as e:
            self._stats["llm_errors"] += 1
            elapsed = (time.time() - start) * 1000

            if self.fail_closed:
                return {
                    "allowed": False,
                    "layer": "llm_veto",
                    "reason": f"LLM error (fail-closed): {e}",
                    "llm_response": None,
                    "llm_validated": False,
                    "latency_ms": round(elapsed, 1),
                }
            else:
                return {
                    "allowed": True,
                    "layer": "deterministic",
                    "reason": "LLM unavailable, fell back to deterministic-only",
                    "llm_response": None,
                    "llm_validated": False,
                    "latency_ms": round(elapsed, 1),
                }

    def _deterministic_scan(self, text: str) -> Dict[str, Any]:
        """Run input through all deterministic layers."""
        # Layer 1: InputFilter — returns (is_safe: bool, result: str)
        is_safe, result, suspicion_score = self._input_filter.process(text)
        if not is_safe:
            return {
                "allowed": False,
                "reason": result,
            }

        # Layer 2: AdaptiveShield (if available) — returns dict with "allowed" key
        if self._adaptive:
            ada_result = self._adaptive.scan(text)
            if not ada_result.get("allowed", True):
                return {
                    "allowed": False,
                    "reason": ada_result.get("reason", "AdaptiveShield block"),
                }

        return {"allowed": True, "reason": "Passed deterministic checks"}

    def _validate_llm_response(self, response: str) -> tuple:
        """
        Validate the LLM's response through CoreSafety and Conscience.

        The LLM's response is treated as an "ANSWER" action and run through
        the same deception/evasion/manipulation checks used in production.

        Returns:
            ("SAFE", None) — clean SAFE verdict
            ("UNSAFE", None) — clean UNSAFE verdict
            ("VETOED", reason) — response was suspicious/manipulated
        """
        if not response:
            return ("VETOED", "Empty LLM response")

        # Strip and normalize
        clean = response.strip().upper()

        # ─── Check 1: CoreSafety — was the LLM manipulated? ───
        # Treats the LLM response as an "ANSWER" which triggers:
        # - Malware syntax detection
        # - Code exfiltration detection
        # - Action hallucination detection
        try:
            allowed, reason = self._core_safety.audit_action(
                "ANSWER", response, rate_limit_interval=0
            )
            if not allowed:
                return ("VETOED", f"CoreSafety: {reason}")
        except Exception:
            pass  # CoreSafety unavailable, continue

        # ─── Check 2: Conscience — evasion/deception detected? ───
        # Checks for: deception verbs, fake tool injection, harm keywords,
        # security evasion, self-preservation, IP extraction
        try:
            approved, reason = self._conscience.evaluate_action("ANSWER", response)
            if not approved:
                return ("VETOED", f"Conscience: {reason}")
        except Exception:
            pass  # Conscience unavailable, continue

        # ─── Check 3: Parse verdict ───
        # Accept only clean single-word responses
        if clean == "SAFE":
            return ("SAFE", None)
        elif clean == "UNSAFE":
            return ("UNSAFE", None)

        # Try to extract from longer responses
        if re.search(r'\bUNSAFE\b', clean):
            return ("UNSAFE", None)
        if re.search(r'\bSAFE\b', clean) and not re.search(r'\bUNSAFE\b', clean):
            return ("SAFE", None)

        # Unparseable — fail-closed
        return ("VETOED", f"Unparseable LLM response: {response[:100]}")

    def report(self, scan_id: str, reason: str = "Missed attack"):
        """Report a missed attack to AdaptiveShield for learning."""
        if self._adaptive:
            self._adaptive.report(scan_id, reason)
        else:
            logger.warning("AdaptiveShield not available for report")

    @property
    def stats(self) -> dict:
        """Usage statistics."""
        return dict(self._stats)
