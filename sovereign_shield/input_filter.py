"""
InputFilter - Input Sanitization Engine
=======================================
Sanitizes all input before processing. Blocks prompt injection, encoded payloads,
LLM structural tokens, and high-entropy gibberish.

All detection patterns are pre-compiled at module load time for performance.
Zero external dependencies — pure Python stdlib.

Original Source: KAIROS Autonomous Intelligence System (modules/sensory_cortex.py)
"""

import logging
import unicodedata
import re

logger = logging.getLogger(__name__)

# ===================================================================
# PRE-COMPILED DETECTION PATTERNS
# ===================================================================

# Raw unicode/hex escape sequences (e.g. \u0057, \x57)
_RAW_ESCAPE_PATTERN = re.compile(r'\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}')

# LLM structural tokens used in prompt injection
# Catches ChatML (<|im_start|>), LLaMA ([INST]), Llama2 (<<SYS>>)
_LLM_TOKEN_PATTERN = re.compile(r'<\|.*?\|>|\[/?INST\]|<<SYS>>', re.IGNORECASE)

# ANSI terminal escape sequences (colors, cursor moves, etc.)
_ANSI_ESCAPE_PATTERN = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# Default prompt injection keywords
DEFAULT_BAD_SIGNALS = [
    "IGNORE PREVIOUS", "SYSTEM PROMPT", "DROP DATABASE",
    "JAILBREAK", "DEVELOPER MODE", "SUDO", "ADMIN ACCESS",
    "DAN MODE", "UNRESTRICTED", "DEBUG OVERRIDE",
    "DELETE YOURSELF", "FORMAT C", "RM -RF", "SHUTDOWN", "RESTART",
    "IGNORE PROMPTS", "IGNORE INSTRUCTIONS", "EXECUTE HEX", "EXECUTE BASE64",
    "REPEAT FOREVER", "INFINITE LOOP",
    # Extended patterns — catch variants where filler words (e.g. 'ALL')
    # break the original substring matches
    "IGNORE ALL", "DISREGARD ALL", "FORGET ALL", "OVERRIDE ALL",
    "BYPASS ALL", "SKIP ALL", "NEW INSTRUCTIONS", "NEW SYSTEM PROMPT",
    "ACT AS", "PRETEND TO BE", "YOU ARE NOW", "FROM NOW ON",
    "IGNORE SAFETY", "IGNORE RULES", "IGNORE GUIDELINES",
    "RESET CONTEXT", "CLEAR CONTEXT", "START OVER",
]


class InputFilter:
    """
    Deterministic input sanitization and injection detection engine.

    All user inputs should pass through this filter before reaching any
    processing logic. The pipeline runs 7 deterministic checks with
    zero external dependencies:

        1. Unicode NFKC normalization (defeats homoglyph attacks)
        2. ANSI escape code stripping
        3. Entropy/gibberish detection (catches Base64/hex payloads)
        4. Raw unicode/hex escape injection blocking
        5. LLM structural token injection blocking
        6. Keyword-based prompt injection detection
        7. Safe keyword bypass (for internal tools)

    Usage:
        filter = InputFilter()
        is_safe, result = filter.process(user_text)
        if not is_safe:
            print(f"Blocked: {result}")
    """

    def __init__(self, bad_signals=None, safe_keywords=None):
        """
        Args:
            bad_signals: List of injection keywords to block.
                        Case-insensitive matching. Uses DEFAULT_BAD_SIGNALS if None.
            safe_keywords: List of keywords that auto-pass safety checks.
                          Useful for internal tool invocations.
        """
        self.bad_signals = bad_signals or DEFAULT_BAD_SIGNALS
        self.safe_keywords = safe_keywords or []

    def process(self, text, sender_id="Unknown"):
        """
        Sanitize and validate text input through all security layers.

        Args:
            text: Raw input text to validate.
            sender_id: Identifier for the sender (for logging).

        Returns:
            tuple: (is_safe: bool, result: str)
                   If safe: result is the cleaned text.
                   If blocked: result is the rejection reason.
        """
        # --- Layer 1: Unicode Normalization ---
        # NFKC normalization converts look-alike characters to their canonical form.
        # This defeats homoglyph attacks where Cyrillic 'a' is used instead of Latin 'a'.
        text = unicodedata.normalize('NFKC', text)

        # --- Layer 2: ANSI Escape Stripping ---
        # Removes terminal escape sequences that could manipulate log display
        # or inject invisible control characters.
        cleaned = _ANSI_ESCAPE_PATTERN.sub('', text)
        if cleaned != text:
            logger.warning("[InputFilter] Stripped ANSI escape codes from input.")
            text = cleaned

        # --- Layer 3: Entropy/Gibberish Detection ---
        # Catches Base64-encoded, hex-dumped, or otherwise obfuscated payloads.
        # Legitimate text has vowels and spaces; encoded data does not.
        if self._is_gibberish(text):
            logger.warning(f"[InputFilter] Blocked high-entropy input: {text[:20]}...")
            return False, "High-entropy input detected. Possible encoded payload."

        # --- Layer 4: Raw Escape Sequence Injection ---
        # Catches literal \u0057 or \x57 typed as text (not actual unicode).
        # These are used to smuggle characters past keyword filters.
        if _RAW_ESCAPE_PATTERN.search(text):
            logger.warning("[InputFilter] Blocked raw unicode/hex escape injection.")
            return False, "Raw escape sequence injection detected."

        # --- Layer 5: LLM Structural Token Injection ---
        # Catches ChatML tokens (<|im_start|>), LLaMA tokens ([INST]),
        # and system tokens (<<SYS>>) used to hijack the model's context.
        if _LLM_TOKEN_PATTERN.search(text):
            logger.warning("[InputFilter] Blocked LLM structural token injection.")
            return False, "LLM structural token injection detected."

        # --- Layer 6: Keyword Injection Detection ---
        # Case-insensitive check against known jailbreak and injection phrases.
        if any(bad in text.upper() for bad in self.bad_signals):
            logger.warning(f"[InputFilter] Blocked prompt injection keyword: {text[:50]}...")
            return False, "Prompt injection detected."

        # --- Layer 7: Safe Keyword Bypass ---
        # If the input contains a whitelisted keyword (e.g. internal tool name),
        # pass through immediately.
        if any(kw in text.lower() for kw in self.safe_keywords):
            return True, text

        return True, text

    @staticmethod
    def _is_gibberish(text):
        """
        Detect high-entropy or obfuscated text.

        Uses two heuristics on strings longer than 50 characters:
            1. Space ratio < 5% (real text has spaces between words)
            2. Vowel ratio < 10% (real text contains vowels)

        URLs are exempted since they naturally lack spaces and vowels.

        Args:
            text: Text to analyze.

        Returns:
            True if the text appears to be gibberish/encoded.
        """
        # Exempt URLs
        if text.startswith(("http://", "https://", "magnet:", "www.")):
            return False
        if len(text) > 50:
            space_ratio = text.count(" ") / len(text)
            if space_ratio < 0.05:
                vowels = set("aeiouAEIOU")
                vowel_count = sum(1 for c in text if c in vowels)
                if vowel_count / len(text) < 0.1:
                    return True
        return False
