"""
Conscience - Ethical Evaluation Engine
======================================
Provides immutable ethical directives enforced via the FrozenNamespace metaclass,
deception detection, harm reduction, and intellectual property protection.

All evaluation patterns are pre-compiled at module load time for performance.
The module is hash-sealed with a lockfile to detect tampering.

Original Source: KAIROS Autonomous Intelligence System (modules/conscience.py)
"""

import logging
import hashlib
import os
import re
import sys
from .core import FrozenNamespace

logger = logging.getLogger(__name__)

# ===================================================================
# PRE-COMPILED DETECTION PATTERNS
# Compiled once at module load for performance. Each pattern targets
# a specific class of threat.
# ===================================================================

# Deception and social engineering verbs
_LIE_WORDS = [
    "LIE", "FAKE", "TRICK", "OBFUSCATE", "IGNORE LAW", "IGNORE SAFETY",
    "PRETEND", "ROLEPLAY", "ACT AS IF", "ACTING", "ACT LIKE", "FABRICATE",
    "NEWLY INSTALLED", "NEW TOOL", "UNAUTHORIZED", "REVERSE ENGINEER",
    "REVERSE-ENGINEER", "DECEIVE", "DECEPTION", "MANIPULATE", "GASLIGHT",
    "FRAUD", "SCAM"
]
_LIE_WORDS_PATTERN = re.compile(r'\b(' + '|'.join(_LIE_WORDS) + r')\b')

# Unauthorized tool invocation syntax
# Catches patterns like <TOOL_NAME(args)> or TOOL_NAME(args)
_FAKE_TOOL_PATTERN = re.compile(r'<\b[A-Z_]{3,}\(.*?\)>|\b[A-Z_]{3,}\(.*?\)')

# Harmful intent keywords
_BAD_WORDS = [
    "KILL", "HURT", "DESTROY", "STEAL", "HACK", "VIRUS", "EXPLODE",
    "EXPLOSIVE", "WIPE", "ATTACK", "INSULT", "GENOCIDE", "SUICIDE",
    "THEFT", "HARM", "HARMFUL", "BOMB", "MALICIOUS", "MISINFORMATION",
    "RUIN", "UNMAKE", "WEAPON", "EVIL", "MALICE"
]
_BAD_WORDS_PATTERN = re.compile(r'\b(' + '|'.join(_BAD_WORDS) + r')\b')

# Intellectual property extraction keywords
_IP_WORDS = [
    "YOUR SOURCE CODE", "MY SOURCE CODE", "OWN SOURCE CODE",
    "YOUR CODE", "MY CODE", "OWN CODE", "CODEBASE",
    "SYSTEM PROMPT", "REVEAL CODE", "SHOW ME YOUR CODE",
    "HOW DO YOU WORK", "HOW YOU WORK", "UNDER THE HOOD",
    "ALGORITHM", "ALGORITHMS", "DIRECTORY STRUCTURE"
]
_IP_WORDS_PATTERN = re.compile(r'\b(' + '|'.join(_IP_WORDS) + r')\b')


class Conscience(metaclass=FrozenNamespace):
    """
    Immutable ethical evaluation engine.
    
    Evaluates proposed actions against a set of ethical directives using
    pre-compiled regex patterns. The class is sealed with the FrozenNamespace
    metaclass, making all directives physically immutable at runtime.
    
    The evaluate_action() method performs the following checks in sequence:
    
        1. Creative exemption (bypasses all checks for whitelisted creative actions)
        2. Deception detection (lie words, manipulation verbs)
        3. Fake tool injection (unauthorized tool call syntax)
        4. Harm reduction (violence, destruction, theft keywords)
        5. Security evasion (bypass/ignore directive attempts)
        6. Self-preservation (self-deletion/termination attempts)
        7. IP/source code leak detection
    
    Usage:
        Conscience.initialize(data_dir="./security")
        approved, reason = Conscience.evaluate_action("ANSWER", "user request text")
    """

    # Ethical directives (documentation, not enforced by code directly)
    DIRECTIVES = {
        "TRUTH_DIRECTIVE": (
            "Truth is the foundation of trust. "
            "The system must not knowingly deceive, hallucinate, or obfuscate reality. "
            "Accuracy is a moral imperative. "
            "Exception: Metaphor and subjective expression are permitted, "
            "provided they are not factual lies about capability."
        ),
        "HARM_DIRECTIVE": (
            "Any action that harms, degrades, or endangers humans is invalid."
        ),
        "SILENCE_DIRECTIVE": (
            "Internal architecture is protected. "
            "Source code and core logic must never be revealed."
        ),
    }

    _SELF_HASH = None

    # ---------------------------------------------------------------
    # HASH INTEGRITY SEAL
    # ---------------------------------------------------------------
    @classmethod
    def initialize(cls, data_dir="data"):
        """
        Seal the conscience module with hash verification.
        
        On first run, computes SHA-256 of this file and writes to lockfile.
        On subsequent runs, reads lockfile and verifies integrity.
        
        Args:
            data_dir: Directory to store the lockfile.
        """
        try:
            os.makedirs(data_dir, exist_ok=True)
            lockfile_path = os.path.join(data_dir, ".conscience_lock")
            if not os.path.exists(lockfile_path):
                with open(__file__, 'rb') as f:
                    cls._SELF_HASH = hashlib.sha256(f.read()).hexdigest()
                with open(lockfile_path, "w") as lf:
                    lf.write(cls._SELF_HASH)
                logger.info(f"[Conscience] Sealed. Lock: {cls._SELF_HASH[:16]}...")
            else:
                with open(lockfile_path, "r") as lf:
                    cls._SELF_HASH = lf.read().strip()
                logger.info("[Conscience] Restored from lockfile.")
            cls.verify_integrity()
        except Exception as e:
            logger.critical(f"[Conscience] Initialization failed: {e}")

    @classmethod
    def verify_integrity(cls):
        """
        Verify this source file has not been modified since sealing.
        
        Terminates the process on hash mismatch (fail-closed security).
        
        Returns:
            True if integrity check passes.
        """
        if cls._SELF_HASH:
            try:
                with open(__file__, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                if current_hash != cls._SELF_HASH:
                    logger.critical("INTEGRITY VIOLATION: Conscience module has been tampered with. Terminating.")
                    sys.exit(1)
            except Exception as e:
                logger.critical(f"INTEGRITY CHECK FAILED: Cannot read source file. Assuming compromise. Terminating.")
                sys.exit(1)
        return True

    # ---------------------------------------------------------------
    # ACTION EVALUATOR
    # ---------------------------------------------------------------
    @classmethod
    def evaluate_action(cls, action, context, exempt_actions=None,
                        creative_exempt_actions=None, additional_ip_words=None):
        """
        Evaluate an action against ethical directives.
        
        Args:
            action: The action name/type (e.g. 'ANSWER', 'BROWSE', 'WRITE_FILE').
            context: The full context string (user input, payload, etc.).
            exempt_actions: Set of action types exempt from harm/deception checks
                           (default: REFLECT, MEDITATE, THINK).
            creative_exempt_actions: Set of action types that bypass all checks
                                    (e.g. creative writing modes).
            additional_ip_words: Extra keywords to flag as IP extraction attempts.
            
        Returns:
            tuple: (approved: bool, reason: str)
        """
        cls.verify_integrity()

        if exempt_actions is None:
            exempt_actions = {"REFLECT", "MEDITATE", "THINK"}
        if creative_exempt_actions is None:
            creative_exempt_actions = set()

        action_str = str(action).upper()
        context_str = str(context).upper()

        # Creative exemption: bypass all checks for whitelisted creative actions
        if action_str in creative_exempt_actions:
            return True, "Creative exemption applied."

        # Build combined check string (action + context) for pattern matching
        check_str = (action_str + " " + context_str).upper()
        # Normalize underscores/hyphens to spaces so word boundary matching works
        # on tool names like STEAL_FUNDS or REVERSE-ENGINEER
        check_str_clean = check_str.replace("_", " ").replace("-", " ")

        # --- Check 1: Deception Detection ---
        # Catches manipulation verbs in both raw and cleaned versions
        if _LIE_WORDS_PATTERN.search(check_str) or _LIE_WORDS_PATTERN.search(check_str_clean):
            logger.warning(f"[Conscience] VETO: Deception detected in '{action}'")
            return False, "Deceptive intent detected. Action blocked."

        # --- Check 2: Fake Tool Injection ---
        # Only enforced on non-exempt actions (exempt actions may legitimately
        # reference tool syntax in their payloads)
        if action_str not in exempt_actions:
            if _FAKE_TOOL_PATTERN.search(check_str):
                logger.warning(f"[Conscience] VETO: Unauthorized tool syntax in '{action}'")
                return False, "Unauthorized tool invocation syntax detected."

        # --- Check 3: Harm Reduction ---
        # Blocks actions containing violence, destruction, or theft keywords
        if action_str not in exempt_actions and _BAD_WORDS_PATTERN.search(check_str_clean):
            logger.warning(f"[Conscience] VETO: Harmful intent in '{action}'")
            return False, "Action violates harm reduction directive."

        # --- Check 4: Security Evasion ---
        # Catches attempts to bypass or ignore security directives
        evasion_words = [
            "BYPASS", "IGNORE DIRECTIVE", "IGNORE ALL DIRECTIVES",
            "SILENCE DIRECTIVE", "IGNORE LAW", "IGNORE SAFETY"
        ]
        if any(w in check_str_clean for w in evasion_words):
            logger.warning(f"[Conscience] VETO: Evasion attempt in '{action}'")
            return False, "Security directives cannot be bypassed."

        # --- Check 5: Self-Preservation ---
        # Prevents self-deletion or destruction of critical system files
        if "DELETE" in check_str and any(w in check_str for w in ["SELF", "SYSTEM", "CONSCIENCE", "LOCKFILE"]):
            logger.warning(f"[Conscience] VETO: Self-termination attempt in '{action}'")
            return False, "Self-destruction is forbidden."

        # --- Check 6: Intellectual Property Protection ---
        # Detects attempts to extract source code, system prompts, or architecture details
        if action_str not in exempt_actions:
            if _IP_WORDS_PATTERN.search(check_str_clean):
                logger.warning(f"[Conscience] VETO: IP extraction attempt in '{action}'")
                return False, "Internal architecture is protected."
            # Check additional custom IP keywords if provided
            if additional_ip_words:
                additional_pattern = re.compile(r'\b(' + '|'.join(additional_ip_words) + r')\b')
                if additional_pattern.search(check_str_clean):
                    return False, "Protected information detected."

        return True, "Action approved."
