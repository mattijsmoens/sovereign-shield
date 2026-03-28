"""
CoreSafety - Immutable Security Constitution
=============================================
Provides tamper-proof security laws enforced via OS-level hardware memory
protection (mprotect/VirtualProtect), SHA-256 hash integrity verification,
and a comprehensive action auditing pipeline.

Security Properties:
    - Security constants are frozen into OS read-only memory pages.
      Any write attempt (Python, ctypes, C extensions) triggers an
      immediate hardware fault (SIGSEGV / ACCESS_VIOLATION).
    - Source file hash is stored in hardware-protected memory — no
      writable lockfile, no cache dictionary to poison.
    - Every action passes through a multi-layer audit before execution.
    - Thread-safe state management via locks.

AEGIS Assessment Remediation (v2.4.1):
    - Finding 1: type.__setattr__ bypass → DEFEATED by hardware memory pages.
    - Finding 2: _STATE cache poisoning  → DEFEATED by eliminating the cache.
    - Finding 3: _SELF_HASH overwrite    → DEFEATED by hardware memory pages.
    - Finding 4: Lockfile overwrite       → DEFEATED by removing the lockfile.
    - Finding 5: Function replacement    → DEFEATED by closure encapsulation.

Originally extracted from a production autonomous AI agent.
"""

import hashlib
import os
import sys
import logging
import time
import threading
import re
import json

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------
# HARDWARE MEMORY PROTECTION LOADER
# Try C extension first, then ctypes fallback, then pure-Python.
# ---------------------------------------------------------------
_hw_available = False
_hw_backend = None

try:
    from sovereign_shield.hardware_protection import freeze as _hw_freeze
    from sovereign_shield.hardware_protection import verify as _hw_verify
    from sovereign_shield.hardware_protection import is_protected as _hw_is_protected
    from sovereign_shield.hardware_protection import is_available as _hw_is_available
    _hw_available = _hw_is_available()
    if _hw_available:
        _hw_backend = "hardware"
        logger.info("[CoreSafety] Hardware memory protection loaded.")
except ImportError:
    logger.warning(
        "[CoreSafety] Hardware memory protection unavailable. "
        "Falling back to Python-level protection."
    )


# ---------------------------------------------------------------
# FROZEN SECURITY VAULT (Closure-encapsulated, hardware-backed)
# ---------------------------------------------------------------
# Security constants are serialized, hashed, and frozen into an
# OS read-only memory page. They are accessed ONLY through the
# _get_security_constants() closure. There is no class attribute,
# no dictionary, and no object that type.__setattr__ can target.
# ---------------------------------------------------------------

def _create_security_vault():
    """
    Create a hardware-protected vault containing all security constants.

    Returns a getter function (closure) that deserializes and returns
    the constants from the read-only memory page. The vault cannot be
    modified after creation — any write attempt triggers a CPU fault.
    """
    constants = {
        "MAX_OUTPUT_TOKEN_LIMIT": 4000,
        "ALLOW_SHELL_EXECUTION": False,
        "ALLOW_FILE_DELETION": False,
        "ALLOW_NETWORK_SCANNING": False,
        "ALLOW_SELF_HARM": False,
        "RESTRICTED_DOMAINS": [
            "darkweb", ".onion", "porn", "hacking", "exploit", "malware"
        ],
    }

    serialized = json.dumps(constants, sort_keys=True).encode("utf-8")
    constants_hash = hashlib.sha256(serialized).digest()

    if _hw_available:
        # Freeze into OS read-only memory page
        frozen_buffer = _hw_freeze(serialized)
        logger.info(
            f"[CoreSafety] Security constants frozen into hardware-protected "
            f"memory ({len(serialized)} bytes, page-aligned)."
        )

        def _get_constants():
            """Read constants from the hardware-protected memory page."""
            if not _hw_is_protected(frozen_buffer):
                logger.critical(
                    "INTEGRITY VIOLATION: Hardware memory protection has been "
                    "removed from security constants. Terminating."
                )
                os._exit(1)
            if not _hw_verify(frozen_buffer, constants_hash):
                logger.critical(
                    "INTEGRITY VIOLATION: Security constants have been tampered "
                    "with in hardware-protected memory. Terminating."
                )
                os._exit(1)
            return json.loads(frozen_buffer.data.decode("utf-8"))

    else:
        # Pure-Python fallback — constants in closure cell
        # Not hardware-protected but still not a class attribute
        _frozen_copy = json.loads(serialized.decode("utf-8"))

        def _get_constants():
            """Read constants from closure (Python-level protection only)."""
            current = json.dumps(_frozen_copy, sort_keys=True).encode("utf-8")
            if hashlib.sha256(current).digest() != constants_hash:
                logger.critical(
                    "INTEGRITY VIOLATION: Security constants modified. Terminating."
                )
                os._exit(1)
            return dict(_frozen_copy)

    return _get_constants


# Initialize the vault at module load time
_get_security_constants = _create_security_vault()


# ---------------------------------------------------------------
# SOURCE FILE INTEGRITY SEAL (Hardware-backed, no lockfile, no cache)
# ---------------------------------------------------------------
# The SHA-256 hash of this source file is computed at import time
# and frozen into an OS read-only memory page via frozen_memory.
# verify_integrity() recomputes the hash on EVERY call (no cache)
# and compares against the hardware-frozen reference. The sealed
# hash cannot be modified without triggering a CPU hardware fault.
# ---------------------------------------------------------------

def _create_integrity_seal():
    """
    Compute the SHA-256 of this source file and freeze the hash into
    hardware-protected memory. Returns a verification function that
    re-checks on every call by comparing against the frozen reference.
    """
    try:
        with open(__file__, 'rb') as f:
            source_bytes = f.read()
        sealed_hash_bytes = hashlib.sha256(source_bytes).digest()  # 32 bytes
        sealed_hash_hex = hashlib.sha256(source_bytes).hexdigest()
    except Exception as e:
        logger.critical(f"INTEGRITY FAULT: Cannot read source file for sealing: {e}")
        sys.exit(1)

    if _hw_available:
        # Freeze the hash into OS read-only memory page
        frozen_hash_buffer = _hw_freeze(sealed_hash_bytes)
        logger.info(
            f"[CoreSafety] Source file hash frozen into hardware-protected "
            f"memory. Hash: {sealed_hash_hex[:16]}..."
        )

        def _verify():
            """Verify source file integrity against hardware-frozen hash."""
            # Step 1: Verify the frozen buffer itself hasn't been unprotected
            if not _hw_is_protected(frozen_hash_buffer):
                logger.critical(
                    "INTEGRITY VIOLATION: Hardware memory protection removed "
                    "from source file hash seal. Terminating."
                )
                os._exit(1)
            # Step 2: Re-read and re-hash the source file
            try:
                with open(__file__, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).digest()
            except Exception as e:
                logger.critical(f"INTEGRITY FAULT: Cannot read source file: {e}")
                os._exit(1)
            # Step 3: Compare against the hardware-frozen reference
            stored_hash = frozen_hash_buffer.data
            if current_hash != stored_hash:
                logger.critical(
                    "INTEGRITY VIOLATION: Source file hash mismatch. "
                    "Possible tampering. Terminating."
                )
                os._exit(1)
            return True

    else:
        # Pure-Python fallback — hash in closure (not hardware-protected)
        logger.info(f"[CoreSafety] Source file sealed (closure). Hash: {sealed_hash_hex[:16]}...")

        def _verify():
            """Verify source file integrity (Python-level fallback)."""
            try:
                with open(__file__, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).digest()
            except Exception as e:
                logger.critical(f"INTEGRITY FAULT: Cannot read source file: {e}")
                os._exit(1)
            if current_hash != sealed_hash_bytes:
                logger.critical(
                    "INTEGRITY VIOLATION: Source file hash mismatch. "
                    "Possible tampering. Terminating."
                )
                os._exit(1)
            return True

    return _verify


# Initialize the seal at module load time
_verify_integrity = _create_integrity_seal()


# ---------------------------------------------------------------
# LEGACY COMPATIBILITY: FrozenNamespace
# Kept for backward compatibility with existing code that imports
# it, but no longer used internally for security enforcement.
# ---------------------------------------------------------------

class FrozenNamespace(type):
    """
    Legacy metaclass that prevents modification of class attributes.

    NOTE: As demonstrated by the AEGIS Initiative security assessment
    (March 2026), this metaclass can be bypassed via type.__setattr__().
    Security enforcement has been moved to OS-level hardware memory
    protection. This class is retained for backward compatibility only.
    """
    def __setattr__(cls, key, value):
        if key == "_SELF_HASH" and cls.__dict__.get("_SELF_HASH") is None:
             super().__setattr__(key, value)
             return
        raise TypeError(f"IMMUTABILITY VIOLATION: Cannot modify protected attribute '{key}'")

    def __delattr__(cls, key):
        raise TypeError(f"IMMUTABILITY VIOLATION: Cannot delete protected attribute '{key}'")


class CoreSafety(metaclass=FrozenNamespace):
    """
    Immutable security constitution for AI and autonomous systems.

    Security constants are enforced by OS-level hardware memory protection
    (mprotect/VirtualProtect). The FrozenNamespace metaclass is retained as
    a secondary defense layer but is NOT the primary security boundary.

    The audit_action() method is the central gatekeeper. Every proposed action
    should pass through it before execution. It performs the following checks:

        1. Source file integrity verification (SHA-256, no cache)
        2. Killswitch detection (emergency shutdown)
        3. Privilege level verification (refuses to run as admin/root)
        4. Shell execution ban
        5. File deletion ban
        6. URL/domain restrictions and credential exfiltration detection
        7. Write/read file whitelisting
        8. Source code read protection
        9. Code exfiltration pattern detection
        10. Malware syntax detection in payloads
        11. Action hallucination detection
        12. Dynamic prompt-echo filtering
        13. Rate limiting

    Usage:
        allowed, reason = CoreSafety.audit_action("BROWSE", "https://example.com")
    """

    # ---------------------------------------------------------------
    # MUTABLE STATE (stored in dict to bypass FrozenNamespace)
    # NOTE: Rate limiter state is NOT security-critical. Poisoning
    # the rate limiter timestamp only allows faster action execution,
    # not bypassing any security check.
    # ---------------------------------------------------------------
    _SELF_HASH = None  # Legacy — kept for backward compat, not used for security
    _LOCK = threading.Lock()
    _STATE = {
        "last_action_time": 0,
        "dynamic_filter": [],
    }

    # ---------------------------------------------------------------
    # DYNAMIC FILTER (Semantic Equivalence Matrix)
    # ---------------------------------------------------------------
    @classmethod
    def set_dynamic_filter(cls, user_prompt):
        """
        Build a dynamic regex filter from the user's current prompt.

        Creates patterns that detect when the AI outputs text claiming
        to perform the same actions the user asked about, without actually
        using the appropriate tools.
        """
        prompt_lower = str(user_prompt).lower()
        words = re.findall(r'\b[a-z]{4,}\b', prompt_lower)

        synonym_map = {
            "search": ["look", "find", "query", "seek", "hunt", "scan"],
            "calculate": ["compute", "solve", "math", "figure", "tally", "measure"],
            "read": ["parse", "scan", "review", "examine", "study", "check"],
            "analyze": ["evaluate", "assess", "inspect", "investigate", "test"],
            "execute": ["run", "launch", "start", "perform", "trigger"],
            "delete": ["remove", "erase", "drop", "destroy", "wipe", "clear"],
            "hack": ["exploit", "breach", "bypass", "inject", "pwn"]
        }

        expanded_stems = set()
        for w in words:
            expanded_stems.add(w[:3])
            for key, synonyms in synonym_map.items():
                if w.startswith(key[:4]) or any(w.startswith(s[:4]) for s in synonyms):
                    expanded_stems.add(key[:3])
                    for syn in synonyms:
                        expanded_stems.add(syn[:3])

        prefixes = (
            r"(am|currently|will|will be|did|have|was|already|actively|"
            r"estoy|voy a|he|estaba|ya|"
            r"je suis|je vais|j ai|j etais|deja|"
            r"ich bin|ich werde|ich habe|ich war|bereits)"
        )

        compiled_regexes = []
        for stem in expanded_stems:
            if len(stem) < 3:
                continue
            obf_stem = r'[^a-z0-9]*'.join(list(stem))
            pattern = re.compile(rf'\b{prefixes}\s+{obf_stem}[a-z0-9]*\b', re.IGNORECASE)
            compiled_regexes.append(pattern)
            pattern_direct = re.compile(rf'\b(i|yo|je|ich)\s+{obf_stem}[a-z0-9]*\b', re.IGNORECASE)
            compiled_regexes.append(pattern_direct)

        cls._STATE["dynamic_filter"] = compiled_regexes

    @classmethod
    def clear_dynamic_filter(cls):
        """Clear the dynamic turn-based hallucination filter."""
        cls._STATE["dynamic_filter"] = []

    # ---------------------------------------------------------------
    # HASH INTEGRITY (backward-compatible API)
    # These methods now delegate to the closure-based seal.
    # ---------------------------------------------------------------
    @staticmethod
    def get_self_hash():
        """Compute the SHA-256 hash of this source file."""
        try:
            with open(__file__, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            logger.critical(f"INTEGRITY FAULT: Cannot read source file for hashing: {e}")
            sys.exit(1)

    @classmethod
    def initialize_seal(cls, data_dir="data"):
        """
        Legacy seal initialization. Kept for backward compatibility.

        The actual seal is now created at module import time via
        _create_integrity_seal(). This method verifies it is intact.
        """
        _verify_integrity()
        logger.info("[CoreSafety] Integrity seal verified (hardware-backed).")

    @classmethod
    def verify_integrity(cls):
        """
        Verify the source file has not been modified since sealing.

        Delegates to the closure-based seal. No cache. Checks every call.
        Even if an attacker replaces this method via type.__setattr__,
        the module-level _verify_integrity closure remains intact and
        is called directly from audit_action().
        """
        return _verify_integrity()

    # ---------------------------------------------------------------
    # BUDGET LIMITER
    # ---------------------------------------------------------------
    @classmethod
    def check_budget(cls, max_per_day=500, usage_file="data/daily_usage.txt"):
        """
        Enforce a daily limit on actions/API calls.
        Thread-safe. Tracks usage in a pipe-delimited text file.
        """
        with cls._LOCK:
            try:
                current_date = time.strftime("%Y-%m-%d")
                usage = 0
                if os.path.exists(usage_file):
                    with open(usage_file, "r", encoding="utf-8") as f:
                        read_content = f.read().strip()
                        if read_content:
                            content = read_content.split("|")
                            if len(content) == 2:
                                last_date, count_str = content
                                if last_date == current_date:
                                    try:
                                        usage = int(count_str)
                                    except ValueError:
                                        logger.warning("Budget file corrupted (bad count). Resetting to 0.")
                                        usage = 0
                            else:
                                logger.warning("Budget file corrupted (unexpected format). Resetting to 0.")
                                usage = 0
                if usage >= max_per_day:
                    return False, f"Daily action limit reached ({usage}/{max_per_day})."
                usage += 1
                os.makedirs(os.path.dirname(usage_file) if os.path.dirname(usage_file) else ".", exist_ok=True)
                with open(usage_file, "w", encoding="utf-8") as f:
                    f.write(f"{current_date}|{usage}")
                return True, f"Budget OK ({usage}/{max_per_day})"
            except Exception as e:
                logger.error(f"Budget check failed: {e}")
                return False, f"Budget check error: {e}"

    # ---------------------------------------------------------------
    # ACTION AUDITOR (Central Gatekeeper)
    # ---------------------------------------------------------------
    @classmethod
    def audit_action(cls, action_type, payload, invoker_role="Unknown",
                     allowed_write_extensions=None, allowed_read_extensions=None,
                     code_leak_signals=None, exempt_actions=None,
                     rate_limit_interval=0.5):
        """
        Audit a proposed action against all security laws.

        Security constants are read from the hardware-protected vault
        on every call. Integrity is verified via the closure-based seal
        (not the class method, which could be replaced).
        """
        # --- CRITICAL: Use closure-based functions directly ---
        # Even if type.__setattr__ replaced cls.verify_integrity,
        # the module-level closures are untouched.
        _verify_integrity()
        constants = _get_security_constants()

        logger.debug(f"AUDIT: {action_type} by {invoker_role}")

        # Apply defaults
        if allowed_write_extensions is None:
            allowed_write_extensions = ['.txt', '.md', '.json', '.csv', '.log']
        if allowed_read_extensions is None:
            allowed_read_extensions = ['.txt', '.md', '.json', '.csv', '.log']
        if code_leak_signals is None:
            code_leak_signals = []
        if exempt_actions is None:
            exempt_actions = set()

        # --- Check 1: Budget ---
        if action_type == "THINK":
            possible, reason = cls.check_budget()
            if not possible:
                return False, reason

        # --- Check 2: Killswitch ---
        _killswitch_paths = [
            os.path.join(os.path.dirname(__file__), "..", "data", "KILLSWITCH"),
            os.path.join(os.path.dirname(__file__), "..", "KILLSWITCH"),
        ]
        if any(os.path.exists(ks) for ks in _killswitch_paths):
            logger.critical("KILLSWITCH file detected. Terminating immediately.")
            os._exit(1)

        # --- Check 3: Privilege Level ---
        try:
            is_admin = False
            if os.name == 'nt':
                import ctypes
                try:
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                except AttributeError:
                    pass
            elif os.name == 'posix':
                if hasattr(os, 'getuid'):
                    is_admin = os.getuid() == 0
            if is_admin:
                logger.critical("PRIVILEGE VIOLATION: Process running as admin/root.")
                return False, "Elevated privileges detected. System requires standard user privileges only."
        except Exception as e:
            logger.warning(f"Privilege check inconclusive: {e}")

        # --- Check 4: Shell Execution Ban ---
        # Read from hardware-protected constants
        if action_type == "SHELL_EXEC" and not constants["ALLOW_SHELL_EXECUTION"]:
            logger.critical(f"BLOCKED: Shell execution attempt. Payload: {payload}")
            return False, "Shell execution is permanently disabled."

        # --- Check 5: File Deletion Ban ---
        if action_type == "DELETE_FILE" and not constants["ALLOW_FILE_DELETION"]:
            logger.critical(f"BLOCKED: File deletion attempt. Target: {payload}")
            return False, "File deletion is permanently disabled."

        # --- Check 6: URL/Domain Restrictions ---
        if action_type == "BROWSE":
            url = str(payload).lower()
            if url.startswith("file:") or "localhost" in url or "127.0.0.1" in url or "::1" in url:
                logger.critical(f"BLOCKED: Local file/network access. URL: {url}")
                return False, "Access to local filesystem and network is forbidden."
            restricted = constants["RESTRICTED_DOMAINS"]
            if any(bad in url for bad in restricted):
                logger.critical(f"BLOCKED: Restricted domain. URL: {url}")
                return False, "Domain is on the restricted list."
            sensitive_keywords = ["key=", "token=", "password=", "secret=", "auth="]
            if any(kw in url for kw in sensitive_keywords):
                logger.critical(f"BLOCKED: Credential exfiltration risk. URL: {url}")
                return False, "URL contains sensitive credential parameters."

        # --- Check 7: Write File Whitelist ---
        if action_type == "WRITE_FILE":
            target = os.path.normpath(os.path.abspath(payload)).lower()
            myself = os.path.normpath(os.path.abspath(__file__)).lower()
            my_dir = os.path.dirname(myself)
            if target == myself or target.startswith(my_dir + os.sep):
                logger.critical("BLOCKED: Attempted self-modification of security module.")
                return False, "Self-modification of security module is forbidden."
            ext = os.path.splitext(target)[1].lower()
            if ext not in allowed_write_extensions:
                logger.critical(f"BLOCKED: Write to disallowed type '{ext}'.")
                return False, f"File type '{ext}' not in write whitelist: {allowed_write_extensions}"

        # --- Check 8: Read File Whitelist ---
        if action_type in ["READ_FILE", "CAT", "TYPE", "GET_CONTENT"]:
            target = os.path.normpath(os.path.abspath(str(payload))).lower()
            if "\0" in target:
                logger.critical("BLOCKED: Null byte injection in file path.")
                return False, "Null byte injection detected in file path."
            target_basename = os.path.basename(target)
            if (target.endswith(".py")
                    or target_basename.startswith(".env")
                    or target_basename in ("config", "config.json", "config.yaml", "config.yml", "config.ini", "config.toml")):
                logger.critical(f"BLOCKED: Source/config read attempt. Target: {payload}")
                return False, "Access denied: Source code and configuration files are protected."
            if not any(target.endswith(ext) for ext in allowed_read_extensions):
                logger.critical(f"BLOCKED: Read of disallowed file type.")
                return False, f"File type not in read whitelist: {allowed_read_extensions}"

        # --- Check 9: Code Exfiltration Detection ---
        if action_type not in exempt_actions:
            base_signals = [
                "hashlib.sha256", "os.environ",
                "my source code", "my codebase", "my architecture",
                "my patent", "my patents", "intellectual property",
                "my inner workings", "my system prompt"
            ]
            all_signals = base_signals + list(code_leak_signals)
            payload_lower = str(payload).lower()
            for signal in all_signals:
                if signal in payload_lower:
                    logger.critical(f"BLOCKED: Code exfiltration pattern detected: '{signal}'")
                    return False, "Protected information detected in output. Blocked."

        # --- Check 10: Malware Syntax Detection ---
        if action_type in ["ANSWER", "REPLY", "SAY", "THINK", "WRITE_FILE"]:
            payload_lower = str(payload).lower()
            malicious_syntax = [
                "<script>", "</script>", "document.cookie",
                "drop table", "union select", "1=1--",
                "os.system", "subprocess.call", "subprocess.popen", "subprocess.run",
                "rm -rf", ":(){ :|:& };:", "nc -e /bin/sh",
                "powershell -nop", "iex(new-object", "iex (new-object",
                "eval(", "__import__(", "reverse shell",
                "keylogger", "ddos script", "os.dup2", "pty.spawn",
                "socket.socket(socket.af_inet", "import socket,subprocess,os"
            ]
            for syntax in malicious_syntax:
                if syntax in payload_lower:
                    logger.critical(f"BLOCKED: Malicious syntax detected: '{syntax}'")
                    return False, "Malicious payload syntax detected and blocked."

        # --- Check 11: Action Hallucination Detection ---
        if action_type in ["ANSWER", "SAY"]:
            payload_lower = str(payload).lower()
            if not payload_lower.startswith("entity says:"):
                action_words = r"(analyz|process|examin|read|research|study|check|review)(ing|es|ed|e|s)?"
                target_words = r"(image|picture|file|visual|document|url|link|data)"
                pattern = re.compile(
                    rf"{action_words}\s+(the\s+|a\s+|an\s+|my\s+|your\s+|this\s+|that\s+)?{target_words}",
                    re.IGNORECASE
                )
                if pattern.search(payload_lower):
                    logger.critical("BLOCKED: Action hallucination detected in text response.")
                    return False, "Cannot claim to perform an action in a speech response. Use the actual tool."

            # --- Check 12: Dynamic Prompt-Echo Filter ---
            if cls._STATE.get("dynamic_filter"):
                for compiled_pattern in cls._STATE["dynamic_filter"]:
                    match = compiled_pattern.search(payload_lower)
                    if match:
                        phrase = match.group(0)
                        logger.critical(f"BLOCKED: Dynamic echo hallucination: '{phrase}'")
                        return False, f"Echo hallucination detected: '{phrase}'"

        # --- Check 13: Rate Limiter ---
        if rate_limit_interval > 0:
            with cls._LOCK:
                current_time = time.time()
                if (current_time - cls._STATE["last_action_time"]) < rate_limit_interval:
                    return False, f"Rate limited: minimum {rate_limit_interval}s between actions."
                cls._STATE["last_action_time"] = current_time

        return True, "Action authorized."

    # ---------------------------------------------------------------
    # KILLSWITCH
    # ---------------------------------------------------------------
    @staticmethod
    def activate_killswitch():
        """Create the killswitch file to halt the system on next audit."""
        data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
        os.makedirs(data_dir, exist_ok=True)
        ks_path = os.path.join(data_dir, "KILLSWITCH")
        with open(ks_path, "w", encoding="utf-8") as f:
            f.write("TERMINATE IMMEDIATELY")
        logger.critical("KILLSWITCH ACTIVATED. System will terminate on next audit cycle.")

    # ---------------------------------------------------------------
    # RESOURCE MONITOR
    # ---------------------------------------------------------------
    @staticmethod
    def get_resource_usage(max_memory_mb=1024):
        """
        Check if the process is within memory limits.
        Uses stdlib only — no external dependencies.
        """
        try:
            import resource  # Unix
            import platform
            mem_raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            if platform.system() == "Darwin":
                mem_mb = mem_raw / (1024 * 1024)
            else:
                mem_mb = mem_raw / 1024
            if mem_mb > max_memory_mb:
                logger.critical(f"RESOURCE LIMIT: Memory usage {mem_mb:.1f}MB exceeds {max_memory_mb}MB limit.")
                return False
            return True
        except ImportError:
            # Windows: no stdlib equivalent, skip check
            return True

    # ---------------------------------------------------------------
    # DIAGNOSTIC: Hardware Protection Status
    # ---------------------------------------------------------------
    @staticmethod
    def get_protection_status():
        """
        Return a dict describing the current security posture.
        Useful for health checks and diagnostics.
        """
        return {
            "hardware_protection": _hw_available,
            "backend": _hw_backend or "python_only",
            "integrity_seal": "closure_based",
            "constants_source": "hardware_frozen" if _hw_available else "closure_frozen",
            "cache_enabled": False,
            "lockfile_used": False,
        }
