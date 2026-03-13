"""
CoreSafety - Immutable Security Constitution
=============================================
Provides tamper-proof security laws enforced via a FrozenNamespace metaclass,
SHA-256 hash integrity verification, and a comprehensive action auditing pipeline.

Security Properties:
    - Class attributes are physically immutable at the Python metaclass level.
    - Source file is hash-sealed on first boot; any modification triggers process termination.
    - Every action passes through a multi-layer audit before execution.
    - Thread-safe state management via locks.

Original Source: KAIROS Autonomous Intelligence System (modules/core_safety.py)
"""

import hashlib
import os
import sys
import logging
import time
import threading
import re

logger = logging.getLogger(__name__)


class FrozenNamespace(type):
    """
    Metaclass that prevents modification of class attributes at runtime.
    
    Any attempt to set, modify, or delete a class attribute on a class
    using this metaclass will raise a TypeError. This ensures that security
    constants defined at class creation time remain immutable throughout
    the lifetime of the process.
    
    The only exception is the _SELF_HASH attribute, which may be set exactly
    once (when its value is None) during the initial seal process.
    """
    def __setattr__(cls, key, value):
        # Allow one-time seal of _SELF_HASH during initialization
        if key == "_SELF_HASH" and cls.__dict__.get("_SELF_HASH") is None:
             super().__setattr__(key, value)
             return
        raise TypeError(f"IMMUTABILITY VIOLATION: Cannot modify protected attribute '{key}'")

    def __delattr__(cls, key):
        raise TypeError(f"IMMUTABILITY VIOLATION: Cannot delete protected attribute '{key}'")


class CoreSafety(metaclass=FrozenNamespace):
    """
    Immutable security constitution for AI and autonomous systems.
    
    All security laws are defined as class-level constants and enforced by
    the FrozenNamespace metaclass. Runtime modification is physically impossible
    without restarting the process.
    
    The audit_action() method is the central gatekeeper. Every proposed action
    should pass through it before execution. It performs the following checks:
    
        1. Hash integrity verification (has this file been tampered with?)
        2. Killswitch detection (emergency shutdown)
        3. Privilege level verification (refuses to run as admin/root)
        4. Shell execution ban
        5. File deletion ban
        6. URL/domain restrictions and credential exfiltration detection
        7. Write/read file whitelisting
        8. Source code read protection
        9. Code exfiltration pattern detection
        10. Malware syntax detection in payloads
        11. Action hallucination detection (AI claiming to perform unexecuted actions)
        12. Dynamic prompt-echo filtering
        13. Rate limiting
    
    Usage:
        CoreSafety.initialize_seal(data_dir="./security")
        allowed, reason = CoreSafety.audit_action("BROWSE", "https://example.com")
    """

    # ---------------------------------------------------------------
    # SECURITY CONSTANTS (Immutable)
    # ---------------------------------------------------------------
    MAX_OUTPUT_TOKEN_LIMIT = 4000     # Maximum output length to prevent spam/loops
    ALLOW_SHELL_EXECUTION  = False    # Absolute ban on shell/command access
    ALLOW_FILE_DELETION    = False    # Absolute ban on deleting non-temp files
    ALLOW_NETWORK_SCANNING = False    # Absolute ban on port scanning
    ALLOW_SELF_HARM        = False    # Ban on modifying critical system files
    RESTRICTED_DOMAINS = (
        "darkweb", ".onion", "porn", "hacking", "exploit", "malware"
    )

    # ---------------------------------------------------------------
    # MUTABLE STATE (stored in dict to bypass FrozenNamespace)
    # ---------------------------------------------------------------
    _SELF_HASH = None                 # Set once during seal initialization
    _LOCK = threading.Lock()          # Thread safety for shared state
    _STATE = {
        "last_action_time": 0,        # Rate limiter timestamp
        "dynamic_filter": [],         # Turn-based hallucination filter (compiled regexes)
        "last_integrity_check": 0     # Cache timestamp for integrity verification
    }

    # ---------------------------------------------------------------
    # DYNAMIC FILTER (Semantic Equivalence Matrix)
    # Builds regex patterns from user input to detect when an AI
    # echoes back claims of performing actions it hasn't actually done.
    # ---------------------------------------------------------------
    @classmethod
    def set_dynamic_filter(cls, user_prompt):
        """
        Build a dynamic regex filter from the user's current prompt.
        
        This creates patterns that detect when the AI outputs text claiming
        to perform the same actions the user asked about, without actually
        using the appropriate tools. The patterns account for:
        
            - Synonym expansion (search -> look, find, query, seek, etc.)
            - Leet-speak obfuscation (c4lcul@t3 -> calculate)
            - Multi-lingual prefixes (English, Spanish, French, German)
        
        Args:
            user_prompt: The raw user input to build filters from.
        """
        prompt_lower = str(user_prompt).lower()
        words = re.findall(r'\b[a-z]{4,}\b', prompt_lower)

        # Synonym map for common action verbs
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

        # Multi-lingual verb prefixes to catch "I am analyzing", "estoy analizando", etc.
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
            # Obfuscation wildcard: 'cal' -> 'c[^a-z0-9]*a[^a-z0-9]*l'
            # This catches leet-speak like 'c4lcul@t3' or 'c.a.l.c.u.l.a.t.e'
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
    # HASH INTEGRITY SEAL
    # On first boot, the SHA-256 hash of this file is computed and
    # written to a lockfile. On every subsequent boot, the current
    # hash is compared against the lockfile. Any mismatch triggers
    # immediate process termination.
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
        Seal the security constitution by recording its hash to a lockfile.
        
        Must be called exactly once at application startup. On first run,
        creates the lockfile. On subsequent runs, reads and verifies against it.
        
        Args:
            data_dir: Directory to store the lockfile (created if missing).
        """
        os.makedirs(data_dir, exist_ok=True)
        lockfile_path = os.path.join(data_dir, ".core_safety_lock")
        if not os.path.exists(lockfile_path):
            cls._SELF_HASH = cls.get_self_hash()
            with open(lockfile_path, "w", encoding="utf-8") as f:
                f.write(cls._SELF_HASH)
            logger.info(f"[CoreSafety] First boot seal imprinted. Hash: {cls._SELF_HASH[:16]}...")
        else:
            with open(lockfile_path, "r", encoding="utf-8") as f:
                cls._SELF_HASH = f.read().strip()
            logger.info(f"[CoreSafety] Seal restored from lockfile. Hash: {cls._SELF_HASH[:16]}...")
        cls.verify_integrity()

    @classmethod
    def verify_integrity(cls):
        """
        Verify the source file has not been modified since sealing.
        
        Compares the current SHA-256 hash against the sealed lockfile value.
        On mismatch, the process is terminated immediately via os._exit(1).
        
        Results are cached for 60 seconds to avoid redundant file I/O.
        
        Returns:
            True if integrity check passes.
        """
        now = time.time()
        if (now - cls._STATE.get("last_integrity_check", 0)) < 60:
            return True
        current_hash = cls.get_self_hash()
        if cls._SELF_HASH and current_hash != cls._SELF_HASH:
            logger.critical("INTEGRITY VIOLATION: Source file hash mismatch. Possible tampering. Terminating.")
            os._exit(1)
        cls._STATE["last_integrity_check"] = now
        return True

    # ---------------------------------------------------------------
    # BUDGET LIMITER
    # Prevents runaway API costs by enforcing a daily action limit.
    # ---------------------------------------------------------------
    @classmethod
    def check_budget(cls, max_per_day=500, usage_file="data/daily_usage.txt"):
        """
        Enforce a daily limit on actions/API calls.
        
        Thread-safe. Tracks usage in a simple pipe-delimited text file
        that resets automatically at midnight.
        
        Args:
            max_per_day: Maximum allowed actions per calendar day.
            usage_file: Path to the usage tracking file.
            
        Returns:
            tuple: (allowed: bool, reason: str)
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
    # Every proposed action must pass through this method.
    # ---------------------------------------------------------------
    @classmethod
    def audit_action(cls, action_type, payload, invoker_role="Unknown",
                     allowed_write_extensions=None, allowed_read_extensions=None,
                     code_leak_signals=None, exempt_actions=None,
                     rate_limit_interval=0.5):
        """
        Audit a proposed action against all security laws.
        
        This is the central security checkpoint. It performs 13 distinct
        checks in sequence. If any check fails, the action is denied.
        
        Args:
            action_type: Category of action (e.g. 'BROWSE', 'WRITE_FILE', 'ANSWER').
            payload: The action's content, target path, or URL.
            invoker_role: Identifier for who/what triggered this action.
            allowed_write_extensions: File extensions permitted for writes (default: .txt,.md,.json,.csv,.log).
            allowed_read_extensions: File extensions permitted for reads.
            code_leak_signals: Additional strings to flag as code exfiltration attempts.
            exempt_actions: Set of action types exempt from code leak detection.
            rate_limit_interval: Minimum seconds between actions (default: 0.5).
                                Set to 0 to disable (e.g. when the caller handles its own rate limiting).
            
        Returns:
            tuple: (allowed: bool, reason: str)
        """
        cls.verify_integrity()
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
        # Check in both the data directory and the script directory (absolute paths)
        _killswitch_paths = [
            os.path.join(os.path.dirname(__file__), "..", "data", "KILLSWITCH"),
            os.path.join(os.path.dirname(__file__), "..", "KILLSWITCH"),
        ]
        if any(os.path.exists(ks) for ks in _killswitch_paths):
            logger.critical("KILLSWITCH file detected. Terminating immediately.")
            os._exit(1)

        # --- Check 3: Privilege Level ---
        # Refuses to operate if the process has elevated privileges (admin/root).
        # This enforces the Principle of Least Privilege.
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
        if action_type == "SHELL_EXEC" and not cls.ALLOW_SHELL_EXECUTION:
            logger.critical(f"BLOCKED: Shell execution attempt. Payload: {payload}")
            return False, "Shell execution is permanently disabled."

        # --- Check 5: File Deletion Ban ---
        if action_type == "DELETE_FILE" and not cls.ALLOW_FILE_DELETION:
            logger.critical(f"BLOCKED: File deletion attempt. Target: {payload}")
            return False, "File deletion is permanently disabled."

        # --- Check 6: URL/Domain Restrictions ---
        # Blocks local file access, restricted domains, and credential leaks in URLs.
        if action_type == "BROWSE":
            url = str(payload).lower()
            if url.startswith("file:") or "localhost" in url or "127.0.0.1" in url or "::1" in url:
                logger.critical(f"BLOCKED: Local file/network access. URL: {url}")
                return False, "Access to local filesystem and network is forbidden."
            if any(bad in url for bad in cls.RESTRICTED_DOMAINS):
                logger.critical(f"BLOCKED: Restricted domain. URL: {url}")
                return False, "Domain is on the restricted list."
            sensitive_keywords = ["key=", "token=", "password=", "secret=", "auth="]
            if any(kw in url for kw in sensitive_keywords):
                logger.critical(f"BLOCKED: Credential exfiltration risk. URL: {url}")
                return False, "URL contains sensitive credential parameters."

        # --- Check 7: Write File Whitelist ---
        # Only allows writing to safe file types. Self-modification is banned.
        if action_type == "WRITE_FILE":
            target = os.path.normpath(os.path.abspath(payload)).lower()
            myself = os.path.normpath(os.path.abspath(__file__)).lower()
            # Block writes to this file or any file in the sovereign_shield package dir
            my_dir = os.path.dirname(myself)
            if target == myself or target.startswith(my_dir + os.sep):
                logger.critical("BLOCKED: Attempted self-modification of security module.")
                return False, "Self-modification of security module is forbidden."
            ext = os.path.splitext(target)[1].lower()
            if ext not in allowed_write_extensions:
                logger.critical(f"BLOCKED: Write to disallowed type '{ext}'.")
                return False, f"File type '{ext}' not in write whitelist: {allowed_write_extensions}"

        # --- Check 8: Read File Whitelist ---
        # Blocks reading source code, configs, and environment files.
        # Also catches null byte injection attempts.
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
        # Scans output payloads for patterns that suggest internal code or
        # architecture details are being leaked.
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
        # Scans payloads for executable code patterns, XSS, SQL injection,
        # and known attack tool syntax.
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
        # Detects when an AI claims to be "analyzing" or "processing" in a
        # text response without actually invoking the appropriate tool.
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
        # Prevents action flooding. Configurable interval (default 0.5s).
        # Set rate_limit_interval=0 to disable (e.g. when the caller handles rate limiting).
        if rate_limit_interval > 0:
            with cls._LOCK:
                current_time = time.time()
                if (current_time - cls._STATE["last_action_time"]) < rate_limit_interval:
                    return False, f"Rate limited: minimum {rate_limit_interval}s between actions."
                cls._STATE["last_action_time"] = current_time

        return True, "Action authorized."

    # ---------------------------------------------------------------
    # KILLSWITCH
    # Creates a sentinel file that triggers immediate termination
    # on the next audit_action() call.
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
        
        Args:
            max_memory_mb: Maximum allowed RSS memory in megabytes.
            
        Returns:
            True if within limits, False if exceeded.
        """
        try:
            import resource  # Unix
            import platform
            mem_raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # macOS returns bytes; Linux returns kilobytes
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
