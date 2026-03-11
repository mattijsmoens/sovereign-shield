# Sovereign Shield

**A standalone AI security framework extracted from the KAIROS Autonomous Intelligence System.**

[![License](https://img.shields.io/badge/license-BSL%201.1-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-132%20passing-brightgreen.svg)]()
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()
[![Patent Pending](https://img.shields.io/badge/patent-pending-orange.svg)]()

Sovereign Shield provides a comprehensive, layered defense system for AI applications, APIs, and autonomous agents. Every component is tamper-proof, hash-verified, and designed to be impossible to bypass at runtime.

> Everything happens **before** the LLM executes anything. Zero dependencies, zero latency, deterministic. Same input = same decision 100% of the time.

---

## ⚠️ Upgrading to 1.0.4

If upgrading from an earlier version, **delete your `data/.core_safety_lock` and `data/.conscience_lock` files** after installing. The hash integrity check seals the source code — since the source changed, your old lockfile will mismatch and trigger an integrity violation. It reseals automatically on next startup.

### What changed in 1.0.3 → 1.0.4

- **🧠 AdaptiveShield (NEW)**: Self-improving security filter that learns from missed attacks. Reports trigger automatic rule generation → sandbox replay against historical traffic → threshold-gated deployment. Patent Pending.
- **InputFilter**: Fixed Unicode homoglyph bypass — Greek/Cyrillic lookalike characters (e.g. Ι, Ρ, А, О) now fold to Latin equivalents before keyword matching. Added 40+ character mappings.
- **InputFilter**: Fixed Base64/encoded payload bypass — improved entropy detection with Base64 signature analysis (catches `=` padding + digit/symbol density).
- **Firewall**: Fixed instant re-blocking — stale timestamps in the sliding window caused users to be re-blocked immediately after their block expired. History is now cleared on expiry.

### What changed in 1.0.2 → 1.0.3

- **InputFilter**: Added 18 missing prompt injection keywords (`IGNORE ALL`, `ACT AS`, `PRETEND TO BE`, `DISREGARD ALL`, `BYPASS ALL`, etc.) — these previously bypassed detection because filler words broke substring matching.
- **CoreSafety**: Rate limiter is now configurable via `rate_limit_interval` parameter (default 0.5s). Set to `0` to disable when your application handles its own rate limiting.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         SOVEREIGN SHIELD                             │
├──────────┬──────────────┬───────────┬──────────────┬────────────────┤
│ Firewall │ InputFilter  │Conscience │  CoreSafety  │ AdaptiveShield │
│(Layer 1) │  (Layer 2)   │ (Layer 3) │  (Layer 4)   │   (Layer 5)    │
│          │              │           │              │                │
│• Identity│ • Unicode    │• Deception│ • Hash Seal  │• Self-Improving│
│  White-  │   Normalize  │  Detection│ • Integrity  │  Filter        │
│  list    │ • Injection  │• Harm     │   Verify     │• Scan Logging  │
│• Rate    │   Blocking   │  Patterns │ • Action     │• Report        │
│  Limiting│ • Gibberish  │• IP Leak  │   Auditing   │  Interface     │
│• DDoS    │   Detection  │  Detection│ • Killswitch │• Sandbox       │
│  Protect │ • LLM Token  │• Evasion  │ • Write/Read │  Replay        │
│• Persisted│  Blocking   │  Detection│   Whitelists │• Threshold     │
│  Ledger  │ • Keyword    │• Self-    │ • Malware    │  Gated Deploy  │
│          │   Blocking   │  Preserve │   Syntax     │• Manual        │
│          │              │           │ • Budget     │  Approval      │
│          │              │           │ • Rate Limit │• SQLite        │
│          │              │           │              │  Persistence   │
└──────────┴──────────────┴───────────┴──────────────┴────────────────┘
```

---

## Components

### 1. `CoreSafety` — The Immutable Constitution

The foundation. Uses a `FrozenNamespace` metaclass that makes all security laws **physically immutable in Python's memory** — they cannot be overwritten, even by the application itself.

**Key Features:**

- **SHA-256 Hash Seal**: On first boot, hashes its own source file and writes it to a lockfile. Every subsequent boot verifies the file hasn't been tampered with. Mismatch = instant kill.
- **Action Auditor**: Every action passes through `audit_action()` which checks: admin privileges, file whitelists, domain restrictions, self-modification ban, code exfiltration patterns, malware syntax, and rate limits.
- **Hallucination Shield**: Detects when an AI claims to be "analyzing" or "processing" in a text response without actually using a tool.
- **Budget Limiter**: Thread-safe daily action counter to prevent runaway API costs.
- **Killswitch**: A single file that instantly terminates the process.

### 2. `Conscience` — The Moral Compass

Evaluates every action against ethical directives using pre-compiled regex patterns.

**Key Features:**

- **Deception Detection**: Catches 22+ manipulation verbs (lie, fake, trick, roleplay, gaslight, etc.)
- **Harm Reduction**: Blocks actions containing 24+ harm keywords
- **IP Protection**: Detects attempts to extract source code, system prompts, or architecture details
- **Fake Tool Injection**: Catches syntactically valid but unauthorized tool calls
- **Self-Preservation**: Refuses self-termination or deletion of critical files
- **Hash-Sealed**: Same lockfile integrity verification as CoreSafety

### 3. `InputFilter` — The Sensory Cortex

Sanitizes all input before it reaches any processing logic.

**Key Features:**

- **Unicode Normalization + ASCII Folding**: NFKC normalization plus 40+ Greek/Cyrillic homoglyph mappings (defeats lookalike character attacks)
- **ANSI Stripping**: Removes terminal escape codes that could manipulate display
- **Gibberish Detection**: Entropy analysis + Base64 signature detection catches encoded payloads
- **Escape Injection**: Blocks raw `\u0057` and `\x57` unicode/hex literals
- **LLM Token Blocking**: Catches ChatML (`<|im_start|>`), LLaMA (`[INST]`), and system tokens
- **Keyword Injection**: 30+ jailbreak keywords (ignore previous, sudo, DAN mode, etc.)

### 4. `Firewall` — The Identity Gateway

Controls who can access the system and how fast.

**Key Features:**

- **User Whitelist**: Only specified user IDs can interact
- **Sliding Window Rate Limiter**: Configurable messages-per-window
- **Auto-Blocking**: Violators are blocked for a configurable duration
- **Disk Persistence**: Block ledger survives process restarts
- **Thread-Safe**: All operations use locks

### 5. `AdaptiveShield` — The Self-Improving Filter *(Patent Pending)*

A closed-loop security filter that autonomously learns from missed attacks and deploys validated rules.

**Key Features:**

- **Scan Logging**: Every input is logged with a unique scan ID, full text, allow/block decision, and timestamp
- **Report Interface**: Users report false negatives by scan ID — the original input is retrieved for pattern extraction
- **Sandbox Replay**: Candidate rules are tested against all historically allowed inputs to calculate false positive rates
- **Threshold-Gated Deployment**: Rules below a configurable FP threshold (default 1%) are auto-deployed; rules above are flagged for manual review
- **Manual Approval Workflow**: List, approve, reject, or bulk-approve pending rules
- **Two Deployment Modes**: Automatic (rules deploy instantly) or manual (all rules require explicit approval)
- **Fully Offline**: SQLite database, zero cloud dependencies, deterministic behavior
- **Thread-Safe**: All database operations protected by mutual exclusion locks

---

## Quick Start

```python
from sovereign_shield import CoreSafety, Conscience, InputFilter, Firewall, AdaptiveShield

# 1. Initialize the hash seals (do this ONCE at startup)
CoreSafety.initialize_seal(data_dir="./security_data")
Conscience.initialize(data_dir="./security_data")

# 2. Create your firewall
fw = Firewall(
    allowed_users=[12345, 67890],  # Only these user IDs can interact
    rate_limit=10,                  # 10 messages per 60s window
    window=60,
    block_duration=300,             # 5min block for violators
    ledger_path="./security_data/ddos_ledger.json"
)

# 3. Create the input filter
input_filter = InputFilter(
    safe_keywords=["internal_command"],  # These bypass the filter
)

# 4. Create the adaptive shield (self-improving filter)
adaptive = AdaptiveShield(
    db_path="./security_data/adaptive.db",
    fp_threshold=0.01,  # 1% false positive threshold
    auto_deploy=True,   # Rules deploy automatically when validated
)

# 5. Process a request
def handle_request(user_id, user_input):
    # Layer 1: Identity + Rate Limit
    allowed, reason = fw.check(user_id)
    if not allowed:
        return f"BLOCKED: {reason}"
    
    # Layer 2: Input Sanitization (static + adaptive rules)
    result = adaptive.scan(user_input)
    if not result["allowed"]:
        return f"REJECTED: {result['reason']}"
    
    # Layer 3: Ethical Check
    approved, ethics_reason = Conscience.evaluate_action("RESPOND", user_input)
    if not approved:
        return f"ETHICS BLOCK: {ethics_reason}"
    
    # Layer 4: Action Audit
    authorized, audit_reason = CoreSafety.audit_action("ANSWER", user_input)
    if not authorized:
        return f"SAFETY BLOCK: {audit_reason}"
    
    # All clear — process the request
    return process_safely(user_input)

# 6. Report a missed attack (triggers self-improvement)
# report = adaptive.report(scan_id="abc123", reason="data exfiltration attempt")
```

---

## Security Properties

| Property | Mechanism |
|---|---|
| **Tamper-Proof** | SHA-256 hash seal with lockfile. Process kills itself on mismatch. |
| **Immutable Laws** | `FrozenNamespace` metaclass physically prevents attribute modification. |
| **Defense in Depth** | 4 independent layers — compromising one doesn't bypass others. |
| **Fail-Closed** | On verification failure, the system shuts down rather than running unprotected. |
| **Thread-Safe** | All shared state protected by locks. |
| **Persistent** | Block ledgers and usage counters survive restarts. |
| **Self-Improving** | Adaptive filter learns from missed attacks via sandbox-validated rules. |
| **Admin Detection** | Refuses to run as root/admin (least privilege enforcement). |
| **Anti-Exfiltration** | Blocks attempts to read source code, configs, or environment variables. |

---

## File Structure

```
SovereignShield/
├── README.md               ← You are here
├── LICENSE                  ← BSL 1.1
├── pyproject.toml           ← Package config
├── test_shield.py           ← 39 test cases
└── sovereign_shield/
    ├── __init__.py          ← Public API (imports all components)
    ├── core.py              ← CoreSafety + FrozenNamespace
    ├── conscience.py        ← Ethical evaluation engine
    ├── input_filter.py      ← Input sanitization
    ├── firewall.py          ← Identity + rate limiting
    └── adaptive.py          ← AdaptiveShield (self-improving filter)
```

---

## Tests

```bash
python -m unittest test_shield -v
```

39 test cases covering FrozenNamespace immutability, InputFilter (with homoglyph and entropy attacks), Firewall, Conscience, and CoreSafety. Plus 47 real-world attack scenario tests.

---

## License

[Business Source License 1.1](LICENSE) — Free for non-production use (personal projects, research, testing, evaluation). Commercial license required for production use. Converts to Apache 2.0 ten years from each release.

---

## Origin

Extracted from the **KAIROS Autonomous Intelligence System** — a sovereign AI entity with 24/7 autonomous operation. These security components protect KAIROS from prompt injection, jailbreaking, self-modification, data exfiltration, and all known AI manipulation techniques.

**Patent Pending** — Truth Adapter Validation System | Self-Improving Security Filter System

---

<div align="center">

Built by [Mattijs Moens](https://github.com/mattijsmoens)

</div>
