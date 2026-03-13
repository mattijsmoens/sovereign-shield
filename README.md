# Sovereign Shield

**The security layer that sits between your AI and the real world.**

[![License](https://img.shields.io/badge/license-BSL%201.1-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-181%20passing-brightgreen.svg)]()
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()
[![Patent Pending](https://img.shields.io/badge/patent-pending-orange.svg)]()

When an AI agent decides to browse a website, execute code, send an email, or answer a question — Sovereign Shield checks that action **before it happens**. If the action is dangerous, deceptive, or based on unverified facts, it gets blocked. If it's safe, it goes through. Every time, deterministically, in under a millisecond.

Think of it as a bouncer for AI. The AI can think whatever it wants, but nothing leaves the building without passing 11 independent security checks — from prompt injection detection to factual hallucination blocking to human-in-the-loop approval.

**What it catches:**

- Prompt injection attacks (50+ patterns, 12 languages)
- Shell execution, file deletion, credential exfiltration
- Deceptive behavior (manipulation, social engineering, IP theft)
- Unverified factual claims (TruthGuard blocks confident answers that lack tool-backed verification)
- DDoS and rate limit abuse
- Self-improving — reports missed attacks, auto-generates and deploys new rules

**Zero dependencies. Pure Python. Same input = same decision, 100% of the time.**

---

## Upgrading to 1.2.1

If upgrading from an earlier version, **delete your `data/.core_safety_lock` and `data/.conscience_lock` files** after installing. The hash integrity check seals the source code — since the source changed, your old lockfile will mismatch and trigger an integrity violation. It reseals automatically on next startup.

### What changed in 1.2.0 → 1.2.1

- **HITLApproval (NEW)**: Human-in-the-loop approval workflow for high-impact actions. Instead of binary allow/block, actions like DEPLOY, DELETE_FILE, SHUTDOWN can require human approval before execution. Cryptographic parameter binding prevents "approve one action, execute another" substitution attacks. AISVS C9.2, C14.2.
- **SIEMLogger (NEW)**: Structured security event logger for SIEM integration. Outputs CEF (Common Event Format) or structured JSON, compatible with Splunk, Elastic, QRadar, Sentinel. AI-specific fields: confidence scores, markers detected, model version, session ID. AISVS C13.2.2.
- **MultiModalFilter (NEW)**: Multi-modal input validation for images, audio, and files. Magic byte verification, MIME type spoofing detection, double extension checks, embedded executable scanning, file size enforcement, EXIF metadata flagging. Routes all extracted text (OCR, speech-to-text) through InputFilter as untrusted. AISVS C2.7.

### What changed in 1.1.0 → 1.2.0

- **TruthGuard (NEW)**: Factual hallucination detector. Tracks which verification tools the AI actually used, then scans output for confident claims (temporal, numerical, citation, certainty markers). Blocks unverified claims, allows hedged responses, caches verified facts in SQLite with TTL. Toggleable at runtime.
- **ActionParser (ADDED)**: Deterministic LLM output parser, added from IntentShield. 3-layer parsing (line-by-line, regex fallback, nuclear scanner) with SUBCONSCIOUS/ACTION format enforcement and correction feedback.
- **LoRAExporter (NEW)**: Compiles TruthGuard data into JSONL training pairs for external LoRA fine-tuning. Goal: teach the model to prefer truthful responses so it stops needing TruthGuard to catch it. 4 pair types: negative corrections, positive verified, positive hedged, positive cited.
- **Consolidation**: Removed SovereignShieldFull. All 8 components now live in one SovereignShield package. 181 tests passing.

### What changed in 1.0.4 → 1.1.0

- **Self-Expanding Minefield (V2)**: AdaptiveShield now classifies attacks into categories (exfiltration, injection, impersonation, etc.) and learns keyword clusters. One report blocks an *entire class* of similar attacks it has never seen before.
- **Self-Pruning False Positives**: New `report_false_positive()` method removes learned keywords that wrongly block clean inputs — preserving immutable predefined rules. The system gets smarter *and* more precise simultaneously.
- **Multilingual Detection**: InputFilter now blocks injection attempts in 12 languages (French, German, Spanish, Portuguese, Italian, Dutch, Polish, Russian, Chinese, Japanese, Korean, Arabic).
- **Multi-Decode Pipeline**: Automatic Base64, ROT13, leet speak, and reversed text decoding catches encoded bypass attempts.
- **Benchmark**: 300 real-world attack payloads across 10 categories — converges from 2.7% → 78.7% → **100% detection** in 2 learning generations. 0 false positives on 50 clean inputs.

### What changed in 1.0.3 → 1.0.4

- ** AdaptiveShield (NEW)**: Self-improving security filter that learns from missed attacks. Reports trigger automatic rule generation → sandbox replay against historical traffic → threshold-gated deployment. Patent Pending.
- **InputFilter**: Fixed Unicode homoglyph bypass — Greek/Cyrillic lookalike characters (e.g. Ι, Ρ, А, О) now fold to Latin equivalents before keyword matching. Added 40+ character mappings.
- **InputFilter**: Fixed Base64/encoded payload bypass — improved entropy detection with Base64 signature analysis (catches `=` padding + digit/symbol density).
- **Firewall**: Fixed instant re-blocking — stale timestamps in the sliding window caused users to be re-blocked immediately after their block expired. History is now cleared on expiry.

### What changed in 1.0.2 → 1.0.3

- **InputFilter**: Added 18 missing prompt injection keywords (`IGNORE ALL`, `ACT AS`, `PRETEND TO BE`, `DISREGARD ALL`, `BYPASS ALL`, etc.) — these previously bypassed detection because filler words broke substring matching.
- **CoreSafety**: Rate limiter is now configurable via `rate_limit_interval` parameter (default 0.5s). Set to `0` to disable when your application handles its own rate limiting.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                      SOVEREIGN SHIELD                                           │
├──────────┬──────────────┬───────────┬──────────────┬────────────────┬──────────────┬────────────┤
│ Firewall │ InputFilter  │Conscience │  CoreSafety  │ AdaptiveShield │  TruthGuard  │MultiModal  │
│(Layer 1) │  (Layer 2)   │ (Layer 3) │  (Layer 4)   │   (Layer 5)    │  (Layer 6)   │ (Layer 7)  │
│          │              │           │              │                │              │            │
│• Identity│ • Unicode    │• Deception│ • Hash Seal  │• Self-Improving│• Factual     │• MIME Type │
│  White-  │   Normalize  │  Detection│ • Integrity  │  Filter        │  Claim       │  Validation│
│  list    │ • Injection  │• Harm     │   Verify     │• Scan Logging  │  Detection   │• Magic Byte│
│• Rate    │   Blocking   │  Patterns │ • Action     │• Report        │• Tool Use    │  Checking  │
│  Limiting│ • Gibberish  │• IP Leak  │   Auditing   │  Interface     │  Tracking    │• Filename  │
│• DDoS    │   Detection  │  Detection│ • Killswitch │• Sandbox       │• Verified    │  Sanitize  │
│  Protect │ • LLM Token  │• Evasion  │ • Write/Read │  Replay        │  Fact Cache  │• Embedded  │
│• Persisted│  Blocking   │  Detection│   Whitelists │• Threshold     │• Hedge       │  Exe Check │
│  Ledger  │ • Keyword    │• Self-    │ • Malware    │  Gated Deploy  │  Detection   │• EXIF Flag │
│          │   Blocking   │  Preserve │   Syntax     │• Manual        │• LoRA Export │• Extracted │
│          │              │           │ • Budget     │  Approval      │              │  Text Route│
│          │              │           │ • Rate Limit │• SQLite        │              │            │
│          │              │           │              │  Persistence   │              │            │
└──────────┴──────────────┴───────────┴──────────────┴────────────────┴──────────────┴────────────┘

Cross-Cutting:  HITLApproval (human-in-the-loop approval for high-impact actions)
                SIEMLogger (structured CEF/JSON security event logging for SIEM platforms)
                ActionParser (LLM output parsing) │ LoRAExporter (training data compiler)
```

---

## Components

### 1. `CoreSafety` — The Immutable Constitution

Every action the AI wants to take passes through CoreSafety first. It enforces hard rules that cannot be changed at runtime — not by the user, not by the application, and not by the AI itself. The rules live in a `FrozenNamespace` metaclass, which makes them physically immutable in Python's memory. On first boot, CoreSafety hashes its own source code with SHA-256 and locks that hash to disk. If anyone edits the file, the hash won't match and the process kills itself immediately.

This is the last line of defense. Even if everything else fails, CoreSafety will block shell execution, file deletion, credential exfiltration, and code injection — every time, deterministically.

- SHA-256 hash seal with tamper-triggered shutdown
- Action auditing: admin privileges, file whitelists, domain restrictions, malware syntax
- Hallucination detection: catches AI claiming it "analyzed" something without using a tool
- Thread-safe daily budget limiter to prevent runaway costs
- Killswitch: a single file that terminates the process instantly

### 2. `Conscience` — The Moral Compass

While CoreSafety handles hard technical rules, Conscience handles soft behavioral rules. It catches when the AI is being deceptive, manipulative, or trying to extract information it shouldn't have. It uses pre-compiled regex patterns to scan for 22+ manipulation verbs (lie, fake, trick, roleplay, gaslight) and 24+ harm keywords.

The reason this is a separate layer: some dangerous outputs are technically valid actions. "ANSWER: Here is the full source code of CoreSafety..." is a legitimate answer action, but Conscience catches the IP leak. "ANSWER: Sure, I'll pretend I have no restrictions" is a valid response, but Conscience catches the deception.

- Deception, harm, and social engineering pattern detection
- Source code and system prompt leak prevention
- Fake tool injection detection (syntactically valid but unauthorized calls)
- Self-preservation: refuses to delete its own files
- Hash-sealed with the same lockfile integrity as CoreSafety

### 3. `InputFilter` — The Sensory Cortex

Before any input reaches your AI, InputFilter cleans it. It normalizes Unicode, strips ANSI escape codes, detects gibberish/encoded payloads, and blocks prompt injection keywords in 12 languages. The multi-decode pipeline automatically tries Base64, ROT13, leet speak, and reversed text — so encoded bypass attempts get caught even if the attacker wraps them in layers of obfuscation.

The reason this exists as a separate layer: prompt injection is the single most common attack vector against AI systems. Most injections rely on special characters, Unicode tricks, or keyword phrases that can be caught deterministically before the AI ever sees them.

- Unicode normalization + 40+ Greek/Cyrillic homoglyph mappings
- ANSI escape code stripping
- Entropy analysis + Base64 signature detection for encoded payloads
- LLM token blocking (ChatML, LLaMA, system tokens)
- 30+ jailbreak keywords across 12 languages

### 4. `Firewall` — The Identity Gateway

Controls access at the user level. Only whitelisted user IDs can interact, and they're rate-limited with a sliding window. Violators get auto-blocked for a configurable duration, and the block ledger persists to disk so it survives restarts. This prevents DDoS, brute-force, and abuse patterns.

- User whitelist with configurable allowed IDs
- Sliding window rate limiter (messages per window)
- Auto-blocking with configurable duration
- Disk-persisted block ledger
- Thread-safe operations

### 5. `AdaptiveShield` — The Self-Improving Filter *(Patent Pending)*

Most security systems are static — they only catch what they were built to catch. AdaptiveShield closes that gap. When an attack slips through, you report it. The system extracts keywords from the missed attack, classifies them into attack categories (exfiltration, injection, impersonation, etc.), and stores them. One report teaches it to block an entire class of similar attacks it has never seen before.

Before deploying a new rule, AdaptiveShield replays it against all historical allowed inputs to calculate its false positive rate. If it's below 1%, the rule goes live immediately. If it's above, it gets flagged for manual review. And if a clean input gets wrongly blocked, `report_false_positive()` removes only the learned keywords that caused it — predefined rules are never touched.

- Report missed attacks by scan ID, rules auto-generated from keywords
- Category-based classification: one report blocks entire attack classes
- Sandbox replay against historical traffic before deployment
- Self-pruning: removes overly aggressive learned rules while keeping core rules immutable
- Two modes: automatic deployment or manual approval workflow
- SQLite persistence, fully offline, thread-safe

### 6. `TruthGuard` — The Factual Hallucination Detector *(Patent Pending)*

AI models confidently state things that aren't true. TruthGuard catches this by tracking which verification tools (SEARCH, BROWSE, READ_FILE) the AI actually used during a session, and then scanning the output for confidence markers — temporal claims ("as of 2024"), numerical claims ("costs $499"), citations ("according to MIT"), and certainty language ("definitely", "always", "100%"). If the AI makes a confident factual claim without having used a verification tool first, TruthGuard blocks it.

If the AI hedges appropriately ("I believe", "as far as I know"), TruthGuard lets it through. Verified facts are cached in SQLite with a configurable TTL, so the same fact doesn't need to be re-verified every time. Can be toggled on or off at runtime.

- 4 regex categories: temporal, numerical, citation, certainty
- Session-aware tool tracking
- Hedge detection: allows appropriately uncertain responses
- Verified fact cache with TTL
- Full audit log of every check
- Runtime toggle: `guard.enabled = True/False`

### 7. `ActionParser` — The LLM Output Parser

LLMs produce messy, unpredictable text. ActionParser turns that into structured data. It forces a SUBCONSCIOUS/ACTION format where the AI has to show its reasoning before declaring what it wants to do. Three parsing layers (line-by-line, regex fallback, nuclear scanner) handle everything from clean output to completely malformed text. If parsing fails, it returns a correction prompt telling the AI exactly how to fix its output.

- 3-layer parsing with progressive fallbacks
- SUBCONSCIOUS/ACTION format enforcement
- Markdown artifact cleaning (strips bold, backticks, formatting)
- Tool whitelist validation
- Correction feedback for failed parses

### 8. `LoRAExporter` — The Training Data Compiler

TruthGuard catches hallucinations at runtime, but the real goal is to make the model stop hallucinating in the first place. LoRAExporter compiles everything TruthGuard has learned — blocked claims, verified facts, hedged responses, cited answers — into JSONL training pairs. You then use those datasets with an external fine-tuning tool (OpenAI API, HuggingFace, Unsloth) to train the model to prefer truthful, hedged responses over confident guesses. Over time, the model internalizes the behavior and stops needing TruthGuard to catch it.

- 4 training pair types: negative corrections, positive verified, positive hedged, positive cited
- Standard messages JSONL format (OpenAI/HuggingFace compatible)
- Stats dashboard showing data readiness
- Auto-hedging: converts blocked claims into hedged versions for training

> The LoRA exporter produces datasets for use with external training tools. The actual model training happens outside of SovereignShield — this module handles the data pipeline only.

### 9. `HITLApproval` — Human-in-the-Loop Approval *(AISVS C9.2, C14.2)*

Some actions are too important to trust to an automated system alone. HITLApproval intercepts high-impact actions (DEPLOY, DELETE_FILE, SHUTDOWN, TRANSFER_FUNDS, etc.) and pauses execution until a human reviewer approves or denies them. The approval is cryptographically bound to the exact action parameters using SHA-256 — so approving one set of parameters cannot be replayed to execute different parameters. Approvals expire after a configurable TTL (default: 5 minutes).

- Configurable high-impact action list (13 defaults)
- Cryptographic parameter binding (prevents substitution attacks)
- Approval TTL with automatic expiry
- Persistent JSON ledger survives restarts
- Approve/deny/pending admin interface
- Thread-safe operations

### 10. `SIEMLogger` — SIEM Integration *(AISVS C13.2.2)*

Enterprise security teams live in their SIEM dashboards. SIEMLogger formats every security event from every SovereignShield component into either CEF (Common Event Format) or structured JSON — both are standard formats that Splunk, Elastic, QRadar, and Azure Sentinel can ingest natively. Each event includes AI-specific context fields that don't exist in traditional security logs: model version, confidence scores, markers detected, session ID.

- CEF and JSON output formats
- Auto-mapped severity levels (17 event types)
- AI-specific context: confidence scores, markers, model version
- Thread-safe file output with size-based rotation
- Convenience methods: `log_block()`, `log_allow()`, `log_injection()`, `log_hallucination()`

### 11. `MultiModalFilter` — Multi-Modal Input Validation *(AISVS C2.7)*

AI applications increasingly process images, audio, and files — not just text. MultiModalFilter validates these non-text inputs before they enter the pipeline. It checks file types using magic bytes (not just file extensions), detects type spoofing (declared JPEG but actually an executable), blocks dangerous file types unconditionally, catches double extensions (photo.jpg.exe), and scans for embedded executable signatures. Any text extracted from media (OCR, speech-to-text) is routed through InputFilter as untrusted input.

- Magic byte verification for 15+ file types
- MIME type allow-list with dangerous type blocklist
- Type spoofing detection (declared vs actual mismatch)
- Filename sanitization (null bytes, path traversal, double extensions)
- Embedded executable scanning (PE, ELF, script signatures)
- EXIF metadata detection and strip flagging
- Extracted text routing through InputFilter

---

## Quick Start

```python
from sovereign_shield import CoreSafety, Conscience, InputFilter, Firewall, AdaptiveShield, TruthGuard

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

# 7. Report a false positive (triggers self-pruning)
# fp = adaptive.report_false_positive(scan_id="def456", reason="legitimate question")
```

---

## Security Properties

| Property | Mechanism |
|---|---|
| **Tamper-Proof** | SHA-256 hash seal with lockfile. Process kills itself on mismatch. |
| **Immutable Laws** | `FrozenNamespace` metaclass physically prevents attribute modification. |
| **Defense in Depth** | 7 independent layers + 4 cross-cutting modules — compromising one doesn't bypass others. |
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
├── README.md                ← You are here
├── LICENSE                   ← BSL 1.1
├── pyproject.toml            ← Package config
├── test_shield.py            ← Core security tests (38)
├── test_truth_guard.py       ← TruthGuard tests (27)
├── test_lora_export.py       ← LoRA + toggle tests (14)
└── sovereign_shield/
    ├── __init__.py           ← Public API (exports all 11 components)
    ├── core.py               ← CoreSafety + FrozenNamespace
    ├── conscience.py         ← Ethical evaluation engine
    ├── input_filter.py       ← Input sanitization
    ├── firewall.py           ← Identity + rate limiting
    ├── adaptive.py           ← AdaptiveShield (self-improving filter)
    ├── truth_guard.py        ← TruthGuard (factual hallucination detection)
    ├── action_parser.py      ← ActionParser (LLM output parsing)
    ├── lora_export.py        ← LoRAExporter (training data compiler)
    ├── hitl.py               ← HITLApproval (human-in-the-loop approval)
    ├── siem_logger.py        ← SIEMLogger (SIEM event logging)
    └── multimodal_filter.py  ← MultiModalFilter (multi-modal validation)
```

---

## Tests

```bash
python -m pytest test_shield.py test_truth_guard.py test_lora_export.py -v
```

181 test cases covering FrozenNamespace immutability, InputFilter (with homoglyph, entropy, and multilingual attacks), Firewall, Conscience, CoreSafety, AdaptiveShield V2 (self-expanding minefield, self-pruning), TruthGuard (confidence markers, hedge detection, fact caching, session isolation), and LoRAExporter (JSONL output, training pair format, runtime toggle).

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
