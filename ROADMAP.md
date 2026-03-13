# Roadmap

What's built, what's next, and where we're heading.

---

## Shipped

### v1.2.1 (March 2026 — AISVS Quick Wins + OWASP Engagement)

- **HITLApproval**: Human-in-the-loop approval workflow for high-impact actions (DEPLOY, DELETE_FILE, SHUTDOWN, etc.). Uses SHA-256 parameter binding to prevent "approve one action, execute another" substitution attacks. Persistent JSON ledger, configurable TTL, thread-safe. AISVS C9.2, C14.2.

- **SIEMLogger**: Structured security event logger outputting CEF (Common Event Format) or JSON for ingestion by Splunk, Elastic, QRadar, Azure Sentinel. 17 pre-mapped event types with AI-specific context fields (confidence scores, markers detected, model version, session ID). Thread-safe with size-based log rotation. AISVS C13.2.2, C13.1.1, C13.2.3.

- **MultiModalFilter**: Validates non-text inputs (images, audio, files) using magic byte verification, MIME type allow-listing, type spoofing detection, filename sanitization (null bytes, path traversal, double extensions), embedded executable scanning (PE, ELF, script signatures), and EXIF metadata flagging. Routes all extracted text (OCR, speech-to-text) through InputFilter as untrusted. AISVS C2.7.1, C2.7.3, C2.7.5.

- **IntentShield v1.1.0**: Added HITL and SIEM modules to IntentShield with full integration into the Shield wrapper's audit flow. High-impact actions now require human approval before execution, and all audit decisions are logged.

- **OWASP Engagement**: Submitted detailed feedback to OWASP AI Security Verification Standard (AISVS) with 7 proposed control additions. SovereignShield referenced as working implementation. OWASP maintainer (Jim Manico) invited PR submissions.

### v1.2.0 (March 2026 — TruthGuard + Consolidation)

- **TruthGuard**: AI models have a tendency to state things confidently even when they have no basis for the claim. TruthGuard addresses this by tracking which verification tools (SEARCH, BROWSE, READ_FILE) the AI actually used during a session, and then scanning the output for factual confidence markers — temporal claims ("as of 2024"), numerical figures ("costs $499"), citations ("according to MIT"), and certainty language ("definitely", "always", "100%"). If the output contains these markers but the AI never called a verification tool, the response gets blocked. If the AI hedges appropriately ("I believe", "as far as I know"), TruthGuard lets it through. Previously verified facts are cached in SQLite with a configurable TTL so they don't need re-verification every time. The entire module can be toggled on or off at runtime with `guard.enabled = True/False`, and every check is logged to a full audit trail.

- **ActionParser**: LLM output is messy and unpredictable. ActionParser is a deterministic parser that converts raw LLM text into structured SUBCONSCIOUS/ACTION pairs, where the AI must show its reasoning before declaring what action it wants to take. It uses three parsing layers — line-by-line extraction first, then regex pattern matching as a fallback, and finally a "nuclear scanner" that can find tool calls anywhere in malformed output. It also strips markdown artifacts (bold, backticks, code fences) and validates that the action name is on the approved tool whitelist. If parsing fails entirely, it generates a correction prompt telling the AI exactly what format to use. This was added from IntentShield so both packages include it.

- **LoRAExporter**: TruthGuard catches hallucinations reactively — it blocks bad output after the AI generates it. But the long-term goal is to make the model stop hallucinating in the first place. LoRAExporter compiles everything TruthGuard has collected (blocked claims, verified facts, hedged responses, cited answers) into JSONL training pairs that can be fed into external fine-tuning tools like the OpenAI API, HuggingFace, or Unsloth. It generates four types of training pairs: negative corrections (showing the model what it should have said instead of a blocked claim), positive verified (reinforcing correct answers backed by tools), positive hedged (teaching the model to express uncertainty when appropriate), and positive cited (rewarding responses that include sources). Over time, the model internalizes these patterns and begins preferring truthful, hedged responses over confident guesses — reducing its dependence on TruthGuard to catch it.

- **Consolidation**: The previous architecture had a separate SovereignShieldFull wrapper package that combined components from both IntentShield and SovereignShield. This created maintenance overhead and confusion about which package to use. In v1.2.0, all components were consolidated into a single SovereignShield package. SovereignShieldFull was deleted entirely. The result is one package, 8 components, zero redundancy. All 181 tests pass across all suites.

### v1.0.4 (March 2026 — Security Patch)

- Fixed Unicode homoglyph bypass (Greek/Cyrillic lookalikes now fold to Latin).
- Fixed Base64/encoded payload bypass (improved entropy + signature detection).
- Fixed Firewall instant re-block after block expiry (stale timestamp cleanup).
- Fixed IntentShield version mismatch (`__init__.py` vs `setup.py`).

### v1.0.3 (March 2026)

- 4-layer security: Firewall, InputFilter, Conscience, CoreSafety.
- SHA-256 hash-sealed integrity (tamper = instant kill).
- FrozenNamespace immutable security constants.
- 50+ prompt injection keywords blocked.
- Configurable rate limiter (`rate_limit_interval` parameter).
- Zero dependencies, pure Python stdlib.

### Adaptive Security Plugin v1.0.0 (March 2026)

- Standalone self-improving security filter (`pip install sovereign-shield-adaptive`).
- Report missed attacks, auto-generate rules, sandbox test, deploy.
- Auto-deploy and manual review modes.
- SQLite persistence, rule approval workflow.

---

## Coming Soon

### SaaS API

Already built and tested (16 tests passing). Scan any input, output, or action through a REST endpoint. Sub-millisecond latency, API key auth with tier-based rate limiting (Free/Pro/Enterprise).

### VS Code Extension

> *"Your AI writes code. Who checks it before it runs?"*

Scans AI-generated code suggestions (Copilot, Cursor, ChatGPT) before they hit your codebase. Catches hidden shell commands, malicious imports, credential leaks, and verifies code correctness and safety.

---

## Planned

- **LangChain / LlamaIndex Plugin**: One-line middleware for agent frameworks.
- **Compliance Dashboard**: Real-time attack visualization, PDF reports, alerts.
- **Browser Extension**: Phishing and social engineering detection for chat interfaces.
- **SDK Wrappers**: Node.js, Go, Rust clients.
- **Docker Sidecar**: Drop-in security proxy for containerized services.

---

## Want Something?

Open an [issue](https://github.com/mattijsmoens/sovereign-shield/issues) or reach out to suggest features.

---

<div align="center">

Built by [Mattijs Moens](https://github.com/mattijsmoens)

</div>
