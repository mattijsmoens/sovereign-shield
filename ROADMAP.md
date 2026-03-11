# 🗺️ Roadmap

What's built, what's next, and where we're heading.

---

## ✅ Shipped

### v1.0.4 (March 2026 — Security Patch)
- Fixed Unicode homoglyph bypass (Greek/Cyrillic lookalikes now fold to Latin)
- Fixed Base64/encoded payload bypass (improved entropy + signature detection)
- Fixed Firewall instant re-block after block expiry (stale timestamp cleanup)
- Fixed IntentShield version mismatch (__init__.py vs setup.py)

### v1.0.3 (March 2026)
- 4-layer security: Firewall → InputFilter → Conscience → CoreSafety
- SHA-256 hash-sealed integrity (tamper = instant kill)
- FrozenNamespace immutable security constants
- 50+ prompt injection keywords blocked
- Configurable rate limiter (`rate_limit_interval` parameter)
- Zero dependencies, pure Python stdlib

### Adaptive Security Plugin v1.0.0 (March 2026)

- Standalone self-improving security filter (`pip install sovereign-shield-adaptive`)
- Report missed attacks → auto-generate rules → sandbox test → deploy
- Auto-deploy and manual review modes
- SQLite persistence, rule approval workflow

---

## 🚀 Coming Soon

### SaaS API
Scan any input, output, or action through our REST API. Sub-millisecond latency, API key auth with tier-based rate limiting (Free/Pro/Enterprise). Full scan endpoints for input, action, and output filtering.

### 🖥️ VS Code Extension
> *"Your AI writes code. Who checks it before it runs?"*

Scans AI-generated code suggestions (Copilot, Cursor, ChatGPT) **before** they hit your codebase. Catches hidden shell commands, malicious imports, credential leaks, and verifies code correctness and safety.

---

## 📋 Planned

- **LangChain / LlamaIndex Plugin**: One-line middleware for agent frameworks
- **Compliance Dashboard**: Real-time attack visualization, PDF reports, alerts
- **Browser Extension**: Phishing and social engineering detection for chat interfaces
- **SDK Wrappers**: Node.js, Go, Rust clients
- **Docker Sidecar**: Drop-in security proxy for containerized services

---

## 📣 Want Something?

Open an [issue](https://github.com/mattijsmoens/sovereign-shield/issues) or reach out to suggest features.

---

<div align="center">

Built by [Mattijs Moens](https://github.com/mattijsmoens)

</div>
