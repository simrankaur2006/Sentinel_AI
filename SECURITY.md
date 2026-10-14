# Security policy

SentinelAI is a **defensive, educational** project intended for authorised lab use with synthetic or data you are permitted to analyse.

## Reporting a vulnerability
Open a private security advisory on the repository (GitHub: *Security → Report a vulnerability*) or contact the maintainer privately. Please include steps to reproduce and the affected version. Do not publish exploit details before a fix is available.

## Scope and assumptions
- **Local demo mode has no authentication.** Run the API on `127.0.0.1` only. Do not expose it to a network or the internet.
- Uploaded logs are untrusted input: they are parsed as data (never executed), size/row limited, and rendered through React's escaping and sanitized Markdown.
- No real credentials belong in the repository. `.env` is git-ignored; only `.env.example` with placeholders is committed.
- The optional LLM runs locally; remote endpoints are refused unless `OLLAMA_ALLOW_REMOTE=true`.
See `docs/threat-model.md` for details and known gaps.
