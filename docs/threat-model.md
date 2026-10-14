# Threat model (local demo)

**Assets:** uploaded logs, alerts, analyst notes, reports. **Trust boundary:** the browser ↔ API on localhost; the API ↔ optional local model.

| Threat | Mitigation | Residual risk |
|---|---|---|
| Malicious upload (oversized, binary, malformed) | Extension allow-list, byte and row limits (read capped at limit+1), strict UTF-8, csv/json parsing only | Large allowed files use memory up to the limit |
| Formula/HTML/script injection in log fields | Stored as inert text; React escapes on render; report Markdown escapes `\|`, backticks, `<`, `>` and control chars | Opening a downloaded `.md`/`.json` in other tools is outside SentinelAI's control |
| SQL injection | SQLAlchemy ORM / bound parameters; sort columns allow-listed; LIKE wildcards escaped | – |
| Path traversal | Sample datasets selected by allow-listed ID only; upload filename is never used as a path | – |
| Prompt injection via logs | System prompt declares logs untrusted; logs passed as a JSON data block; control chars stripped; instruction-like text flagged; output validated; unknown alert/event refs removed; IPs not in evidence flagged; MITRE never taken from the model | LLMs can still be misled; output is advisory and labelled |
| Data exfiltration to external AI | Default provider is deterministic; Ollama endpoint must be local unless `OLLAMA_ALLOW_REMOTE=true`; prompt size bounded | User can opt in to remote at their own risk |
| Unauthorised access | **None implemented** (local demo). CORS restricted to configured origins | Anyone who can reach the port can read/modify data. Bind to 127.0.0.1 |
| Information leakage in errors | Generic 500/503 messages; stack traces only in server logs | Server logs may contain data; protect them |
| Secrets in repo | `.env` ignored; placeholders only | Users must choose their own DB password |
