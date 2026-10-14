# API notes

Interactive OpenAPI docs: `http://127.0.0.1:8000/docs`. All routes are under `/api`. Lists return `{items,total,page,page_size}` (`page_size` ≤ 200). Errors return `{"detail": "..."}` (422 validation, 404, 409, 413, 503, generic 500).

| Method & path | Purpose |
|---|---|
| GET `/health`, `/system/info`, `/ai/status` | health, config summary, AI provider availability |
| GET `/ingest/samples` · POST `/ingest/sample/{id}` | list/load built-in datasets (allow-listed ids) |
| POST `/ingest/upload` (multipart `file`) · GET `/ingest/batches` | import logs, history |
| GET `/events`, `/events/{id}` | filters: q, source_ip, destination_ip, username, event_type, status, source, start, end; sort, order |
| GET `/dashboard/metrics?start&end` | all dashboard data |
| POST `/detection/run` `{use_ml, clear_existing, contamination}` · GET `/detection/runs` | run pipeline |
| GET/PUT `/detection/config` · POST `/detection/config/reset` · GET `/detection/rules` · GET `/mitre/mappings` | configuration, docs |
| GET `/alerts` (q, severity[], status[], detection_source, rule_id, sort, order) · GET/PATCH `/alerts/{id}` | alert management |
| POST/GET `/incidents` · GET/PATCH `/incidents/{id}` · POST `/incidents/{id}/alerts` · POST `/incidents/{id}/notes` | incidents |
| POST `/incidents/{id}/analysis` `{provider}` | AI-assisted analysis (`auto`/`fallback`/`ollama`) |
| POST `/incidents/{id}/reports` · GET `/reports` · GET `/reports/{id}` · GET `/reports/{id}/download?format=markdown\|json` | reports |
