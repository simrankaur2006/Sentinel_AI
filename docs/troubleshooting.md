# Troubleshooting

| Symptom | Fix |
|---|---|
| `Configuration error: DATABASE_URL is not set` | Copy `backend/.env.example` to `backend/.env` and set `DATABASE_URL`. |
| API returns 503 "Database unavailable" | Start PostgreSQL; check host/port/user/password/db in `DATABASE_URL`; run `python -m scripts.init_db`. |
| `psycopg.OperationalError: password authentication failed` | The password in `.env` must match the one set with `CREATE USER`. |
| UI banner "Cannot reach the SentinelAI API" | Start the backend; `VITE_API_BASE_URL` in `frontend/.env` must match it. |
| Browser CORS error | Add the frontend origin to `CORS_ORIGINS` (comma separated) and restart the backend. |
| Upload rejected 422 | Read the message: unsupported extension, not UTF-8, no valid rows, or missing timestamp. |
| 413 on upload | Raise `MAX_UPLOAD_MB`, or split the file. |
| "ML skipped: only N events" | Rules still ran. ML needs `ml_min_events` (default 50) events. |
| No alerts after loading data | Click **Run detection** (ingestion does not run it automatically). |
| Ollama analysis falls back | The report says why (`fallback_reason`). Start `ollama serve`, `ollama pull <model>`, check System page. |
| PowerShell blocks venv activation | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` then activate again. |
| `pip` fails building numpy/pandas on a new Python | Use Python 3.11 or 3.12 (tested range) and upgrade pip. |
