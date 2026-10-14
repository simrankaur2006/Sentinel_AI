# SentinelAI — AI-Powered SOC Copilot

*Intelligent security log analysis, anomaly detection and incident investigation.*

SentinelAI ingests security logs, normalizes them, detects suspicious activity with **explainable rules** and an **Isolation Forest**, prioritizes alerts, maps findings to **MITRE ATT&CK** (as hypotheses), and generates evidence-based incident reports. It runs fully locally: no paid API, no cloud, and an optional local LLM (Ollama) with a deterministic fallback that works with no model at all.

> **Status honesty.** See [Verification status](#verification-status) for exactly what was and was not executed when this project was generated. No screenshots, benchmarks or accuracy figures are claimed.

## Problem statement
Analysts drown in raw logs. SentinelAI shows how a small SOC tool can turn logs into prioritized, evidence-backed leads with clear limitations, while staying defensible in an interview: every alert states why it fired, what evidence supports it, and what it cannot prove.

## Key features
CSV/JSON/JSONL ingestion with alias mapping, validation, limits and duplicate handling · 8 configurable detection rules incl. correlation · Isolation Forest with reproducible seed and per-alert feature explanations · alert filtering/search/sort/status workflow · incident workspace with timeline, notes, MITRE table · AI-assisted analysis (fallback or local Ollama) with fact/hypothesis separation and anti-hallucination checks · Markdown/JSON reports · dashboard computed from the database · 9 UI views.

## Technology stack
React 18 + Vite + Recharts (JavaScript) · Python, FastAPI, Pydantic v2, SQLAlchemy 2 · PostgreSQL (psycopg 3) · scikit-learn, pandas, NumPy · pytest · Vitest + React Testing Library.

## Architecture
See [docs/architecture.md](docs/architecture.md) (Mermaid diagram). Data flow: *upload → parse/normalize → store (deduplicated) → detection run (rules → correlation → ML) → alerts with evidence links → incident → analysis (fallback/Ollama) → report*.

## Detection pipeline: rules vs ML
Rules are deterministic, threshold-driven and explain themselves; they catch known patterns but miss anything below thresholds. The Isolation Forest is unsupervised: it ranks events that are statistically unusual *within the uploaded data*, can surface the unknown, but also flags rare-but-benign activity. ML alerts are labelled separately, never exceed Medium severity, carry no MITRE mapping, and are skipped (with a reason) when there are too few events. Details: [docs/detection-rules.md](docs/detection-rules.md).

## AI provider and fallback
`AI_PROVIDER=fallback` (default) uses deterministic templates grounded in stored alerts. `ollama` (or choosing it in the UI) calls a **local** model; if unreachable, slow or returning invalid output, the API returns the deterministic analysis and says so (`fallback_reason`). Model output is validated: unknown alert/event references are removed, IPs not in the evidence are flagged, MITRE data always comes from the mapping file, and logs are passed as untrusted data. Analysis is always labelled advisory.

## Database schema overview
`ingestion_batches` → `security_events` (unique fingerprint, indexed timestamp/IP/user/type) · `alerts` (unique fingerprint; severity/status CHECK constraints; JSON evidence metadata) · `alert_events` (many-to-many evidence) · `incidents` + `incident_alerts` + `incident_notes` · `reports` · `detection_runs` · `detection_config`. Tables are created by `python -m scripts.init_db` (SQLAlchemy `create_all`). Alembic migrations are **not included** in v1.

## MITRE ATT&CK approach
Small, well-supported set in `backend/app/mitre/mappings.json` with rationale and relation (`behavior_consistent` / `potential_association`). Some detections deliberately have no mapping. References: https://attack.mitre.org/

## Prerequisites
Python 3.11–3.12, Node.js 18+ (20+ recommended), PostgreSQL 14+. Optional: [Ollama](https://ollama.com) for local LLM analysis.

## Installation

### 1. PostgreSQL (once)
Windows (PowerShell, using the `psql` that ships with the PostgreSQL installer):
```powershell
psql -U postgres -c "CREATE USER sentinel WITH PASSWORD 'choose-a-password';"
psql -U postgres -c "CREATE DATABASE sentinelai OWNER sentinel;"
```
Linux/macOS:
```bash
sudo -u postgres psql -c "CREATE USER sentinel WITH PASSWORD 'choose-a-password';"
sudo -u postgres psql -c "CREATE DATABASE sentinelai OWNER sentinel;"
```

### 2. Backend
Windows PowerShell:
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env      # then edit DATABASE_URL (use your password)
python -m scripts.init_db        # create tables
python -m scripts.seed_demo      # optional: load sample data, run detection, create a demo incident
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Linux/macOS: `python3 -m venv .venv && source .venv/bin/activate`, `cp .env.example .env`, then the same `pip`/`python -m`/`uvicorn` commands. API docs: http://127.0.0.1:8000/docs

### 3. Frontend (second terminal)
```powershell
cd frontend
npm install
Copy-Item .env.example .env      # Linux/macOS: cp .env.example .env
npm run dev                      # http://127.0.0.1:5173
```

### Environment configuration
See `backend/.env.example` (copy of root `.env.example`) and `frontend/.env.example`. Never commit `.env`.

### Resetting the demo database
`python -m scripts.reset_demo_db --yes` drops and recreates all tables. It refuses non-local databases.

## Using the app
1. **Load data** — *Log ingestion* → load a sample dataset or upload CSV/JSON/JSONL (≤10 MB, ≤50,000 rows by default). Re-uploading the same events is detected as duplicates.
2. **Run detection** — *Alerts* → **Run detection**. Tune thresholds/ML sensitivity in *Detection settings* and re-run (optionally clearing untouched New alerts).
3. **Investigate** — filter/search alerts, open one to see why it fired, limitations, MITRE table and evidence events; set status (New / Investigating / Resolved / False Positive).
4. **Incident** — select alerts → *Create incident*; review the timeline, affected assets, guidance and notes.
5. **Report** — on the incident, choose a provider and *Analyse incident* / *Generate report*; download Markdown or JSON from *Reports*.

### Sample demonstration workflow (≈5 minutes)
Load *Synthetic security logs* → Run detection → open the **Critical** correlated alert for `admin` → tick it together with the other `admin` alerts in the list and choose *Create incident* (or open an alert and use *Add to existing incident*) → read the timeline → Analyse (fallback) → add a note → Generate report → download Markdown. Compare with `reports/sample-incident-report.md`. Which sample records trigger which rules: [backend/sample_data/README.md](backend/sample_data/README.md).

## Running tests
```powershell
cd backend ; pip install -r requirements-dev.txt ; pytest          # unit + API tests (API tests use in-memory SQLite)
cd ../frontend ; npm test ; npm run build
```
Backend API tests use SQLite purely as a documented test strategy; the application targets PostgreSQL.

## Verification status
Actually executed while generating this project (sandbox without network access):
- Backend core (parser, rules, correlation, Isolation Forest, MITRE data, AI fallback + Ollama provider logic with a fake transport, report generation, sample-data expectations): **71 tests passed**, run with a minimal stand-in for pytest because pytest could not be installed. They are written for pytest.
- `py_compile` of every backend module; `esbuild` parse + import-resolution of the whole frontend, including tests; a script confirming all 28 frontend API calls map to implemented backend routes.

**NOT executed (could not install the packages offline):** FastAPI/SQLAlchemy layer, `backend/tests/test_api.py`, PostgreSQL integration, `npm install/build/test`, Vitest tests, Ollama integration against a real model. Expect to fix small integration issues on first run; please report/fix them. No `package-lock.json` could be generated offline; run `npm install` to create one. Python versions are pinned in `requirements.txt` but not hash-locked.

## Security limitations
Local demo mode has **no authentication** — bind to 127.0.0.1 and use synthetic/authorised data. No role-based access, audit log, or TLS. Detections are leads, not proof; ML scores are relative; MITRE links are hypotheses. See [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).

## Known limitations / not implemented
Authentication, Alembic migrations, PDF export, removing alerts from an incident, live log streaming, long-term behavioral baselines, labelled-data evaluation of the ML model, Windows-specific event parsing beyond codes 4624/4625.

## Future enhancements
Authentication + RBAC, Alembic, Sigma rule import, labelled benchmark datasets with honest metrics, threat-intel enrichment, PDF reports, background job queue for large analyses.

## Screenshots
None are included (none were captured). To add genuine ones: run the demo workflow, capture the Dashboard, Alerts, an incident timeline and a report, save to `docs/screenshots/`, and link them here.

## Troubleshooting
See [docs/troubleshooting.md](docs/troubleshooting.md). Other docs: [API notes](docs/api.md), [detection rules](docs/detection-rules.md), [threat model](docs/threat-model.md).

## License
MIT — see [LICENSE](LICENSE).
