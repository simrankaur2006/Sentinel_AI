# Contributing

1. Fork, create a branch, make focused changes.
2. Backend: `cd backend && pip install -r requirements-dev.txt && pytest`. Frontend: `cd frontend && npm install && npm test && npm run build`.
3. New detection rules must: use only canonical `Event` fields, be configurable via `DetectionConfig`, attach evidence, document limitations in `RULE_CATALOG`, skip safely when fields are missing, and ship unit tests (including a non-triggering case).
4. New MITRE mappings go in `backend/app/mitre/mappings.json` with a rationale and an honest relation (`behavior_consistent` or `potential_association`). Prefer fewer, well-supported mappings.
5. Use only synthetic data in tests and examples. Never commit secrets or real logs.
6. Do not add offensive capabilities (exploitation, scanning, credential theft).
