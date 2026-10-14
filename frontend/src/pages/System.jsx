import { api, API_BASE } from "../api/client";
import { useAsync } from "../api/useAsync";
import { ErrorBanner, Loading, Notice } from "../components/ui";

export default function System() {
  const health = useAsync(() => api.health(), []);
  const info = useAsync(() => api.systemInfo(), []);
  const ai = useAsync(() => api.aiStatus(), []);
  const o = ai.data?.ollama;
  return (
    <>
      <div className="page-head"><div><h1>System</h1><p>Health, configuration and known limitations.</p></div></div>
      <ErrorBanner error={health.error} onRetry={health.reload} />
      <div className="grid g2">
        <div className="panel"><h2>Backend health</h2>{health.loading && <Loading what="health" />}
          {health.data && (<dl className="kv"><dt>API</dt><dd>{API_BASE}</dd><dt>Status</dt><dd>{health.data.status}</dd><dt>Database</dt><dd>{health.data.database}{health.data.detail ? ` — ${health.data.detail}` : ""}</dd><dt>Version</dt><dd>{health.data.version}</dd></dl>)}</div>
        <div className="panel"><h2>Configuration</h2>{info.loading && <Loading what="info" />}<ErrorBanner error={info.error} onRetry={info.reload} />
          {info.data && (<dl className="kv"><dt>Mode</dt><dd>{info.data.mode}</dd><dt>Database</dt><dd>{info.data.database_dialect}</dd><dt>Stored events</dt><dd>{info.data.counts.events}</dd>
            <dt>Upload limit</dt><dd>{(info.data.limits.max_upload_bytes / 1048576).toFixed(0)} MB, {info.data.limits.max_upload_rows} rows</dd><dt>Allowed origins</dt><dd>{info.data.cors_origins.join(", ")}</dd></dl>)}</div>
        <div className="panel"><h2>AI analysis providers</h2>{ai.loading && <Loading what="AI status" />}<ErrorBanner error={ai.error} onRetry={ai.reload} />
          {ai.data && (<>
            <dl className="kv"><dt>Default provider</dt><dd>{ai.data.default_provider}</dd><dt>Deterministic fallback</dt><dd>always available</dd>
              <dt>Local model (Ollama)</dt><dd>{o.reachable ? (o.model_available ? `reachable, model ${o.model} available` : `reachable, but model ${o.model} is not installed`) : `not reachable${o.error ? ` (${o.error})` : ""}`}</dd></dl>
            <p className="small muted">No logs are sent anywhere unless you choose the local model, and only to a local address. Core features work without it.</p></>)}</div>
        <div className="panel"><h2>Known limitations</h2>
          {info.data && <ul>{info.data.limitations.map((l) => <li key={l}>{l}</li>)}</ul>}
          <Notice kind="info">No screenshots, benchmarks or accuracy figures are claimed by this project.</Notice></div>
      </div>
    </>
  );
}
