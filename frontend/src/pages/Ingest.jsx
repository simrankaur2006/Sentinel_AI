import { useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useAsync } from "../api/useAsync";
import { ErrorBanner, Loading, Notice, fmtTime } from "../components/ui";

function Result({ r }) {
  return (
    <Notice kind={r.rows_imported > 0 ? "ok" : "info"}>
      <strong>{r.filename}</strong>: {r.rows_imported} imported, {r.rows_duplicate} duplicate(s) skipped, {r.rows_invalid} invalid of {r.rows_total} rows
      {r.warnings ? `, ${r.warnings} field warning(s)` : ""}. {r.errors.length > 0 && (
        <details><summary>First problems</summary><ul>{r.errors.slice(0, 10).map((e, i) => <li key={i}>Row {e.row}: {e.message}</li>)}</ul></details>)}
      {" "}<Link to="/alerts">Run detection</Link>
    </Notice>
  );
}

export default function Ingest() {
  const samples = useAsync(() => api.samples(), []);
  const batches = useAsync(() => api.batches(), []);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const fileRef = useRef(null);

  async function act(fn) {
    setBusy(true); setError(null); setResult(null);
    try { setResult(await fn()); batches.reload(); } catch (e) { setError(e); } finally { setBusy(false); }
  }
  const onUpload = (ev) => {
    ev.preventDefault();
    const f = fileRef.current?.files?.[0];
    if (!f) { setError({ status: 400, message: "Choose a CSV, JSON or JSONL file first." }); return; }
    act(() => api.upload(f));
  };

  return (
    <>
      <div className="page-head"><div><h1>Log ingestion</h1><p>Import CSV, JSON or JSON Lines logs. Fields are mapped to a canonical schema; re-importing the same events is safe.</p></div></div>
      <ErrorBanner error={error} />
      {result && <Result r={result} />}
      <div className="grid g2">
        <form className="panel" onSubmit={onUpload}>
          <h2>Upload a file</h2>
          <label>Log file (.csv, .json, .jsonl)<input ref={fileRef} type="file" accept=".csv,.json,.jsonl,.ndjson" /></label>
          <p className="small muted">Required per row: a parseable timestamp plus at least one of event type, action, status or message. Timestamps without a zone are treated as UTC. Files are parsed as data only; nothing is executed.</p>
          <button type="submit" disabled={busy}>{busy ? "Importing…" : "Import file"}</button>
        </form>
        <div className="panel">
          <h2>Synthetic sample data</h2>
          {samples.loading && <Loading what="samples" />}<ErrorBanner error={samples.error} onRetry={samples.reload} />
          <ul className="plain">
            {(samples.data || []).map((s) => (
              <li key={s.id}><strong>{s.title}</strong><div className="small muted">{s.description}</div>
                <button className="ghost" disabled={busy} onClick={() => act(() => api.loadSample(s.id))}>Load this dataset</button></li>
            ))}
          </ul>
        </div>
      </div>
      <div className="panel">
        <h2>Import history</h2>
        {batches.loading && !batches.data && <Loading what="history" />}<ErrorBanner error={batches.error} onRetry={batches.reload} />
        {batches.data && batches.data.length === 0 && <p className="muted">Nothing imported yet.</p>}
        {batches.data && batches.data.length > 0 && (
          <div className="table-wrap"><table>
            <thead><tr><th>When (UTC)</th><th>File</th><th>Format</th><th>Rows</th><th>Imported</th><th>Duplicates</th><th>Invalid</th></tr></thead>
            <tbody>{batches.data.map((b) => (<tr key={b.id}><td className="mono">{fmtTime(b.created_at)}</td><td>{b.filename}</td><td>{b.file_format}</td><td>{b.rows_total}</td><td>{b.rows_imported}</td><td>{b.rows_duplicate}</td><td>{b.rows_invalid}</td></tr>))}</tbody>
          </table></div>
        )}
      </div>
    </>
  );
}
