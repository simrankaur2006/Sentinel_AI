import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, reportDownloadUrl } from "../api/client";
import { useAsync } from "../api/useAsync";
import { AlertTable, ErrorBanner, INCIDENT_STATUSES, Loading, MitreTable, Notice, SEVERITIES, SeverityBadge, StatusBadge, fmtTime } from "../components/ui";

function Analysis({ a }) {
  const fallback = a.generator === "deterministic-fallback";
  return (
    <div>
      <div className="banner warn"><strong>Advisory only.</strong> {a.advisory_notice}</div>
      <p><span className="tag">Generator: {a.generator}</span> {fallback && <span className="muted small">Fixed templates, no language model was used.</span>}</p>
      {a.fallback_reason && <Notice kind="warn">{a.fallback_reason}</Notice>}
      {a.warnings.map((w) => <Notice key={w} kind="warn">{w}</Notice>)}
      <p>{a.summary}</p>
      <h3>Observed facts</h3><ul>{a.observed_facts.map((f, i) => <li key={i}>{f.text} <span className="mono muted">[{(f.refs || []).slice(0, 6).join(", ")}]</span></li>)}</ul>
      <h3>Hypotheses (not established facts)</h3><ul>{a.hypotheses.map((h, i) => <li key={i}>{h.text} <span className="mono muted">[{(h.refs || []).join(", ")}]</span></li>)}</ul>
      <h3>Investigation steps</h3><ol>{a.investigation_steps.map((s) => <li key={s}>{s}</li>)}</ol>
      <h3>Containment considerations</h3>
      {a.containment.length ? <ul>{a.containment.map((c, i) => <li key={i}>{c.action} <span className="muted small">Reason: {c.justification}</span></li>)}</ul> : <p className="muted">None justified by the current evidence.</p>}
      <h3>Missing evidence</h3><ul>{a.missing_evidence.map((m) => <li key={m}>{m}</li>)}</ul>
    </div>
  );
}

export default function IncidentDetail() {
  const { id } = useParams();
  const { data: inc, error, loading, reload } = useAsync(() => api.incident(id), [id]);
  const [actionError, setActionError] = useState(null);
  const [note, setNote] = useState({ author: "analyst", body: "" });
  const [provider, setProvider] = useState("auto");
  const [analysis, setAnalysis] = useState(null);
  const [report, setReport] = useState(null);
  const [busy, setBusy] = useState("");

  async function act(label, fn) {
    setBusy(label); setActionError(null);
    try { return await fn(); } catch (e) { setActionError(e); return null; } finally { setBusy(""); }
  }
  const update = (body) => act("update", async () => { await api.updateIncident(id, body); reload(); });
  const addNote = async (e) => {
    e.preventDefault();
    const ok = await act("note", async () => { await api.addNote(id, note); return true; });
    if (ok) { setNote({ ...note, body: "" }); reload(); }
  };
  const analyze = async () => { const r = await act("analyze", () => api.analyze(id, provider)); if (r) setAnalysis(r); };
  const makeReport = async () => { const r = await act("report", () => api.createReport(id, { provider, include_analysis: true })); if (r) setReport(r); };

  if (loading && !inc) return <Loading what="incident" />;
  if (error) return <ErrorBanner error={error} onRetry={reload} />;
  const sevOf = Object.fromEntries(inc.alerts.map((a) => [a.ref, a.severity]));
  return (
    <>
      <p className="small"><Link to="/incidents">← All incidents</Link></p>
      <div className="page-head">
        <div><h1>{inc.title}</h1><p><span className="mono">{inc.ref}</span> · opened {fmtTime(inc.created_at)}</p></div>
        <div className="row">
          <SeverityBadge value={inc.severity} /><StatusBadge value={inc.status} />
          <label>Status<select value={inc.status} disabled={!!busy} onChange={(e) => update({ status: e.target.value })}>{INCIDENT_STATUSES.map((s) => <option key={s}>{s}</option>)}</select></label>
          <label>Severity<select value={inc.severity} disabled={!!busy} onChange={(e) => update({ severity: e.target.value })}>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select></label>
        </div>
      </div>
      <ErrorBanner error={actionError} />
      {inc.description && <p className="muted">{inc.description}</p>}
      <div className="grid g2">
        <div className="panel"><h2>Affected assets</h2>
          <dl className="kv"><dt>Users</dt><dd>{inc.affected.users.join(", ") || "–"}</dd><dt>IP addresses</dt><dd className="mono">{inc.affected.ips.join(", ") || "–"}</dd><dt>Log sources</dt><dd>{inc.affected.hosts.join(", ") || "–"}</dd></dl></div>
        <div className="panel"><h2>Investigation guidance</h2>
          {inc.guidance.length ? <ul>{inc.guidance.map((g) => <li key={g}>{g}</li>)}</ul> : <p className="muted">Link alerts to get guidance.</p>}</div>
      </div>
      <div className="panel"><h2>Related alerts ({inc.alerts.length})</h2>
        {inc.alerts.length ? <AlertTable alerts={inc.alerts} /> : <p className="muted">No alerts linked. Select alerts on the Alerts page and create an incident from them.</p>}</div>
      <div className="panel"><h2>Timeline (UTC)</h2>
        {inc.timeline.length === 0 ? <p className="muted">No events yet.</p> : (
          <ol className="timeline" style={{ listStyle: "none" }}>
            {inc.timeline.map((e) => {
              const owner = inc.alerts.find((a) => a.event_refs.includes(e.ref));
              return (
                <li key={e.id} className={owner ? `tl-${sevOf[owner.ref]}` : ""}>
                  <time>{fmtTime(e.timestamp)}</time> <span className="mono">{e.ref}</span>{" "}
                  {[e.event_type, e.action, e.status].filter(Boolean).join(" / ")}{" "}
                  <span className="muted">{[e.username && `user ${e.username}`, e.source_ip && `from ${e.source_ip}`, e.destination_ip && `to ${e.destination_ip}${e.port != null ? ":" + e.port : ""}`].filter(Boolean).join(" ")}</span>
                  {owner && <> <Link to={`/alerts/${owner.id}`} className="small">{owner.ref}</Link></>}
                </li>
              );
            })}
          </ol>
        )}</div>
      <div className="panel"><h2>MITRE ATT&amp;CK</h2><MitreTable items={inc.mitre} /></div>
      <div className="grid g2">
        <div className="panel"><h2>Analyst notes</h2>
          {inc.notes.length === 0 && <p className="muted">No notes yet.</p>}
          <ul className="plain">{inc.notes.map((n) => <li key={n.id}><strong>{n.author}</strong> <span className="muted small">{fmtTime(n.created_at)}</span><div style={{ whiteSpace: "pre-wrap" }}>{n.body}</div></li>)}</ul>
          <form onSubmit={addNote} style={{ marginTop: ".8rem" }}>
            <label>Author<input type="text" required maxLength={100} value={note.author} onChange={(e) => setNote({ ...note, author: e.target.value })} /></label>
            <label>New note<textarea required maxLength={5000} value={note.body} onChange={(e) => setNote({ ...note, body: e.target.value })} /></label>
            <button type="submit" disabled={busy === "note"}>Add note</button>
          </form></div>
        <div className="panel"><h2>AI-assisted analysis and report</h2>
          <div className="row">
            <label>Provider<select value={provider} onChange={(e) => setProvider(e.target.value)}>
              <option value="auto">Default (from server settings)</option><option value="fallback">Deterministic fallback</option><option value="ollama">Local model (Ollama)</option></select></label>
            <button disabled={!!busy} onClick={analyze}>{busy === "analyze" ? "Analysing…" : "Analyse incident"}</button>
            <button className="ghost" disabled={!!busy} onClick={makeReport}>{busy === "report" ? "Generating…" : "Generate report"}</button>
          </div>
          {report && (<Notice kind="ok">Report #{report.id} created (generator: {report.generator}).{" "}
            <a href={reportDownloadUrl(report.id, "markdown")}>Download Markdown</a> · <a href={reportDownloadUrl(report.id, "json")}>Download JSON</a> · <Link to="/reports">All reports</Link></Notice>)}
          {analysis && <Analysis a={analysis} />}
        </div>
      </div>
    </>
  );
}
