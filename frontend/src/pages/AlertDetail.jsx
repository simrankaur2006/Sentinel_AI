import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import { useAsync } from "../api/useAsync";
import { ALERT_STATUSES, ErrorBanner, EventTable, Loading, MitreTable, SeverityBadge, SourceTag, StatusBadge, confidenceLabel, fmtTime } from "../components/ui";

export default function AlertDetail() {
  const { id } = useParams();
  const nav = useNavigate();
  const { data: a, error, loading, reload } = useAsync(() => api.alert(id), [id]);
  const [actionError, setActionError] = useState(null);
  const [busy, setBusy] = useState(false);
  const incidents = useAsync(() => api.incidents({ page: 1, page_size: 100 }), []);
  const [target, setTarget] = useState("");

  async function setStatus(status) {
    setBusy(true); setActionError(null);
    try { await api.updateAlert(id, status); reload(); } catch (e) { setActionError(e); } finally { setBusy(false); }
  }
  async function toIncident() {
    setBusy(true); setActionError(null);
    try { const inc = await api.createIncident({ title: `Investigate: ${a.title}`.slice(0, 200), alert_ids: [a.id] }); nav(`/incidents/${inc.id}`); }
    catch (e) { setActionError(e); setBusy(false); }
  }

  async function addToIncident() {
    if (!target) return;
    setBusy(true); setActionError(null);
    try { await api.addAlerts(target, [a.id]); nav(`/incidents/${target}`); } catch (e) { setActionError(e); setBusy(false); }
  }

  if (loading && !a) return <Loading what="alert" />;
  if (error) return <ErrorBanner error={error} onRetry={reload} />;
  return (
    <>
      <p className="small"><Link to="/alerts">← All alerts</Link></p>
      <div className="page-head">
        <div><h1>{a.title}</h1><p><span className="mono">{a.ref}</span> · <SourceTag value={a.detection_source} /> <span className="mono">{a.rule_id}</span></p></div>
        <div className="row">
          <SeverityBadge value={a.severity} /><StatusBadge value={a.status} />
          <label>Status<select value={a.status} disabled={busy} onChange={(e) => setStatus(e.target.value)}>{ALERT_STATUSES.map((s) => <option key={s}>{s}</option>)}</select></label>
          <button className="ghost" disabled={busy} onClick={toIncident}>Open new incident</button>
          {incidents.data && incidents.data.items.length > 0 && (
            <>
              <label>Add to existing incident<select value={target} onChange={(e) => setTarget(e.target.value)}>
                <option value="">Choose…</option>{incidents.data.items.map((i) => <option key={i.id} value={i.id}>{i.ref} {i.title}</option>)}</select></label>
              <button className="ghost" disabled={busy || !target} onClick={addToIncident}>Add</button>
            </>
          )}
        </div>
      </div>
      <ErrorBanner error={actionError} />
      <div className="grid g2">
        <div className="panel"><h2>What was detected</h2><p>{a.description}</p>
          <dl className="kv">
            <dt>First seen</dt><dd className="mono">{fmtTime(a.first_seen)}</dd><dt>Last seen</dt><dd className="mono">{fmtTime(a.last_seen)}</dd>
            <dt>Users</dt><dd>{a.usernames.join(", ") || "–"}</dd><dt>IP addresses</dt><dd className="mono">{a.ips.join(", ") || "–"}</dd><dt>Log source</dt><dd>{a.host || "–"}</dd>
            <dt>Indicator</dt><dd>{a.confidence.toFixed(2)} <span className="muted small">— {confidenceLabel(a.confidence_kind)}</span></dd>
            <dt>Evidence</dt><dd>{a.evidence_total} event(s)</dd>
            <dt>Incidents</dt><dd>{a.incident_ids.length ? a.incident_ids.map((i) => <Link key={i} to={`/incidents/${i}`}>INC-{String(i).padStart(4, "0")} </Link>) : "None"}</dd>
          </dl></div>
        <div className="panel"><h2>Why it was flagged</h2><p>{a.explanation}</p>
          <h3>Limitations</h3><p className="muted">{a.limitations}</p>
          {a.details.reasons?.length > 0 && (<><h3>Model: most unusual features</h3><ul className="plain">{a.details.reasons.map((r) => <li key={r.feature}>{r.label} <span className="muted small">· {r.deviation} robust SDs from typical</span></li>)}</ul></>)}</div>
      </div>
      <div className="panel"><h2>Recommended investigation steps</h2><ol>{a.recommended_steps.map((s) => <li key={s}>{s}</li>)}</ol></div>
      <div className="panel"><h2>MITRE ATT&amp;CK</h2><MitreTable items={a.mitre} />
        <p className="small muted">Associations are hypotheses. “Behavior consistent” means the logs match the technique’s pattern, not that an adversary used it.</p></div>
      <div className="panel"><h2>Supporting events</h2><EventTable events={a.events} />
        {a.evidence_total > a.events.length && <p className="small muted">Showing {a.events.length} of {a.evidence_total} events.</p>}</div>
    </>
  );
}
