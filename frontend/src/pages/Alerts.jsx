import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useAsync } from "../api/useAsync";
import { ALERT_STATUSES, AlertTable, Empty, ErrorBanner, Loading, Notice, Pager, SEVERITIES } from "../components/ui";

const INITIAL = { q: "", severity: [], status: [], detection_source: "", sort: "severity", order: "desc" };

export default function Alerts() {
  const nav = useNavigate();
  const [draft, setDraft] = useState(INITIAL);
  const [filters, setFilters] = useState(INITIAL);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState(new Set());
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [title, setTitle] = useState("");
  const { data, error, loading, reload } = useAsync(() => api.alerts({ ...filters, page, page_size: 25 }), [filters, page]);

  const toggleIn = (key, v) => setDraft((d) => ({ ...d, [key]: d[key].includes(v) ? d[key].filter((x) => x !== v) : [...d[key], v] }));
  const apply = (e) => { e.preventDefault(); setPage(1); setFilters(draft); };
  const toggleSel = (id) => setSelected((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });

  async function run(opts) {
    setBusy(true); setMsg(null); setActionError(null);
    try {
      const r = await api.runDetection(opts);
      setMsg(`Detection run #${r.id}: ${r.events_analyzed} events analysed, ${r.alerts_created} new alert(s), ${r.alerts_updated} refreshed${r.alerts_cleared ? `, ${r.alerts_cleared} cleared` : ""}.` +
        (Object.keys(r.skipped).length ? ` Skipped: ${Object.entries(r.skipped).map(([k, v]) => `${k} (${v})`).join("; ")}` : ""));
      reload();
    } catch (e) { setActionError(e); } finally { setBusy(false); }
  }
  async function createIncident(e) {
    e.preventDefault(); setBusy(true); setActionError(null);
    try { const inc = await api.createIncident({ title, alert_ids: [...selected] }); nav(`/incidents/${inc.id}`); }
    catch (err) { setActionError(err); setBusy(false); }
  }

  return (
    <>
      <div className="page-head">
        <div><h1>Alerts</h1><p>Rule, correlation and model-generated findings. Each is a lead for investigation, not proof of an attack.</p></div>
        <div className="row"><button disabled={busy} onClick={() => run({ use_ml: true, clear_existing: false })}>{busy ? "Working…" : "Run detection"}</button></div>
      </div>
      <ErrorBanner error={actionError} />
      {msg && <Notice kind="ok">{msg}</Notice>}
      <form className="panel" onSubmit={apply} role="search">
        <div className="row">
          <label>Search<input type="search" value={draft.q} onChange={(e) => setDraft({ ...draft, q: e.target.value })} placeholder="title, user, IP, host" /></label>
          <label>Source<select value={draft.detection_source} onChange={(e) => setDraft({ ...draft, detection_source: e.target.value })}><option value="">Any</option><option value="rule">Rule</option><option value="correlation">Correlation</option><option value="ml">ML anomaly</option></select></label>
          <label>Sort by<select value={draft.sort} onChange={(e) => setDraft({ ...draft, sort: e.target.value })}>
            <option value="severity">Severity</option><option value="last_seen">Last seen</option><option value="first_seen">First seen</option><option value="confidence">Indicator</option><option value="status">Status</option></select></label>
          <label>Order<select value={draft.order} onChange={(e) => setDraft({ ...draft, order: e.target.value })}><option value="desc">Descending</option><option value="asc">Ascending</option></select></label>
        </div>
        <div className="row" style={{ marginTop: ".7rem" }}>
          <fieldset style={{ border: 0, padding: 0, margin: 0 }}><legend className="small muted">Severity</legend>
            <div className="row">{SEVERITIES.map((s) => <label className="check" key={s}><input type="checkbox" checked={draft.severity.includes(s)} onChange={() => toggleIn("severity", s)} />{s}</label>)}</div></fieldset>
          <fieldset style={{ border: 0, padding: 0, margin: 0 }}><legend className="small muted">Status</legend>
            <div className="row">{ALERT_STATUSES.map((s) => <label className="check" key={s}><input type="checkbox" checked={draft.status.includes(s)} onChange={() => toggleIn("status", s)} />{s}</label>)}</div></fieldset>
          <button type="submit">Apply filters</button>
          <button type="button" className="ghost" onClick={() => { setDraft(INITIAL); setFilters(INITIAL); setPage(1); }}>Reset</button>
        </div>
      </form>
      <ErrorBanner error={error} onRetry={reload} />
      {loading && !data && <Loading what="alerts" />}
      {selected.size > 0 && (
        <form className="panel row" onSubmit={createIncident}>
          <label>Incident title for {selected.size} selected alert(s)<input type="text" required minLength={3} value={title} onChange={(e) => setTitle(e.target.value)} /></label>
          <button type="submit" disabled={busy}>Create incident</button>
          <button type="button" className="ghost" onClick={() => setSelected(new Set())}>Clear selection</button>
        </form>
      )}
      {data && (
        <div className="panel">
          {data.items.length === 0 ? (
            <Empty title="No alerts">{data.total === 0 && !filters.q && !filters.severity.length && !filters.status.length ? "Load data on the Log ingestion page, then choose Run detection." : "No alerts match these filters."}</Empty>
          ) : <AlertTable alerts={data.items} selected={selected} onToggle={toggleSel} />}
          <Pager page={data.page} pageSize={data.page_size} total={data.total} onPage={setPage} />
        </div>
      )}
    </>
  );
}
