import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useAsync } from "../api/useAsync";
import { Empty, ErrorBanner, Loading, Pager, SeverityBadge, StatusBadge, fmtTime } from "../components/ui";

export default function Incidents() {
  const nav = useNavigate();
  const [page, setPage] = useState(1);
  const [title, setTitle] = useState("");
  const [err, setErr] = useState(null);
  const { data, error, loading, reload } = useAsync(() => api.incidents({ page, page_size: 25 }), [page]);

  async function create(e) {
    e.preventDefault(); setErr(null);
    try { const inc = await api.createIncident({ title, alert_ids: [] }); nav(`/incidents/${inc.id}`); } catch (x) { setErr(x); }
  }
  return (
    <>
      <div className="page-head"><div><h1>Incidents</h1><p>Group related alerts, investigate, record notes and produce a report.</p></div></div>
      <ErrorBanner error={err} /><ErrorBanner error={error} onRetry={reload} />
      <form className="panel row" onSubmit={create}>
        <label>New empty incident<input type="text" required minLength={3} maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Short descriptive title" /></label>
        <button type="submit">Create incident</button>
        <span className="small muted">Tip: select alerts on the Alerts page to start an incident from them.</span>
      </form>
      {loading && !data && <Loading what="incidents" />}
      {data && (
        <div className="panel">
          {data.items.length === 0 ? <Empty title="No incidents yet">Create one above, or select alerts on the <Link to="/alerts">Alerts</Link> page.</Empty> : (
            <div className="table-wrap"><table>
              <thead><tr><th>Incident</th><th>Title</th><th>Severity</th><th>Status</th><th>Alerts</th><th>Updated (UTC)</th></tr></thead>
              <tbody>{data.items.map((i) => (<tr key={i.id}><td className="mono"><Link to={`/incidents/${i.id}`}>{i.ref}</Link></td><td className="wrap">{i.title}</td>
                <td><SeverityBadge value={i.severity} /></td><td><StatusBadge value={i.status} /></td><td>{i.alert_count}</td><td className="mono">{fmtTime(i.updated_at)}</td></tr>))}</tbody>
            </table></div>
          )}
          <Pager page={data.page} pageSize={data.page_size} total={data.total} onPage={setPage} />
        </div>
      )}
    </>
  );
}
