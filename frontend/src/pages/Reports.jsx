import { useState } from "react";
import { Link } from "react-router-dom";
import { api, reportDownloadUrl } from "../api/client";
import { useAsync } from "../api/useAsync";
import { Empty, ErrorBanner, Loading, Pager, fmtTime } from "../components/ui";

export default function Reports() {
  const [page, setPage] = useState(1);
  const [openId, setOpenId] = useState(null);
  const { data, error, loading, reload } = useAsync(() => api.reports({ page, page_size: 25 }), [page]);
  const detail = useAsync(() => (openId ? api.report(openId) : Promise.resolve(null)), [openId]);

  return (
    <>
      <div className="page-head"><div><h1>Incident reports</h1><p>Generated from stored incident data. Download as Markdown or JSON.</p></div></div>
      <ErrorBanner error={error} onRetry={reload} />
      {loading && !data && <Loading what="reports" />}
      {data && (
        <div className="panel">
          {data.items.length === 0 ? <Empty title="No reports yet">Open an incident and choose Generate report.</Empty> : (
            <div className="table-wrap"><table>
              <thead><tr><th>Report</th><th>Incident</th><th>Generated (UTC)</th><th>Analysis by</th><th>Actions</th></tr></thead>
              <tbody>{data.items.map((r) => (
                <tr key={r.id}><td className="mono">#{r.id}</td><td><Link to={`/incidents/${r.incident_id}`}>{r.title}</Link></td><td className="mono">{fmtTime(r.generated_at)}</td><td>{r.generator}</td>
                  <td className="row"><button className="ghost" onClick={() => setOpenId(r.id === openId ? null : r.id)}>{r.id === openId ? "Hide" : "View"}</button>
                    <a className="btn ghost" href={reportDownloadUrl(r.id, "markdown")}>Markdown</a><a className="btn ghost" href={reportDownloadUrl(r.id, "json")}>JSON</a></td></tr>))}</tbody>
            </table></div>
          )}
          <Pager page={data.page} pageSize={data.page_size} total={data.total} onPage={setPage} />
        </div>
      )}
      {openId && (<div className="panel"><h2>Report #{openId}</h2><ErrorBanner error={detail.error} />{detail.loading ? <Loading what="report" /> : detail.data && <pre className="report">{detail.data.markdown}</pre>}</div>)}
    </>
  );
}
