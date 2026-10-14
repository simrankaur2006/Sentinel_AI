import { useState } from "react";
import { Link } from "react-router-dom";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api/client";
import { useAsync } from "../api/useAsync";
import { AlertTable, Empty, ErrorBanner, Loading, SEV_COLORS, SeverityBadge, StatCard, fmtTime } from "../components/ui";

const axis = { stroke: "#93a1bb", fontSize: 12 };

function Bars({ data, colorFor }) {
  return (
    <div style={{ width: "100%", height: 200 }}>
      <ResponsiveContainer>
        <BarChart data={data} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
          <CartesianGrid stroke="#263250" vertical={false} />
          <XAxis dataKey="name" {...axis} /><YAxis allowDecimals={false} {...axis} />
          <Tooltip contentStyle={{ background: "#141c2e", border: "1px solid #263250" }} cursor={{ fill: "#1a2438" }} />
          <Bar dataKey="count" fill="#7c9cf5" radius={[3, 3, 0, 0]}>
            {colorFor && data.map((d) => <Cell key={d.name} fill={colorFor(d.name)} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

const toIso = (v) => (v ? new Date(v).toISOString() : undefined);

export default function Dashboard() {
  const [range, setRange] = useState({ start: "", end: "" });
  const { data, error, loading, reload } = useAsync(() => api.dashboard({ start: toIso(range.start), end: toIso(range.end) }), [range.start, range.end]);

  return (
    <>
      <div className="page-head">
        <div><h1>Dashboard</h1><p>Everything below is computed from the events and alerts stored in the database.</p></div>
        <div className="row">
          <label>From<input type="datetime-local" value={range.start} onChange={(e) => setRange({ ...range, start: e.target.value })} /></label>
          <label>To<input type="datetime-local" value={range.end} onChange={(e) => setRange({ ...range, end: e.target.value })} /></label>
          <button className="ghost" onClick={() => setRange({ start: "", end: "" })}>Clear dates</button>
        </div>
      </div>
      <ErrorBanner error={error} onRetry={reload} />
      {loading && !data && <Loading what="dashboard" />}
      {data && data.totals.events === 0 && (
        <div className="panel"><Empty title="No security events yet" action={<Link className="btn" to="/ingest">Load data</Link>}>
          Load the synthetic sample dataset or upload your own logs, then run detection.</Empty></div>
      )}
      {data && data.totals.events > 0 && (
        <>
          <div className="grid g4" style={{ marginBottom: "1rem" }}>
            <StatCard label="Events ingested" value={data.totals.events.toLocaleString()} />
            <StatCard label="Alerts" value={data.totals.alerts} />
            <StatCard label="Open alerts (New or Investigating)" value={data.totals.open_alerts} />
            <StatCard label="Incidents" value={data.totals.incidents} />
          </div>
          {data.totals.alerts === 0 && (
            <div className="banner info">No alerts yet. <Link to="/alerts">Run detection</Link> to analyse the stored events.</div>
          )}
          <div className="panel">
            <h2>Event volume per {data.events_over_time.bucket}</h2>
            <div style={{ width: "100%", height: 220 }}>
              <ResponsiveContainer>
                <AreaChart data={data.events_over_time.points.map((p) => ({ ...p, label: fmtTime(p.time).slice(5, 16) }))} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
                  <CartesianGrid stroke="#263250" vertical={false} />
                  <XAxis dataKey="label" {...axis} /><YAxis allowDecimals={false} {...axis} />
                  <Tooltip contentStyle={{ background: "#141c2e", border: "1px solid #263250" }} />
                  <Area type="monotone" dataKey="count" stroke="#7c9cf5" fill="#7c9cf5" fillOpacity={0.18} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div className="grid g2">
            <div className="panel"><h2>Alerts by severity</h2><Bars data={data.alerts_by_severity} colorFor={(n) => SEV_COLORS[n]} /></div>
            <div className="panel"><h2>Alerts by detection source</h2><Bars data={data.alerts_by_source} /></div>
            <div className="panel"><h2>Alert status</h2><Bars data={data.alerts_by_status} /></div>
            <div className="panel">
              <h2>Anomaly detection (Isolation Forest)</h2>
              {data.anomaly.metadata.skipped ? (
                <p className="muted">Skipped on the last run: {data.anomaly.metadata.skipped}</p>
              ) : data.latest_run ? (
                <p className="small muted">
                  {data.anomaly.alert_count} model-generated alert(s). Sensitivity (contamination) {data.anomaly.metadata.contamination}, seed {data.anomaly.metadata.random_seed}.
                  Scores are relative to this dataset and are not probabilities; an anomaly is not necessarily malicious.
                </p>
              ) : <p className="muted">Run detection to see anomaly results.</p>}
              <ul className="plain">
                {data.anomaly.top.map((a) => (
                  <li key={a.id}><Link to={`/alerts/${a.id}`}>{a.ref}</Link> <SeverityBadge value={a.severity} /> <span className="muted small">score {a.confidence.toFixed(2)}</span> {a.title}</li>
                ))}
              </ul>
            </div>
            <div className="panel"><h2>Top affected users</h2>
              {data.top_users.length ? <ul className="plain">{data.top_users.map((u) => <li key={u.name}>{u.name} <span className="muted">· {u.count} alert{u.count === 1 ? "" : "s"}</span></li>)}</ul> : <p className="muted">No usernames in alerts.</p>}</div>
            <div className="panel"><h2>Top IP addresses</h2>
              {data.top_ips.length ? <ul className="plain">{data.top_ips.map((u) => <li key={u.name}><span className="mono">{u.name}</span> <span className="muted">· {u.count} alert{u.count === 1 ? "" : "s"}</span></li>)}</ul> : <p className="muted">No IP addresses in alerts.</p>}</div>
          </div>
          <div className="panel"><h2>Recent security activity</h2>
            {data.recent_alerts.length ? <AlertTable alerts={data.recent_alerts} /> : <p className="muted">No alerts in this range.</p>}</div>
          <div className="panel"><h2>Recent incidents</h2>
            {data.recent_incidents.length ? (
              <ul className="plain">{data.recent_incidents.map((i) => <li key={i.id}><Link to={`/incidents/${i.id}`}>{i.ref}</Link> <SeverityBadge value={i.severity} /> {i.title} <span className="muted small">· {i.status}</span></li>)}</ul>
            ) : <p className="muted">No incidents yet. Select alerts on the <Link to="/alerts">Alerts</Link> page to open one.</p>}</div>
        </>
      )}
    </>
  );
}
