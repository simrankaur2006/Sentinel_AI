import { Link } from "react-router-dom";

export const SEVERITIES = ["Critical", "High", "Medium", "Low"];
export const ALERT_STATUSES = ["New", "Investigating", "Resolved", "False Positive"];
export const INCIDENT_STATUSES = ["Open", "Investigating", "Contained", "Resolved", "Closed"];
export const SEV_COLORS = { Critical: "#ff6b78", High: "#f29544", Medium: "#e8c547", Low: "#8ea6c9" };

export const SeverityBadge = ({ value }) => <span className={`badge sev-${value}`}>{value}</span>;
export const StatusBadge = ({ value }) => <span className={`badge st st-${String(value).replace(" ", "-")}`}>{value}</span>;
export const SourceTag = ({ value }) => (
  <span className="tag" title={value === "ml" ? "Model-generated anomaly (not a rule match)" : value === "correlation" ? "Combines several rule findings" : "Deterministic rule"}>
    {value === "ml" ? "ML anomaly" : value === "correlation" ? "Correlation" : "Rule"}
  </span>
);

export const StatCard = ({ label, value }) => (
  <div className="stat"><div className="v">{value ?? "–"}</div><div className="l">{label}</div></div>
);

export const Loading = ({ what = "data" }) => <div className="loading" role="status">Loading {what}…</div>;

export const ErrorBanner = ({ error, onRetry }) =>
  error ? (
    <div className="banner error" role="alert">
      <strong>{error.status === 0 ? "API unreachable." : "Request failed."}</strong> {error.message}{" "}
      {onRetry && <button className="ghost" onClick={onRetry}>Retry</button>}
    </div>
  ) : null;

export const Notice = ({ kind = "info", children }) => (
  <div className={`banner ${kind}`} role={kind === "error" ? "alert" : "status"}>{children}</div>
);

export const Empty = ({ title, children, action }) => (
  <div className="empty"><h2>{title}</h2><p>{children}</p>{action}</div>
);

export function Pager({ page, pageSize, total, onPage }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="pager">
      <span>{total} result{total === 1 ? "" : "s"} · page {page} of {pages}</span>
      <button className="ghost" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
      <button className="ghost" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
    </div>
  );
}

export const fmtTime = (iso) => (iso ? iso.replace("T", " ").replace(/\.\d+/, "").replace("+00:00", "Z") : "–");
export const fmtBytes = (n) => (n == null ? "–" : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : n >= 1e3 ? `${(n / 1e3).toFixed(1)} kB` : `${n} B`);
export const confidenceLabel = (kind) => (kind === "anomaly_score" ? "Anomaly score (relative, not a probability)" : "Heuristic strength (not a probability)");

export const AlertLink = ({ alert }) => <Link to={`/alerts/${alert.id}`}>{alert.ref}</Link>;

export function AlertTable({ alerts, selected, onToggle }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr>{onToggle && <th><span className="sr-only">Select</span></th>}<th>Alert</th><th>Severity</th><th>Title</th><th>Source</th><th>Status</th><th>Last seen (UTC)</th></tr></thead>
        <tbody>
          {alerts.map((a) => (
            <tr key={a.id}>
              {onToggle && (<td><input type="checkbox" aria-label={`Select ${a.ref}`} checked={selected.has(a.id)} onChange={() => onToggle(a.id)} /></td>)}
              <td className="mono"><AlertLink alert={a} /></td>
              <td><SeverityBadge value={a.severity} /></td>
              <td className="wrap">{a.title}</td>
              <td><SourceTag value={a.detection_source} /></td>
              <td><StatusBadge value={a.status} /></td>
              <td className="mono">{fmtTime(a.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function EventTable({ events }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Event</th><th>Time (UTC)</th><th>Type</th><th>Status</th><th>User</th><th>Source IP</th><th>Dest IP</th><th>Port</th><th>Sent</th><th>Message</th></tr></thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id}>
              <td className="mono">{e.ref}</td><td className="mono">{fmtTime(e.timestamp)}</td><td>{e.event_type || "–"}</td><td>{e.status || "–"}</td>
              <td>{e.username || "–"}</td><td className="mono">{e.source_ip || "–"}</td><td className="mono">{e.destination_ip || "–"}</td>
              <td>{e.port ?? "–"}</td><td>{fmtBytes(e.bytes_sent)}</td><td className="wrap">{e.message || "–"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function MitreTable({ items }) {
  if (!items || items.length === 0) return <p className="muted">No MITRE ATT&amp;CK association is supported by the evidence.</p>;
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Technique</th><th>Tactic</th><th>Relation</th><th>Observed</th><th>Why</th></tr></thead>
        <tbody>
          {items.map((m) => (
            <tr key={m.technique_id}>
              <td><a href={m.url} target="_blank" rel="noreferrer noopener">{m.technique_id}</a> {m.technique_name}</td>
              <td>{m.tactics.map((t) => t.name).join(", ")}</td>
              <td title={m.relation_meaning}><span className="tag">{m.relation === "behavior_consistent" ? "Behavior consistent" : "Potential association"}</span></td>
              <td className="wrap">{m.observed_behavior}</td><td className="wrap">{m.rationale}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
