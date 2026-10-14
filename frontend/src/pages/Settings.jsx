import { useEffect, useState } from "react";
import { api } from "../api/client";
import { useAsync } from "../api/useAsync";
import { ErrorBanner, Loading, Notice } from "../components/ui";

const SECTIONS = [
  ["Failed logins (R-AUTH-001)", [["failed_login_threshold", "Failures to alert"], ["failed_login_window_minutes", "Window (minutes)"]]],
  ["Success after failures (R-AUTH-002)", [["success_after_failures_min", "Minimum prior failures"], ["success_after_failures_window_minutes", "Window (minutes)"]]],
  ["Unusual authentication (R-AUTH-003)", [["multi_ip_login_threshold", "Distinct IPs to alert"], ["multi_ip_window_minutes", "Window (minutes)"], ["offhours_start_hour", "Off-hours start (UTC hour)"], ["offhours_end_hour", "Off-hours end (UTC hour)"], ["offhours_min_baseline_logins", "Baseline logins required"]]],
  ["Port scan (R-NET-001)", [["portscan_distinct_ports", "Distinct ports to alert"], ["portscan_window_minutes", "Window (minutes)"]]],
  ["Watchlist (R-NET-002)", [["suspicious_ip_window_minutes", "Grouping window (minutes)"], ["suspicious_ips", "Suspicious IPs / CIDRs (one per line)", "list"]]],
  ["Outbound volume (R-NET-003)", [["outbound_bytes_threshold", "Bytes sent to alert"], ["outbound_window_minutes", "Window (minutes)"]]],
  ["Sensitive resources (R-ACC-001)", [["sensitive_min_events", "Denied attempts to alert"], ["sensitive_window_minutes", "Window (minutes)"], ["sensitive_resource_patterns", "Patterns (one per line, case-insensitive substring)", "list"]]],
  ["Correlation (R-COR-001)", [["correlation_enabled", "Enable correlation", "bool"], ["correlation_min_distinct_rules", "Distinct rules required"]]],
  ["Machine learning (Isolation Forest)", [["ml_enabled", "Enable ML detection", "bool"], ["ml_contamination", "Sensitivity: expected outlier fraction (0.001–0.5)", "float"], ["ml_n_estimators", "Trees"], ["ml_random_seed", "Random seed"], ["ml_min_events", "Minimum events needed"], ["ml_max_alerts", "Maximum ML alerts per run"], ["ml_skip_rule_covered", "Skip events already covered by rules", "bool"]]],
];

export default function Settings() {
  const cfg = useAsync(() => api.getConfig(), []);
  const rules = useAsync(() => api.rules(), []);
  const [form, setForm] = useState(null);
  const [msg, setMsg] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const [run, setRun] = useState({ use_ml: true, clear_existing: false });

  useEffect(() => { if (cfg.data) setForm(cfg.data.config); }, [cfg.data]);
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  async function save(e) {
    e.preventDefault(); setBusy(true); setErr(null); setMsg(null);
    try { await api.putConfig(form); setMsg("Settings saved. Re-run detection to apply them."); cfg.reload(); } catch (x) { setErr(x); } finally { setBusy(false); }
  }
  async function reset() {
    setBusy(true); setErr(null); setMsg(null);
    try { await api.resetConfig(); setMsg("Defaults restored."); cfg.reload(); } catch (x) { setErr(x); } finally { setBusy(false); }
  }
  async function runNow() {
    setBusy(true); setErr(null); setMsg(null);
    try { const r = await api.runDetection(run); setMsg(`Run #${r.id} complete: ${r.alerts_created} new, ${r.alerts_updated} refreshed, ${r.alerts_cleared} cleared.`); } catch (x) { setErr(x); } finally { setBusy(false); }
  }
  function input(k, label, kind) {
    const v = form[k];
    if (kind === "bool") return <label className="check" key={k}><input type="checkbox" checked={!!v} onChange={(e) => set(k, e.target.checked)} />{label}</label>;
    if (kind === "list") return <label key={k}>{label}<textarea value={(v || []).join("\n")} onChange={(e) => set(k, e.target.value.split("\n").map((s) => s.trim()).filter(Boolean))} /></label>;
    return <label key={k}>{label}<input type="number" step={kind === "float" ? "0.001" : "1"} value={v} onChange={(e) => set(k, kind === "float" ? parseFloat(e.target.value) : parseInt(e.target.value, 10))} /></label>;
  }

  return (
    <>
      <div className="page-head"><div><h1>Detection settings</h1><p>Thresholds are stored in the database and used by every detection run.</p></div></div>
      <ErrorBanner error={err} /><ErrorBanner error={cfg.error} onRetry={cfg.reload} />
      {msg && <Notice kind="ok">{msg}</Notice>}
      {cfg.loading && !form && <Loading what="settings" />}
      {form && (
        <>
          <div className="panel"><h2>Run detection</h2>
            <div className="row">
              <label className="check"><input type="checkbox" checked={run.use_ml} onChange={(e) => setRun({ ...run, use_ml: e.target.checked })} />Include ML anomaly detection</label>
              <label className="check"><input type="checkbox" checked={run.clear_existing} onChange={(e) => setRun({ ...run, clear_existing: e.target.checked })} />Clear untouched “New” alerts not in an incident first</label>
              <button disabled={busy} onClick={runNow}>Run detection now</button>
            </div>
            <p className="small muted">Changing ML sensitivity produces a different set of anomaly alerts; earlier ML alerts are kept unless you clear them. Analyst-managed alerts are never deleted.</p></div>
          <form onSubmit={save}>
            {SECTIONS.map(([title, fields]) => (
              <fieldset className="panel" key={title}><legend><strong>{title}</strong></legend><div className="row">{fields.map(([k, label, kind]) => input(k, label, kind))}</div></fieldset>
            ))}
            <div className="row"><button type="submit" disabled={busy}>Save settings</button><button type="button" className="ghost" disabled={busy} onClick={reset}>Restore defaults</button></div>
          </form>
        </>
      )}
      <div className="panel" style={{ marginTop: "1rem" }}><h2>Detection rules and their limitations</h2>
        {rules.loading && <Loading what="rules" />}<ErrorBanner error={rules.error} onRetry={rules.reload} />
        {rules.data && (<div className="table-wrap"><table><thead><tr><th>Rule</th><th>Logic</th><th>Needs</th><th>Limitations</th></tr></thead>
          <tbody>{rules.data.map((r) => <tr key={r.id}><td><span className="mono">{r.id}</span><div>{r.name}</div></td><td className="wrap">{r.logic}</td><td className="wrap">{r.requires}</td><td className="wrap">{r.limitations}</td></tr>)}</tbody></table></div>)}</div>
    </>
  );
}
