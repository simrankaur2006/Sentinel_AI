import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";

const NAV = [
  ["/", "Dashboard"], ["/ingest", "Log ingestion"], ["/events", "Event explorer"], ["/alerts", "Alerts"],
  ["/incidents", "Incidents"], ["/reports", "Reports"], ["/settings", "Detection settings"], ["/system", "System"],
];

export default function Layout() {
  const [open, setOpen] = useState(false);
  return (
    <div className="shell">
      <aside className="rail">
        <div className="brand">
          <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true"><path d="M16 4l10 4v7c0 5.5-3.8 10-10 12.5C9.800 25 6 20.500 6 15V8z" fill="none" stroke="#7c9cf5" strokeWidth="2.4" /><circle cx="16" cy="15" r="3" fill="#7c9cf5" /></svg>
          SentinelAI
          <button className="ghost menu-btn" aria-expanded={open} aria-controls="nav" onClick={() => setOpen(!open)}>Menu</button>
        </div>
        <nav id="nav" className={open ? "open" : ""} aria-label="Main">
          {NAV.map(([to, label]) => (
            <NavLink key={to} to={to} end={to === "/"} onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? "active" : "")}>{label}</NavLink>
          ))}
        </nav>
        <div className="mode">Local demo mode — no authentication. Use synthetic or authorised data only.</div>
      </aside>
      <main><Outlet /></main>
    </div>
  );
}
