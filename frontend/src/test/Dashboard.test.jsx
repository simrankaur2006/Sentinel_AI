import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Dashboard from "../pages/Dashboard";
import { ApiError, api } from "../api/client";

vi.mock("../api/client", async (orig) => {
  const mod = await orig();
  return { ...mod, api: { ...mod.api, dashboard: vi.fn() } };
});

const base = {
  totals: { events: 270, alerts: 12, open_alerts: 12, incidents: 1 },
  alerts_by_severity: [{ name: "Critical", count: 1 }, { name: "High", count: 3 }, { name: "Medium", count: 6 }, { name: "Low", count: 2 }],
  alerts_by_source: [{ name: "rule", count: 9 }], alerts_by_status: [{ name: "New", count: 12 }],
  events_over_time: { bucket: "hour", points: [{ time: "2025-03-10T02:00:00", count: 30 }] },
  top_users: [{ name: "admin", count: 4 }], top_ips: [{ name: "203.0.113.50", count: 3 }],
  recent_alerts: [{ id: 1, ref: "ALT-00001", severity: "Critical", title: "Correlated activity involving admin", detection_source: "correlation", status: "New", last_seen: "2025-03-10T02:55:00+00:00" }],
  recent_events: [], recent_incidents: [], anomaly: { alert_count: 3, top: [], metadata: { contamination: 0.05, random_seed: 42 } },
  latest_run: { id: 1 },
};
const renderPage = () => render(<MemoryRouter><Dashboard /></MemoryRouter>);

describe("Dashboard", () => {
  beforeEach(() => vi.clearAllMocks());

  it("shows a loading state, then API-derived numbers", async () => {
    api.dashboard.mockResolvedValue(base);
    renderPage();
    expect(screen.getByRole("status")).toHaveTextContent(/loading/i);
    expect(await screen.findByText("270")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.50")).toBeInTheDocument();
    expect(screen.getByText("ALT-00001")).toBeInTheDocument();
    expect(screen.getByText(/not probabilities/i)).toBeInTheDocument();
  });

  it("shows a helpful empty state for an empty database", async () => {
    api.dashboard.mockResolvedValue({ ...base, totals: { events: 0, alerts: 0, open_alerts: 0, incidents: 0 } });
    renderPage();
    expect(await screen.findByText(/No security events yet/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /load data/i })).toHaveAttribute("href", "/ingest");
  });

  it("shows an error banner with retry when the API fails", async () => {
    api.dashboard.mockRejectedValue(new ApiError(0, "Cannot reach the SentinelAI API at http://127.0.0.1:8000/api. Is the backend running?"));
    renderPage();
    expect(await screen.findByRole("alert")).toHaveTextContent(/Cannot reach/);
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
  });
});
