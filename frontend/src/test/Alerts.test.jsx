import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Alerts from "../pages/Alerts";
import { ApiError, api } from "../api/client";

vi.mock("../api/client", async (orig) => {
  const mod = await orig();
  return { ...mod, api: { ...mod.api, alerts: vi.fn(), runDetection: vi.fn(), createIncident: vi.fn() } };
});

const alert = (id, severity, title) => ({ id, ref: `ALT-0000${id}`, severity, title, detection_source: "rule", status: "New", last_seen: "2025-03-10T02:55:00+00:00" });
const page = (items) => ({ items, total: items.length, page: 1, page_size: 25 });
const renderPage = () => render(<MemoryRouter><Alerts /></MemoryRouter>);

describe("Alerts page", () => {
  beforeEach(() => { vi.clearAllMocks(); api.alerts.mockResolvedValue(page([alert(1, "High", "Repeated failed logins")])); });

  it("lists alerts from the API", async () => {
    renderPage();
    expect(await screen.findByText("Repeated failed logins")).toBeInTheDocument();
    expect(screen.getAllByText("High").length).toBeGreaterThan(0); // badge (and the severity filter label)
  });

  it("sends severity, status and search filters to the API when applied", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("Repeated failed logins");
    await user.click(screen.getByLabelText("Critical"));
    await user.click(screen.getByLabelText("Investigating"));
    await user.type(screen.getByLabelText("Search"), "203.0.113.50");
    await user.click(screen.getByRole("button", { name: /apply filters/i }));
    await waitFor(() => {
      const last = api.alerts.mock.calls.at(-1)[0];
      expect(last.severity).toEqual(["Critical"]);
      expect(last.status).toEqual(["Investigating"]);
      expect(last.q).toBe("203.0.113.50");
      expect(last.page).toBe(1);
    });
  });

  it("shows an empty state when nothing matches", async () => {
    api.alerts.mockResolvedValue(page([]));
    renderPage();
    expect(await screen.findByText(/No alerts/i)).toBeInTheDocument();
  });

  it("shows API errors", async () => {
    api.alerts.mockRejectedValue(new ApiError(503, "Database unavailable."));
    renderPage();
    expect(await screen.findByRole("alert")).toHaveTextContent("Database unavailable.");
  });

  it("runs detection and reports the outcome", async () => {
    const user = userEvent.setup();
    api.runDetection.mockResolvedValue({ id: 3, events_analyzed: 270, alerts_created: 12, alerts_updated: 0, alerts_cleared: 0, skipped: {} });
    renderPage();
    await screen.findByText("Repeated failed logins");
    await user.click(screen.getByRole("button", { name: /run detection/i }));
    expect(await screen.findByText(/12 new alert/)).toBeInTheDocument();
  });

  it("offers incident creation for selected alerts", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByLabelText("Select ALT-00001"));
    expect(screen.getByRole("button", { name: /create incident/i })).toBeInTheDocument();
  });
});
