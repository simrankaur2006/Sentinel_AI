import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Reports from "../pages/Reports";
import { api } from "../api/client";

vi.mock("../api/client", async (orig) => {
  const mod = await orig();
  return { ...mod, api: { ...mod.api, reports: vi.fn(), report: vi.fn() } };
});

describe("Reports page", () => {
  beforeEach(() => vi.clearAllMocks());

  it("links to Markdown and JSON downloads served by the API", async () => {
    api.reports.mockResolvedValue({ items: [{ id: 4, incident_id: 2, title: "INC-0002 Test", generated_at: "2025-03-11T09:00:00+00:00", generator: "deterministic-fallback" }], total: 1, page: 1, page_size: 25 });
    render(<MemoryRouter><Reports /></MemoryRouter>);
    expect(await screen.findByRole("link", { name: "Markdown" })).toHaveAttribute("href", expect.stringMatching(/\/reports\/4\/download\?format=markdown$/));
    expect(screen.getByRole("link", { name: "JSON" })).toHaveAttribute("href", expect.stringMatching(/format=json$/));
    expect(screen.getByText("deterministic-fallback")).toBeInTheDocument();
  });

  it("shows an empty state", async () => {
    api.reports.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 25 });
    render(<MemoryRouter><Reports /></MemoryRouter>);
    expect(await screen.findByText(/No reports yet/i)).toBeInTheDocument();
  });
});
