import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, reportDownloadUrl, request } from "../api/client";

const respond = (status, body) => vi.fn().mockResolvedValue({ ok: status < 400, status, json: async () => body });

afterEach(() => vi.restoreAllMocks());

describe("api client", () => {
  it("builds query strings, repeating array params and skipping empty values", async () => {
    const f = respond(200, { items: [] });
    vi.stubGlobal("fetch", f);
    await api.alerts({ severity: ["High", "Critical"], q: "", page: 2, status: undefined });
    const url = new URL(f.mock.calls[0][0]);
    expect(url.pathname.endsWith("/alerts")).toBe(true);
    expect(url.searchParams.getAll("severity")).toEqual(["High", "Critical"]);
    expect(url.searchParams.get("page")).toBe("2");
    expect(url.searchParams.has("q")).toBe(false);
  });

  it("turns FastAPI validation errors into readable messages", async () => {
    vi.stubGlobal("fetch", respond(422, { detail: [{ loc: ["body", "title"], msg: "String should have at least 3 characters" }] }));
    await expect(api.createIncident({ title: "x" })).rejects.toMatchObject({ status: 422, message: expect.stringContaining("title") });
  });

  it("surfaces string error details", async () => {
    vi.stubGlobal("fetch", respond(404, { detail: "Alert not found." }));
    await expect(api.alert(1)).rejects.toThrow("Alert not found.");
  });

  it("reports an unreachable API distinctly", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    const err = await request("/health").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(0);
    expect(err.message).toMatch(/Cannot reach/);
  });

  it("sends JSON bodies with the right method", async () => {
    const f = respond(200, {});
    vi.stubGlobal("fetch", f);
    await api.updateAlert(5, "Resolved");
    expect(f.mock.calls[0][1]).toMatchObject({ method: "PATCH", body: JSON.stringify({ status: "Resolved" }) });
  });

  it("builds report download URLs for both formats", () => {
    expect(reportDownloadUrl(7, "markdown")).toMatch(/\/reports\/7\/download\?format=markdown$/);
    expect(reportDownloadUrl(7, "json")).toMatch(/format=json$/);
  });
});
