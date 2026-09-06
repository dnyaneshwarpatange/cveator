import { afterEach, describe, expect, it, vi } from "vitest";
import { apiErrorMessage, ApiError, requestJson } from "./api-client";

afterEach(() => vi.unstubAllGlobals());

describe("user-facing request failures", () => {
  it("formats FastAPI validation arrays as text instead of rendering objects", () => {
    expect(apiErrorMessage({ detail: [{ msg: "Value error, Invalid email" }] }, "Failed"))
      .toBe("Invalid email");
    expect(apiErrorMessage({ detail: [{ bad: true }] }, "Failed")).toBe("Failed");
  });
  it("keeps a 401 status so callers can redirect an expired session", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response('{"detail":"Session expired"}', { status: 401 })));
    await expect(requestJson("/api/dashboard")).rejects.toMatchObject({ status: 401, message: "Session expired" });
  });
  it("accepts successful responses with no body, such as sign-out", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 204 })));
    await expect(requestJson("/api/session", { method: "DELETE" })).resolves.toBeNull();
  });
  it("turns a network rejection into a recoverable error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(requestJson("/api/watchlist")).rejects.toBeInstanceOf(ApiError);
  });
});
