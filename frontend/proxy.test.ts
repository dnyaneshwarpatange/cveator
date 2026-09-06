import { afterEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

import { proxy } from "./proxy";
afterEach(() => vi.unstubAllEnvs());

describe("same-origin API protection", () => {
  it("uses the configured public origin behind a reverse proxy", () => {
    vi.stubEnv("PUBLIC_APP_URL", "https://monitor.company.com");
    const request = new NextRequest("http://0.0.0.0:3000/api/watchlist", {
      method: "POST", headers: { origin: "https://monitor.company.com" }
    });
    expect(proxy(request).status).toBe(200);
    const attack = new NextRequest("http://0.0.0.0:3000/api/watchlist", {
      method: "POST", headers: { origin: "https://attacker.com", "x-forwarded-host": "attacker.com" }
    });
    expect(proxy(attack).status).toBe(403);
  });
  it("rejects a cross-site state-changing request", () => {
    const request = new NextRequest("http://localhost/api/session", {
      method: "DELETE",
      headers: { "sec-fetch-site": "cross-site" }
    });

    expect(proxy(request).status).toBe(403);
  });

  it("allows a matching origin", () => {
    const request = new NextRequest("http://localhost/api/watchlist", {
      method: "POST",
      headers: { origin: "http://localhost" }
    });

    expect(proxy(request).status).toBe(200);
  });
});
