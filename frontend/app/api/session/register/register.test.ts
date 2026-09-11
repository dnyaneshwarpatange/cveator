import { beforeEach, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/backend", () => ({
  backendRequest: vi.fn(), sessionCookieName: "test_session", sessionCookieSecure: true
}));
import { backendRequest } from "@/lib/backend";
import { POST as start } from "./route";
import { POST as verify } from "./verify/route";

const request = () => new NextRequest("http://localhost/api/session/register", {
  method: "POST", headers: {"content-type": "application/json"}, body: "{}"
});
beforeEach(() => vi.clearAllMocks());

it("returns actionable JSON when SMTP request times out upstream", async () => {
  vi.mocked(backendRequest).mockRejectedValue(new Error("timeout"));
  const response = await start(request());
  expect(response.status).toBe(503);
  expect((await response.json()).detail).toContain("newest code");
  expect(response.headers.get("set-cookie")).toBeNull();
});

it("sending a signup code never sets a session cookie", async () => {
  vi.mocked(backendRequest).mockResolvedValue(Response.json({challenge_id: "test-id"}, {status: 202}));
  const response = await start(request());
  expect(response.status).toBe(202);
  expect(response.headers.get("set-cookie")).toBeNull();
  expect(await response.json()).toEqual({challenge_id: "test-id"});
});

it("invalid verification does not authenticate the browser", async () => {
  vi.mocked(backendRequest).mockResolvedValue(Response.json({detail: "Invalid code"}, {status: 400}));
  const response = await verify(request());
  expect(response.status).toBe(400);
  expect(response.headers.get("set-cookie")).toBeNull();
});

it("successful verification sets a secure HttpOnly session without exposing the token in JSON", async () => {
  vi.mocked(backendRequest).mockResolvedValue(Response.json({
    access_token: "test-token", expires_in_seconds: 1800, user: {id: "user-id"}
  }, {status: 201}));
  const response = await verify(request());
  expect(response.cookies.get("test_session")?.value).toBe("test-token");
  expect(response.headers.get("set-cookie")).toContain("HttpOnly");
  expect(response.headers.get("set-cookie")).toContain("Secure");
  expect(await response.json()).toEqual({user: {id: "user-id"}});
});
