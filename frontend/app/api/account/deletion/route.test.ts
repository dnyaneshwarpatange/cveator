import { expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
vi.mock("@/lib/backend", () => ({sessionBackendRequest: vi.fn(), sessionCookieName: "session", sessionCookieSecure: true}));
import { sessionBackendRequest } from "@/lib/backend";
import { DELETE, POST } from "./route";

it("does not clear the session on invalid OTP", async () => {
  vi.mocked(sessionBackendRequest).mockResolvedValue(Response.json({detail: "Invalid code"}, {status: 400}));
  const response = await DELETE(new NextRequest("http://localhost/api/account/deletion", {method: "DELETE", body: "{}"}));
  expect(response.status).toBe(400);
  expect(response.headers.get("set-cookie")).toBeNull();
});
it("clears the cookie only after successful deletion", async () => {
  vi.mocked(sessionBackendRequest).mockResolvedValue(new Response(null, {status: 204}));
  const response = await DELETE(new NextRequest("http://localhost/api/account/deletion", {method: "DELETE", body: "{}"}));
  expect(response.status).toBe(204);
  expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
});
it("requires authentication to request an OTP", async () => {
  vi.mocked(sessionBackendRequest).mockResolvedValue(null);
  expect((await POST()).status).toBe(401);
});
