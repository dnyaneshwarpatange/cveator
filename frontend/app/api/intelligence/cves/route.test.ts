import { expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/backend", () => ({ sessionBackendRequest: vi.fn() }));
import { sessionBackendRequest } from "@/lib/backend";
import { GET } from "./route";

it("forwards sorting together with search filters and pagination", async () => {
  vi.mocked(sessionBackendRequest).mockResolvedValue(Response.json({ items: [] }));
  const response = await GET(new NextRequest("http://localhost/api/intelligence/cves?q=jira&vendor=atlassian&page=2&sort_by=cvss_score&sort_order=asc"));
  expect(response.status).toBe(200);
  const url = new URL(vi.mocked(sessionBackendRequest).mock.calls[0][0], "http://backend");
  expect(Object.fromEntries(url.searchParams)).toEqual({ q: "jira", vendor: "atlassian", page: "2", sort_by: "cvss_score", sort_order: "asc" });
});
