import "server-only";

import { cookies } from "next/headers";

export const sessionCookieSecure = process.env.SESSION_COOKIE_SECURE === "true";
export const sessionCookieName = sessionCookieSecure
  ? "__Host-cve_monitor_access_token"
  : "cve_monitor_access_token";

function apiBaseUrl(): string {
  return (process.env.API_INTERNAL_BASE_URL ?? "http://localhost:8000").replace(/\/$/, "");
}

export async function backendRequest(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`${apiBaseUrl()}${path}`, {
    signal: AbortSignal.timeout(12000),
    ...init,
    cache: "no-store"
  });
}

export async function sessionBackendRequest(
  path: string,
  init: RequestInit = {}
): Promise<Response | null> {
  const token = (await cookies()).get(sessionCookieName)?.value;
  if (!token) {
    return null;
  }
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${token}`);
  return backendRequest(path, { ...init, headers });
}
