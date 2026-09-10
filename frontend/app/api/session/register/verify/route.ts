import { NextRequest, NextResponse } from "next/server";
import { backendRequest, sessionCookieName, sessionCookieSecure } from "@/lib/backend";
import type { AuthResponse } from "@/lib/types";

export async function POST(request: NextRequest) {
  const response = await backendRequest("/auth/register/verify", {
    method: "POST", headers: { "content-type": "application/json" },
    body: await request.text()
  });
  const payload = await response.json().catch(() => ({detail: "Unexpected API response"}));
  if (!response.ok) return NextResponse.json(payload, {status: response.status});
  const authenticated = payload as AuthResponse;
  const result = NextResponse.json({user: authenticated.user});
  result.cookies.set({name: sessionCookieName, value: authenticated.access_token,
    httpOnly: true, secure: sessionCookieSecure, sameSite: "lax",
    maxAge: authenticated.expires_in_seconds, path: "/"});
  return result;
}
