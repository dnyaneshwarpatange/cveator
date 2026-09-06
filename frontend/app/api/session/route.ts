import { NextResponse } from "next/server";

import {
  sessionBackendRequest,
  sessionCookieName,
  sessionCookieSecure
} from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function GET(): Promise<NextResponse> {
  const response = await sessionBackendRequest("/auth/me");
  if (!response) {
    return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
  }
  return proxyBackendResponse(response);
}

export async function DELETE(): Promise<NextResponse> {
  const response = new NextResponse(null, { status: 204 });
  response.cookies.set({
    name: sessionCookieName,
    value: "",
    httpOnly: true,
    secure: sessionCookieSecure,
    sameSite: "lax",
    maxAge: 0,
    path: "/"
  });
  return response;
}
