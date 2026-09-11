import { NextRequest, NextResponse } from "next/server";
import { sessionBackendRequest, sessionCookieName, sessionCookieSecure } from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function POST() {
  try {
    const response = await sessionBackendRequest("/auth/account/deletion-code", { method: "POST", signal: AbortSignal.timeout(60_000) });
    return response ? await proxyBackendResponse(response) : NextResponse.json({detail: "Not authenticated"}, {status: 401});
  } catch { return NextResponse.json({detail: "Unable to send deletion code. Try again later."}, {status: 503}); }
}

export async function DELETE(request: NextRequest) {
  try {
    const response = await sessionBackendRequest("/auth/account/delete", {
      method: "POST", headers: {"content-type": "application/json"}, body: await request.text()
    });
    if (!response) return NextResponse.json({detail: "Not authenticated"}, {status: 401});
    const result = await proxyBackendResponse(response);
    if (response.ok) result.cookies.set({name: sessionCookieName, value: "", httpOnly: true,
      secure: sessionCookieSecure, sameSite: "lax", maxAge: 0, path: "/"});
    return result;
  } catch { return NextResponse.json({detail: "Deletion could not be confirmed. Try signing in again to check your account."}, {status: 503}); }
}
