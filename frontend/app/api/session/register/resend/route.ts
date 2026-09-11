import { NextRequest, NextResponse } from "next/server";
import { backendRequest } from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function POST(request: NextRequest) {
  try {
    return await proxyBackendResponse(await backendRequest("/auth/register/resend", {
      method: "POST", headers: {"content-type": "application/json"},
      signal: AbortSignal.timeout(60_000), body: await request.text()
    }));
  } catch {
    return NextResponse.json({detail: "Email delivery could not be confirmed. Please wait a minute and resend."}, {status: 503});
  }
}
