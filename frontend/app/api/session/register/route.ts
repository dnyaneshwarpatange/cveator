import { NextRequest, NextResponse } from "next/server";
import { backendRequest } from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function POST(request: NextRequest) {
  try {
    return await proxyBackendResponse(await backendRequest("/auth/register", {
    method: "POST", headers: { "content-type": "application/json" },
    signal: AbortSignal.timeout(60000),
    body: await request.text()
    }));
  } catch {
    return NextResponse.json({ detail: "Verification email could not be confirmed. Please wait 60 seconds and try again; use only the newest code." }, { status: 503 });
  }
}
