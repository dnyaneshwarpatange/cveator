import { NextRequest, NextResponse } from "next/server";

import { sessionBackendRequest } from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function GET(): Promise<NextResponse> {
  const response = await sessionBackendRequest("/billing/subscription");
  if (!response) {
    return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
  }
  return proxyBackendResponse(response);
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  const payload = (await request.json().catch(() => null)) as { at_period_end?: boolean } | null;
  if (!payload || typeof payload.at_period_end !== "boolean") {
    return NextResponse.json({ detail: "Invalid cancellation request" }, { status: 400 });
  }
  const response = await sessionBackendRequest("/billing/subscription/cancel", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!response) {
    return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
  }
  return proxyBackendResponse(response);
}
