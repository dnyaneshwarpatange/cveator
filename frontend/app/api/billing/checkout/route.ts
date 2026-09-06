import { NextRequest, NextResponse } from "next/server";

import { sessionBackendRequest } from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function POST(request: NextRequest): Promise<NextResponse> {
  const payload = (await request.json().catch(() => null)) as { plan_id?: string } | null;
  if (!payload || typeof payload.plan_id !== "string" || !payload.plan_id.trim()) {
    return NextResponse.json({ detail: "Invalid plan" }, { status: 400 });
  }
  const response = await sessionBackendRequest("/billing/checkout", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ plan_id: payload.plan_id })
  });
  if (!response) {
    return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
  }
  return proxyBackendResponse(response);
}
