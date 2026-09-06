import { NextRequest, NextResponse } from "next/server";

import { sessionBackendRequest } from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function POST(request: NextRequest): Promise<NextResponse> {
  const payload = (await request.json().catch(() => null)) as {
    provider_subscription_id?: string;
    provider_payment_id?: string;
    signature?: string;
  } | null;
  if (
    !payload ||
    typeof payload.provider_subscription_id !== "string" ||
    typeof payload.provider_payment_id !== "string" ||
    typeof payload.signature !== "string"
  ) {
    return NextResponse.json({ detail: "Invalid checkout verification" }, { status: 400 });
  }
  const response = await sessionBackendRequest("/billing/checkout/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!response) {
    return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
  }
  return proxyBackendResponse(response);
}
