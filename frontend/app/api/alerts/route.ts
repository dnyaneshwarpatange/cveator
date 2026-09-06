import { NextRequest, NextResponse } from "next/server";

import { sessionBackendRequest } from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function GET(request: NextRequest): Promise<NextResponse> {
  const query = request.nextUrl.searchParams;
  const allowed = new URLSearchParams();
  for (const key of ["status", "severity", "page", "page_size"]) {
    const value = query.get(key);
    if (value) {
      allowed.set(key, value);
    }
  }
  const suffix = allowed.size ? `?${allowed}` : "";
  const response = await sessionBackendRequest(`/alerts${suffix}`);
  if (!response) {
    return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
  }
  return proxyBackendResponse(response);
}

export async function PATCH(request: NextRequest): Promise<NextResponse> {
  const payload = (await request.json().catch(() => null)) as {
    alert_id?: number;
    status?: string;
  } | null;
  if (!payload || !Number.isInteger(payload.alert_id) || typeof payload.status !== "string") {
    return NextResponse.json({ detail: "Invalid alert update" }, { status: 400 });
  }
  const response = await sessionBackendRequest(`/alerts/${payload.alert_id}`, {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ status: payload.status })
  });
  if (!response) {
    return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
  }
  return proxyBackendResponse(response);
}
