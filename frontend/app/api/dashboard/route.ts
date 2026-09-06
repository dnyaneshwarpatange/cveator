import { NextResponse } from "next/server";

import { sessionBackendRequest } from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function GET(): Promise<NextResponse> {
  const response = await sessionBackendRequest("/alerts/dashboard/overview");
  if (!response) {
    return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
  }
  return proxyBackendResponse(response);
}
