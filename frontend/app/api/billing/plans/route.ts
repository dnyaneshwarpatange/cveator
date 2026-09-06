import { NextResponse } from "next/server";

import { sessionBackendRequest } from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function GET(): Promise<NextResponse> {
  const response = await sessionBackendRequest("/billing/plans");
  if (!response) {
    return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
  }
  return proxyBackendResponse(response);
}
