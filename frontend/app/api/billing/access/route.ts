import { NextResponse } from "next/server";
import { sessionBackendRequest } from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function GET(): Promise<NextResponse> {
  const response = await sessionBackendRequest("/billing/access");
  return response ? proxyBackendResponse(response) : NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
}
