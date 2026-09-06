import { NextRequest, NextResponse } from "next/server";
import { sessionBackendRequest } from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function GET(request: NextRequest) {
  const query = new URLSearchParams();
  for (const key of ["q", "vendor", "product", "kev", "min_cvss", "min_epss", "page", "page_size"]) {
    const value = request.nextUrl.searchParams.get(key);
    if (value) query.set(key, value);
  }
  const response = await sessionBackendRequest(`/intelligence/cves?${query}`);
  if (!response) return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
  return proxyBackendResponse(response);
}
