import { NextRequest, NextResponse } from "next/server";
import { sessionBackendRequest } from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function GET(request: NextRequest) {
  const query = new URLSearchParams();
  for (const key of ["q", "vendor", "product", "kev", "min_cvss", "min_epss", "page", "page_size", "sort_by", "sort_order"]) {
    const value = request.nextUrl.searchParams.get(key);
    if (value) query.set(key, value);
  }
  try {
    const response = await sessionBackendRequest(`/intelligence/cves?${query}`, {
      signal: AbortSignal.timeout(60_000)
    });
    if (!response) return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
    return await proxyBackendResponse(response);
  } catch {
    return NextResponse.json({ detail: "Search is taking too long or is temporarily unavailable. Try a narrower search." }, { status: 503 });
  }
}
