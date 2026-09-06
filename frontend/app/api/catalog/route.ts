import { NextRequest, NextResponse } from "next/server";

import { backendRequest } from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function GET(request: NextRequest): Promise<NextResponse> {
  const query = request.nextUrl.searchParams.get("q")?.trim() ?? "";
  if (query.length < 2) {
    return NextResponse.json({ detail: "Search must contain at least two characters" }, { status: 400 });
  }
  const encodedQuery = new URLSearchParams({ q: query, limit: "12" });
  const kind = request.nextUrl.searchParams.get("kind") === "vendors" ? "vendors" : "products";
  return proxyBackendResponse(await backendRequest(`/catalog/${kind}?${encodedQuery}`));
}
