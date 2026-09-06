import { NextResponse } from "next/server";
import { sessionBackendRequest } from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function GET(_request: Request, { params }: { params: Promise<{ cveId: string }> }) {
  const { cveId } = await params;
  if (!/^CVE-\d{4}-\d{4,}$/i.test(cveId)) return NextResponse.json({ detail: "Invalid CVE identifier" }, { status: 400 });
  const response = await sessionBackendRequest(`/intelligence/cves/${encodeURIComponent(cveId)}`);
  if (!response) return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
  return proxyBackendResponse(response);
}
