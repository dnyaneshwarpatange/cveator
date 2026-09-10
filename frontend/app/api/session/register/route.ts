import { NextRequest } from "next/server";
import { backendRequest } from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function POST(request: NextRequest) {
  return proxyBackendResponse(await backendRequest("/auth/register", {
    method: "POST", headers: { "content-type": "application/json" },
    signal: AbortSignal.timeout(60000),
    body: await request.text()
  }));
}
