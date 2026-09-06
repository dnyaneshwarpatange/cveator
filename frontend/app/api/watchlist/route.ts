import { NextRequest, NextResponse } from "next/server";

import { sessionBackendRequest } from "@/lib/backend";
import { proxyBackendResponse } from "@/lib/backend-response";

export async function GET(): Promise<NextResponse> {
  const response = await sessionBackendRequest("/watchlist");
  if (!response) {
    return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
  }
  return proxyBackendResponse(response);
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  const payload = (await request.json().catch(() => null)) as { product_id?: number } | null;
  if (
    !payload ||
    typeof payload.product_id !== "number" ||
    !Number.isInteger(payload.product_id) ||
    payload.product_id <= 0
  ) {
    return NextResponse.json({ detail: "Invalid product" }, { status: 400 });
  }
  const productId = payload.product_id;
  const response = await sessionBackendRequest("/watchlist", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ product_id: productId })
  });
  if (!response) {
    return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
  }
  return proxyBackendResponse(response);
}

export async function DELETE(request: NextRequest): Promise<NextResponse> {
  const productId = Number(request.nextUrl.searchParams.get("product_id"));
  if (!Number.isInteger(productId) || productId <= 0) {
    return NextResponse.json({ detail: "Invalid product" }, { status: 400 });
  }
  const response = await sessionBackendRequest(`/watchlist/${productId}`, { method: "DELETE" });
  if (!response) {
    return NextResponse.json({ detail: "Not authenticated" }, { status: 401 });
  }
  return proxyBackendResponse(response);
}
