import { NextResponse } from "next/server";

export async function proxyBackendResponse(response: Response): Promise<NextResponse> {
  if ([204, 205, 304].includes(response.status)) {
    return new NextResponse(null, { status: response.status });
  }
  const text = await response.text();
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return NextResponse.json(text ? JSON.parse(text) : null, { status: response.status });
  }
  return new NextResponse(text, {
    status: response.status,
    headers: { "content-type": contentType || "text/plain; charset=utf-8" }
  });
}
