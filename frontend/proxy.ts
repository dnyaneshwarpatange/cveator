import { NextRequest, NextResponse } from "next/server";

const safeMethods = new Set(["GET", "HEAD", "OPTIONS"]);

export function proxy(request: NextRequest): NextResponse {
  if (safeMethods.has(request.method)) {
    return NextResponse.next();
  }

  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite === "cross-site") {
    return NextResponse.json({ detail: "Cross-site request rejected" }, { status: 403 });
  }

  const origin = request.headers.get("origin");
  const configuredOrigin = process.env.PUBLIC_APP_URL;
  const expectedOrigin = configuredOrigin
    ? new URL(configuredOrigin).origin
    : request.nextUrl.origin;
  if (origin && origin !== expectedOrigin) {
    return NextResponse.json({ detail: "Request origin rejected" }, { status: 403 });
  }
  return NextResponse.next();
}

export const config = {
  matcher: "/api/:path*"
};
