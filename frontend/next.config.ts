import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  // Repeated Windows preview restarts have restored stale route entries.
  // Use fresh development compilations there; production build caching is unchanged.
  experimental: { turbopackFileSystemCacheForDev: process.platform !== "win32" },
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=()"
          }
        ]
      }
    ];
  }
};

export default nextConfig;
