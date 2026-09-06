import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "CVE Monitor",
  description: "Plain-language vulnerability monitoring for your software watchlist"
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
