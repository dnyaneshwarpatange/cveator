"use client";

export default function ErrorPage({ reset }: { reset: () => void }) {
  return <main className="empty-state min-h-screen justify-center"><span className="eyebrow">CVE MONITOR</span><h1 className="mt-4 text-2xl font-semibold">Your workspace is temporarily unavailable</h1><p>We couldn’t connect to the service. Please try again in a moment.</p><button className="button button-primary" type="button" onClick={reset}>Try again</button><a className="text-button mt-4" href="/login">Return to sign in</a></main>;
}
