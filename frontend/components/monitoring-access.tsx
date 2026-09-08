"use client";

import { useEffect, useState } from "react";
import { requestJson } from "@/lib/api-client";

export function MonitoringAccess() {
  const [access, setAccess] = useState<{status: string; trial_ends_at: string | null} | null>(null);
  const [error, setError] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    const refresh = () => requestJson<{status: string; trial_ends_at: string | null}>("/api/billing/access", { signal: controller.signal })
      .then(value => { setAccess(value); setError(false); })
      .catch(() => { if (!controller.signal.aborted) setError(true); });
    void refresh();
    const timer = setInterval(() => void refresh(), 20_000);
    return () => { controller.abort(); clearInterval(timer); };
  }, []);
  if (error) return <p role="status">Unable to check monitoring access. Please refresh.</p>;
  if (!access) return <p role="status">Checking trial and plan status…</p>;
  if (access.status === "active") return <p role="status">Paid monitoring is active.</p>;
  return <div className="message" role="status"><span>{access.status === "trial"
    ? `3-day free trial. Monitoring is free until ${new Date(access.trial_ends_at!).toLocaleString()}. A paid plan is required after that.`
    : "Your 3-day free trial has ended. Software monitoring and alert emails are paused until payment is confirmed."}</span><a href="/dashboard?view=billing" className="text-button">Choose a plan</a></div>;
}
