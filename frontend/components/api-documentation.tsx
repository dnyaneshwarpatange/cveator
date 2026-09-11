"use client";
import { useState } from "react";
import { apiReference } from "@/lib/api-reference";
import { IntegrationGuide } from "@/components/integration-guide";

export function ApiDocumentation() {
  const [query, setQuery] = useState("");
  const endpoints = apiReference.filter(item => `${item.method} ${item.path} ${item.group} ${item.description}`.toLowerCase().includes(query.toLowerCase()));
  return <>
    <IntegrationGuide />
    <h2 id="api-endpoints" className="text-2xl font-semibold mt-8">Endpoint reference</h2>
    <section className="panel p-6 mt-6 space-y-4">
      <h2>Using the application API</h2>
      <p>This reference describes the same-origin <code>/api/*</code> routes used by the web application—not a public API-key service. Requests use your signed-in browser session. No API keys are currently issued.</p>
      <p>Send JSON with <code>Content-Type: application/json</code>. State-changing requests must come from the application origin. Tokens stay in HttpOnly cookies; do not copy passwords, OTPs or cookies into public tools. There are no destructive “try it” buttons here.</p>
      <h3>Signup sequence</h3><p>Request code → verify latest code → session cookie → dashboard. Resend returns a new challenge ID. Refreshing signup restores verification in the same tab without retaining the password.</p>
      <h3>Read-only example in the signed-in application</h3>
      <pre className="overflow-x-auto rounded bg-slate-100 p-4 text-sm"><code>{'const response = await fetch("/api/intelligence/cves?q=authentication&sort_by=cvss_score&sort_order=desc&page=1&page_size=20", { credentials: "same-origin" });\nif (!response.ok) throw new Error(`HTTP ${response.status}`);\nconst results = await response.json();'}</code></pre>
      <h3>Errors</h3><p>400 invalid request/code · 401 sign in again · 402 monitoring trial ended · 403 insufficient permission · 404 not found · 409 account/ownership conflict · 422 invalid fields · 429 wait before retrying · 503 temporarily unavailable. Errors normally contain a <code>detail</code> string or validation list. A timed-out write may have completed: check state before retrying.</p>
      <h3>Vulnerability response contract</h3>
      <p>Lists return <code>{"{items, total, page, page_size}"}</code>. Pages start at 1; page_size is capped at 100. Filters and sorting apply before pagination. Results can change while ingestion runs, so offset pagination is not a frozen export. Scores and timestamps may be null; never replace unknown scores with zero.</p>
      <p>Details add <code>normalized</code> (description, CVSS vectors, affected version conditions, weaknesses and references), <code>decision_evidence</code> (published solutions, workarounds, exploit notes, EPSS score date and exploitation-catalog context), and up to 100 observed <code>history</code> entries. Empty evidence arrays mean “not recorded,” not “no risk.” Internal provenance fields are omitted for ordinary accounts; clients must not require them.</p>
      <p>CVSS ranges from 0–10; EPSS is a probability from 0–1, not a percentage or percentile. Dates use ISO 8601; preserve timezone offsets. Treat upstream text as untrusted plain text and allow only HTTP(S) advisory links. CVE applicability and a confirmed fixed release require review of your installed version and vendor guidance.</p>
    </section>
    <label className="block mt-6">Search endpoints<input className="block w-full border rounded p-3 mt-2" type="search" value={query} onChange={e => setQuery(e.target.value)} placeholder="e.g. OTP, billing, CVE, DELETE" /></label>
    <p className="muted mt-3" role="status">{endpoints.length} endpoints</p>
    {endpoints.map(item => <details className="panel p-5 mt-3" key={`${item.method} ${item.path}`}>
      <summary className="cursor-pointer break-words"><strong className="mr-3">{item.method}</strong><code>{item.path}</code><span className="ml-3 muted">{item.group}</span></summary>
      <div className="mt-4 space-y-3"><p>{item.description}</p><p><strong>Access: </strong>{item.access}</p><h3>Request</h3><pre className="whitespace-pre-wrap break-words rounded bg-slate-100 p-3 text-sm">{item.input}</pre><p><strong>Response: </strong>{item.response}</p></div>
    </details>)}
    {!endpoints.length && <p className="mt-4">No matching endpoints. Try a method or feature name.</p>}
  </>;
}
