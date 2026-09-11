"use client";
import { useState } from "react";

const frameworkSetup = {
  "React / Next.js": {
    file: "frontend/app/dashboard/integration-demo/page.jsx (inside this repository)",
    steps: "Use the existing Next.js application and its BFF. Save the example as a .jsx client page; it redirects on an API 401. For a protected page, wrap the client in a server page using the existing currentSession check. Start the complete stack with the local runner below, sign in, then open /dashboard/integration-demo. Do not run a second Next server on the same port.",
    install: "npm --prefix frontend ci",
  },
  "Vue 3": {
    file: "src/App.vue in a separate Vue client project",
    steps: "Create the client outside the cveator repository, replace App.vue with the example, then run npm install and npm run build. Serve the build under a dedicated path on the same origin as cveator; configure Vite's base path to match. Keep /api/*, /login, /register, /dashboard and /_next/* routed to Next.js. A standalone Vite dev server is not authenticated automatically.",
    install: "npm create vite@latest cveator-vue -- --template vue\ncd cveator-vue\nnpm install",
  },
  "Angular": {
    file: "src/app/app.config.ts and src/app/vulnerability-api.service.ts",
    steps: "Create a separate Angular client. Merge provideHttpClient into the generated providers; do not replace existing router providers. Inject VulnerabilityApi into a component and subscribe with next/error handlers. Build with the base href matching your dedicated path, and serve under the same origin while retaining Next.js API and auth routes.",
    install: "npx @angular/cli new cveator-angular --standalone --routing --style=css\ncd cveator-angular",
  },
  "Python / FastAPI": {
    file: "integration.py on a trusted server (not in a browser bundle)",
    steps: "Install HTTPX in a virtual environment. Set CVEATOR_BACKEND_URL to the privately reachable FastAPI base URL and supply CVEATOR_EMAIL and CVEATOR_PASSWORD through your server secret store. Run python integration.py. Add bounded retries only for safe reads; reauthenticate on expiry and never log authentication responses.",
    install: "python -m venv .venv\n# Activate the environment for your shell, then:\npython -m pip install httpx",
  },
};

function FrameworkSetup({ name }: { name: keyof typeof frameworkSetup }) {
  const setup = frameworkSetup[name];
  return <div className="guide-callout"><h3>Set up {name}</h3><p className="guide-copy"><strong>Example location: </strong><code>{setup.file}</code></p><pre className="guide-code"><code>{setup.install}</code></pre><p className="guide-copy">{setup.steps}</p><p>Client scaffolding alone does not configure the reverse proxy. These are adaptation guides, not additional framework deployments shipped with cveator. Pin and test dependency versions in your integration’s lockfile.</p></div>;
}

export const frameworkExamples = {
  "React / Next.js": `// Client component on the same origin as cveator's /api routes.
"use client";
import { useState } from "react";
export default function Vulnerabilities() {
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  async function load() {
    setError("");
    try {
      const response = await fetch("/api/intelligence/cves?page_size=20", {
        credentials: "same-origin", cache: "no-store"
      });
      if (response.status === 401) { window.location.assign("/login"); return; }
      if (!response.ok) throw new Error("Request failed: " + response.status);
      setResult(await response.json());
    } catch (error) { setError(String(error)); }
  }
  return <section><button onClick={load}>Load CVEs</button>
    <p role="alert">{error}</p><pre>{JSON.stringify(result, null, 2)}</pre></section>;
}`,
  "Vue 3": `<!-- Same-origin Vue component. A separate Vite port is a different origin. -->
<script setup>
import { ref } from "vue";
const result = ref(null);
const error = ref("");
async function load() {
  error.value = "";
  try {
    const response = await fetch("/api/intelligence/cves?page_size=20", {
      credentials: "same-origin", cache: "no-store"
    });
    if (response.status === 401) { window.location.assign("/login"); return; }
    if (!response.ok) throw new Error("Request failed: " + response.status);
    result.value = await response.json();
  } catch (reason) { error.value = String(reason); }
}
</script>
<template><button @click="load">Load CVEs</button>
  <p role="alert">{{ error }}</p><pre>{{ result }}</pre></template>`,
  "Angular": `// app.config.ts: configure once.
import { ApplicationConfig } from "@angular/core";
import { provideHttpClient } from "@angular/common/http";
export const appConfig: ApplicationConfig = { providers: [provideHttpClient()] };

// vulnerability-api.service.ts
import { Injectable, inject } from "@angular/core";
import { HttpClient } from "@angular/common/http";
@Injectable({ providedIn: "root" })
export class VulnerabilityApi {
  private http = inject(HttpClient);
  list() {
    return this.http.get("/api/intelligence/cves", {
      params: { page: "1", page_size: "20", sort_by: "cvss_score", sort_order: "desc" }
    });
  }
}
// Subscribe in your component with next/error handlers.
// On 401, return to sign-in; on 402, show the plan-required state.
// Same-origin cookies are sent automatically. Do not read the HttpOnly token.`,
  "Python / FastAPI": `# Trusted server-side integration only. Dependency: httpx.
# CVEATOR_BACKEND_URL must use a private network or SSH tunnel.
# It is NOT the public website URL: Caddy does not publicly route /auth/*.
import os
import httpx

with httpx.Client(base_url=os.environ["CVEATOR_BACKEND_URL"], timeout=30) as client:
    login = client.post("/auth/login", json={
        "email": os.environ["CVEATOR_EMAIL"],
        "password": os.environ["CVEATOR_PASSWORD"],
    })
    login.raise_for_status()
    token = login.json()["access_token"]  # Keep in server memory; never log it.
    result = client.get("/intelligence/cves", params={"page_size": 20},
        headers={"Authorization": "Bearer " + token})
    result.raise_for_status()
    print("Matching CVEs:", result.json()["total"])
# Use an existing verified account. No API-key or refresh-token grant exists.
# In an async FastAPI route, use httpx.AsyncClient and await the calls.`,
};

export function IntegrationGuide() {
  const [tab, setTab] = useState<keyof typeof frameworkExamples>("React / Next.js");
  const [copied, setCopied] = useState("");
  return <div className="integration-guide">
    <nav className="detail-anchor-nav" aria-label="Documentation sections"><a href="#architecture">Architecture</a><a href="#authentication">Authentication</a><a href="#frameworks">Framework guides</a><a href="#deployment">Setup & deployment</a><a href="#api-endpoints">Endpoint reference</a></nav>
    <section id="architecture" className="panel detail-section"><p className="eyebrow">START HERE</p><h2>Two API surfaces. One trust boundary.</h2><p className="guide-copy">cveator uses a backend-for-frontend (BFF). The browser calls Next.js on its own origin; Next.js talks to the private FastAPI service. Browser and trusted-server integrations use different paths and authentication.</p><div className="auth-flow" aria-label="Request flow"><span>Browser<br /><strong>Same-origin cookie</strong></span><span>Next.js /api/*<br /><strong>Reads HttpOnly cookie</strong></span><span>FastAPI<br /><strong>Bearer JWT + database checks</strong></span></div><div className="guide-table-wrap"><table className="guide-table"><thead><tr><th>Surface</th><th>Example path</th><th>Authentication</th><th>Audience</th></tr></thead><tbody><tr><td>Web BFF</td><td>/api/intelligence/cves</td><td>Browser session cookie</td><td>Same-origin UI</td></tr><tr><td>Private FastAPI</td><td>/intelligence/cves</td><td>Authorization: Bearer JWT</td><td>Trusted server / operator</td></tr></tbody></table></div><p className="guide-callout">No public API-key product, OAuth flow, refresh-token endpoint, or cross-origin browser integration is implemented. Do not point a separate frontend at port 8002 and assume CORS or cookies will work.</p></section>
    <section id="authentication" className="panel detail-section"><h2>Authentication lifecycle</h2><ol className="guide-steps"><li><strong>Request a signup code.</strong> POST /api/session/register with organization_name, email and a password of at least 12 characters. The 202 response contains a challenge ID, not a session. The password is hashed; no user or trial exists yet.</li><li><strong>Verify email ownership.</strong> POST /api/session/register/verify with the latest challenge_id and six-digit code. The BFF returns 200 (private backend: 201), creates the account and starts the 72-hour trial. Resend rotates the challenge without resetting guesses or changing the password hash.</li><li><strong>Keep tokens server-side.</strong> FastAPI issues an HS256 JWT; Next.js puts it in a Secure, HttpOnly, SameSite=Lax, path=/ cookie in production. Browser response JSON contains no token. Do not store JWTs or passwords in localStorage.</li><li><strong>Validate every authenticated request.</strong> FastAPI verifies signature, issuer, audience, expiry and required claims. It reloads the user to check activity, organization and token version. Endpoint roles and monitoring entitlement are then checked.</li><li><strong>Handle expiration.</strong> Tokens default to 30 minutes (JWT_ACCESS_TOKEN_MINUTES). There is no refresh token or sliding session. On 401, sign in again rather than repeatedly retrying.</li><li><strong>Understand sign-out.</strong> DELETE /api/session clears this browser’s cookie; it does not revoke a copied JWT elsewhere. Account deletion removes the user, invalidating all tokens on subsequent database checks.</li></ol><p className="guide-copy">Login remains email + password. Signup OTP is not passwordless login or MFA. Signup and deletion codes are purpose-bound, valid for ten minutes and single-use, with five sends/guesses per hour and a 60-second resend cooldown.</p><p className="guide-callout">State-changing browser requests must pass same-origin checks. PUBLIC_APP_URL must match the actual browser origin. An organization owner is not automatically the application administrator, and a valid login does not bypass the monitoring trial limit.</p></section>
    <section id="frameworks" className="panel detail-section"><h2>Framework integration guides</h2><p className="guide-copy">Read-only starter examples, not complete replacement apps. For React, Vue and Angular, serve your UI and cveator’s BFF under one HTTPS origin while retaining /api/* and the auth pages. A separate development port needs deliberate reverse-proxy configuration; credentials: include does not add CORS support.</p><div className="guide-tabs" role="group" aria-label="Framework examples">{Object.keys(frameworkExamples).map(name => <button key={name} type="button" className="button button-small" aria-pressed={tab===name} onClick={() => {setTab(name as keyof typeof frameworkExamples);setCopied("");}}>{name}</button>)}</div><FrameworkSetup name={tab} /><div className="guide-code-heading"><strong>{tab}</strong><button className="text-button" type="button" onClick={async () => {try {await navigator.clipboard.writeText(frameworkExamples[tab]);setCopied("Copied");} catch {setCopied("Select and copy the code manually");}}}>Copy example</button><span role="status">{copied}</span></div><pre className="guide-code framework-example"><code>{frameworkExamples[tab]}</code></pre><p className="source-note">Setup references: <a href="https://vite.dev/guide/" target="_blank" rel="noopener noreferrer">Vite setup</a> · <a href="https://angular.dev/tools/cli/setup-local" target="_blank" rel="noopener noreferrer">Angular setup</a>. API references: <a href="https://react.dev/reference/react/useState" target="_blank" rel="noopener noreferrer">React</a> · <a href="https://vuejs.org/guide/essentials/reactivity-fundamentals.html" target="_blank" rel="noopener noreferrer">Vue</a> · <a href="https://angular.dev/guide/http/setup" target="_blank" rel="noopener noreferrer">Angular</a> · <a href="https://www.python-httpx.org/async/" target="_blank" rel="noopener noreferrer">HTTPX</a></p></section>
    <section id="deployment" className="panel detail-section"><h2>Setup & deployment</h2><div className="guide-table-wrap"><table className="guide-table"><thead><tr><th>Environment</th><th>Application</th><th>Backend</th></tr></thead><tbody><tr><td>Local runner</td><td>http://localhost:3002</td><td>http://127.0.0.1:8002</td></tr><tr><td>Docker Compose</td><td>http://localhost:3000</td><td>Internal api:8000</td></tr><tr><td>Production</td><td>PUBLIC_APP_URL on HTTPS</td><td>Private network; API_INTERNAL_BASE_URL</td></tr></tbody></table></div><pre className="guide-code"><code>{`# Local: Python 3.12+, Node.js, Docker
python -m pip install -e "./backend[dev]"
npm --prefix frontend ci
python scripts/run_local.py --full --no-demo --enable-email

# Production: configure .env.production on your VPS first.
# Complete domain, SMTP/DKIM and payment configuration; rotate secrets.
python3 scripts/deploy.py --production --env-file .env.production`}</code></pre><p className="guide-copy">Keep JWT_SECRET, database, SMTP and payment credentials on the server—never in NEXT_PUBLIC_* or frontend bundles. Production requires HTTPS and secure cookies. Set APPLICATION_ADMIN_USER_ID to your intended production account UUID.</p><ul className="guide-steps"><li>Test SMTP inbox delivery, not just connectivity. PUBLIC_APP_URL controls the OTP return link.</li><li>Verify payment webhook activation and duplicate-event handling; a checkout signature alone does not activate access.</li><li>Schedule encrypted off-host backups and test restore. Deployment does not automatically roll back migrations.</li><li>Keep PostgreSQL and Redis private. The default edge exposes web traffic, health checks and payment webhooks, not /auth/* as a public integration API.</li><li>Run browser/database regressions and load-test searches with ingestion running before promising capacity.</li></ul><h3>Troubleshooting</h3><p className="guide-copy">401: sign in again. 402: monitoring plan required. 403: role or origin rejection. 429: wait for the cooldown. Email but no OTP form: use its return link. No OTP: check spam, sender authentication and SMTP errors. Never disable verification or tenant checks to fix integration issues.</p></section>
  </div>;
}
