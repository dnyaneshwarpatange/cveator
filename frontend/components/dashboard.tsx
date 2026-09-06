"use client";

import { FormEvent, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { BillingPanel } from "@/components/billing-panel";
import { DataStatus, useIntelligenceStatus, VulnerabilityExplorer } from "@/components/intelligence";
import { productVersionLabel } from "@/lib/product-label";
import { Icon } from "@/components/icon";
import { ApiError, requestJson } from "@/lib/api-client";
import type { Alert, AlertPage, AlertStatus, BillingSnapshot, DashboardOverview, Product, SessionUser, Severity } from "@/lib/types";

export type DashboardView = "overview" | "software" | "intelligence" | "billing";
const navigation = [
  { id: "overview", label: "Overview", icon: "grid" },
  { id: "software", label: "Software subscriptions", icon: "software" },
  { id: "intelligence", label: "Vulnerability database", icon: "search" },
  { id: "billing", label: "Plan & billing", icon: "card" }
] as const;

export function Dashboard({ billing, user, initialView = "overview" }: { billing: BillingSnapshot; user: SessionUser; initialView?: DashboardView }) {
  const router = useRouter();
  const [view, setView] = useState<DashboardView>(initialView);
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [alerts, setAlerts] = useState<AlertPage | null>(null);
  const [watchlist, setWatchlist] = useState<Product[]>([]);
  const [severity, setSeverity] = useState<Severity | "">("");
  const [status, setStatus] = useState<AlertStatus | "">("new");
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [searchKind, setSearchKind] = useState<"products" | "vendors">("products");
  const [results, setResults] = useState<Product[]>([]);
  const [searched, setSearched] = useState(false);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [removed, setRemoved] = useState<Product | null>(null);
  const searchRequest = useRef(0);
  const mutationLock = useRef(false);
  const canEdit = user.role !== "viewer";
  const canManageBilling = user.role === "owner" || user.role === "admin";
  const intelligence = useIntelligenceStatus(revision);

  useEffect(() => {
    const interval = setInterval(() => setRevision((value) => value + 1), 20_000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const params = new URLSearchParams({ page: String(page), page_size: "10" });
    if (severity) params.set("severity", severity);
    if (status) params.set("status", status);
    Promise.all([
      requestJson<DashboardOverview>("/api/dashboard", { signal: controller.signal }),
      requestJson<AlertPage>(`/api/alerts?${params}`, { signal: controller.signal }),
      requestJson<Product[]>("/api/watchlist", { signal: controller.signal })
    ]).then(([nextOverview, nextAlerts, nextWatchlist]) => {
      if (controller.signal.aborted) return;
      if (page > 1 && nextAlerts.items.length === 0) { setPage(page - 1); return; }
      setOverview(nextOverview); setAlerts(nextAlerts); setWatchlist(nextWatchlist); setError(null);
    }).catch((reason: unknown) => {
      if (controller.signal.aborted) return;
      if (reason instanceof ApiError && reason.status === 401) { router.replace("/login"); return; }
      setError(reason instanceof Error ? reason.message : "We couldn’t load your workspace.");
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [page, severity, status, revision, router]);

  function refresh() { setLoading(true); setRevision((value) => value + 1); }
  function filter(nextSeverity: Severity | "", nextStatus: AlertStatus | "") {
    setLoading(true); setPage(1); setSeverity(nextSeverity); setStatus(nextStatus);
    setRevision((value) => value + 1);
  }
  async function mutate(key: string, operation: () => Promise<unknown>, success: string) {
    if (mutationLock.current) return;
    mutationLock.current = true; setBusy(key); setError(null); setNotice(null); setRemoved(null);
    try { await operation(); setNotice(success); refresh(); }
    catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) router.replace("/login");
      else setError(reason instanceof Error ? reason.message : "The change couldn’t be saved.");
    } finally { mutationLock.current = false; setBusy(null); }
  }
  async function searchCatalog(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const query = search.trim();
    if (query.length < 2) { setSearchError("Enter at least two characters."); return; }
    const current = ++searchRequest.current;
    setSearching(true); setSearchError(null); setSearched(false); setResults([]);
    try {
      const products = await requestJson<Product[]>(`/api/catalog?kind=${searchKind}&q=${encodeURIComponent(query)}`);
      if (current === searchRequest.current) { setResults(products); setSearched(true); }
    } catch (reason) {
      if (current === searchRequest.current) setSearchError(reason instanceof Error ? reason.message : "Search is unavailable.");
    } finally { if (current === searchRequest.current) setSearching(false); }
  }
  async function signOut() {
    if (mutationLock.current) return;
    mutationLock.current = true; setBusy("logout");
    try { await requestJson("/api/session", { method: "DELETE" }); router.replace("/login"); router.refresh(); }
    catch { setError("Sign out didn’t complete. Please try again."); }
    finally { mutationLock.current = false; setBusy(null); }
  }
  function add(product: Product) {
    void mutate(`product-${product.id}`, async () => {
      await requestJson("/api/watchlist", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ product_id: product.id }) });
      setRemoved(null);
    }, `${product.product_name} is subscribed. Historical vulnerabilities are loading in the background; alerts will appear as matching completes.`);
  }

  const title = view === "overview" ? "Your security, at a glance." : view === "software" ? "Subscribe to your software." : view === "intelligence" ? "Explore the vulnerability database." : "Your plan. Your control.";
  return <div className="app-shell">
    <a href="#main-content" className="skip-link">Skip to content</a>
    <aside className="sidebar">
      <a href="/dashboard" className="brand"><span className="brand-mark"><Icon name="shield" size={25} /></span><span>CVE Monitor<small>STAY ONE STEP AHEAD</small></span></a>
      <div className="workspace-label"><span className="workspace-avatar">{user.email.slice(0, 1).toUpperCase()}</span><span>Your workspace<small className="capitalize">{user.role} access</small></span></div>
      <nav aria-label="Main navigation">{navigation.map((item) => <button key={item.id} type="button" className={`nav-item ${view === item.id ? "active" : ""}`} aria-current={view === item.id ? "page" : undefined} onClick={() => { setView(item.id); window.history.replaceState(null, "", `/dashboard?view=${item.id}`); }}><Icon name={item.icon} />{item.label}{item.id === "overview" && !!overview?.active_alerts && <span className="nav-count">{overview.active_alerts}</span>}</button>)}</nav>
      <div className="sidebar-note"><Icon name="shield" /><p>Clarity over complexity.</p><small>The vulnerabilities that matter to your business, with a clear next step.</small></div>
      <div className="account"><div><strong title={user.email}>{user.email}</strong><small className="capitalize">{user.role}</small></div><button className="icon-button" type="button" aria-label="Sign out" title="Sign out" disabled={!!busy} onClick={() => void signOut()}><Icon name="logout" /></button></div>
    </aside>
    <main id="main-content" className="main-content">
      <header className="topbar"><span>Workspace <span className="breadcrumb-slash">/</span> <strong>{navigation.find((item) => item.id === view)?.label}</strong></span><span className="topbar-note"><Icon name="shield" size={16} /> Software risk monitoring</span></header>
      <div className="page-content">
        <div className="page-heading"><div><p className="eyebrow">A LITTLE VISIBILITY. A LOT MORE CONFIDENCE.</p><h1>{title}</h1><p>{view === "overview" ? "Focus on what needs your attention. We’ll help you find the next step." : view === "software" ? "Follow product families across all versions and review the source’s affected-version details." : view === "intelligence" ? "Search public vulnerability records, risk signals, references and recorded changes." : "Manage your subscription and keep your team covered."}</p></div><button className="button button-secondary" disabled={loading} onClick={refresh} type="button"><Icon name="refresh" size={16} className={loading ? "spin" : undefined} />{loading ? "Refreshing…" : "Refresh"}</button></div>
        {error && <div className="message message-error" role="alert"><Icon name="warning" /><span>{error}</span><button type="button" onClick={refresh}>Try again</button></div>}
        {notice && <div className="message message-success" role="status"><Icon name="check" /><span>{notice}</span>{removed && <button type="button" disabled={!!busy} onClick={() => add(removed)}>Undo</button>}<button className="icon-button" type="button" aria-label="Dismiss notification" onClick={() => { setNotice(null); setRemoved(null); }}><Icon name="close" size={16} /></button></div>}
        {view !== "billing" && <DataStatus data={intelligence.data} error={intelligence.error} />}
        {view === "intelligence" && <VulnerabilityExplorer revision={revision} />}
        {view === "overview" && <>
          <section className="metric-grid" aria-label="Security summary">
            <Metric label="Needs review" value={overview?.active_alerts} caption="New, unread alerts" icon="bell" selected={!severity && status === "new"} onClick={() => filter("", "new")} />
            <Metric label="Critical severity" value={overview?.critical_alerts} caption="New alerts · CVSS 9+ or known exploited" icon="warning" danger onClick={() => filter("critical", "new")} selected={severity === "critical" && status === "new"} />
            <Metric label="Known exploited" value={overview?.kev_alerts} caption="New alerts · confirmed in the wild" icon="shield" danger />
            <Metric label="Software tracked" value={overview?.watched_products} caption="Products on your watchlist" icon="software" onClick={() => setView("software")} />
          </section>
          <div className="overview-grid"><section className="panel alert-panel" aria-labelledby="alerts-heading">
            <div className="panel-heading"><div><h2 id="alerts-heading">Your alert inbox <span className="count-pill">{alerts?.total ?? "—"}</span></h2><p>Known exploitation first, then severity.</p></div><span className="section-kicker">ACTION CENTER</span></div>
            <div className="filter-bar"><div className="segmented" aria-label="Alert status">{(["new", "read", "dismissed", ""] as const).map((value) => <button key={value} type="button" aria-pressed={status === value} className={status === value ? "selected" : ""} onClick={() => filter(severity, value)}>{value === "" ? "All" : value === "new" ? "Needs review" : value === "read" ? "Reviewed" : "Dismissed"}</button>)}</div><label className="filter-select"><span className="sr-only">Severity</span><select aria-label="Severity" value={severity} onChange={(event) => filter(event.target.value as Severity | "", status)}><option value="">All severities</option>{["critical", "high", "medium", "low", "unknown"].map((value) => <option key={value} value={value}>{value === "unknown" ? "Unscored" : value.charAt(0).toUpperCase() + value.slice(1)}</option>)}</select></label></div>
            <div className="alert-list" aria-busy={loading}>
              {loading ? <div className="loading-state" role="status"><span className="loader" />Loading your alerts…</div> : alerts?.items.length ? alerts.items.map((alert) => <AlertCard key={alert.id} alert={alert} canEdit={canEdit} busy={!!busy} onStatus={(nextStatus) => void mutate(`alert-${alert.id}`, () => requestJson("/api/alerts", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ alert_id: alert.id, status: nextStatus }) }), nextStatus === "new" ? "Alert returned to your inbox." : nextStatus === "read" ? "Alert marked as reviewed." : "Alert dismissed. You can restore it from Dismissed.")} />) : <div className="empty-state"><span className="empty-icon"><Icon name="check" size={28} /></span><h3>{error ? "Your inbox is unavailable" : watchlist.length ? "Nothing here needs your attention" : "Start with the software you use"}</h3><p>{error ? "Retry when your connection is restored." : watchlist.length ? "No alerts match this view. Check another filter or return after the next data update." : "Add your first product to start seeing relevant security alerts."}</p><button className="button button-secondary" type="button" onClick={() => watchlist.length ? filter("", "") : setView("software")}>{watchlist.length ? "View all alerts" : "Add software"}<Icon name="arrow" size={16} /></button></div>}
            </div>
            {!!alerts?.total && <footer className="pagination"><span>{Math.min((page - 1) * 10 + 1, alerts.total)}–{Math.min(page * 10, alerts.total)} of {alerts.total} alerts</span><div><button type="button" className="icon-button" aria-label="Previous page" disabled={loading || page === 1} onClick={() => { setLoading(true); setPage(page - 1); }}><Icon name="chevron" size={16} style={{ transform: "rotate(180deg)" }} /></button><span>Page {page}</span><button type="button" className="icon-button" aria-label="Next page" disabled={loading || page * 10 >= alerts.total} onClick={() => { setLoading(true); setPage(page + 1); }}><Icon name="chevron" size={16} /></button></div></footer>}
          </section><aside className="context-column"><section className="priority-note"><span className="eyebrow">WHERE TO START</span><h2>{overview?.kev_alerts ? "Active exploitation comes first." : "A small routine. A stronger business."}</h2><p>{overview?.kev_alerts ? "Review the alerts marked ‘Known exploited’. These vulnerabilities have been used in real attacks." : "Review new alerts, check the vendor’s guidance, and keep your software watchlist current."}</p><div className="note-divider" /><span><Icon name="check" size={17} /> Review the affected version</span><span><Icon name="check" size={17} /> Check the vendor’s update</span><span><Icon name="check" size={17} /> Schedule and verify the patch</span></section><section className="panel compact-panel"><div className="panel-heading"><h2>Your software</h2><span className="count-pill">{watchlist.length}</span></div>{watchlist.slice(0, 4).map((product) => <div className="software-preview" key={product.id}><span className="product-avatar">{product.vendor.charAt(0).toUpperCase()}</span><div><strong>{product.product_name}</strong><small>{product.vendor} · {productVersionLabel(product)}</small></div></div>)}{!watchlist.length && <p className="muted">Your watchlist is empty.</p>}<button className="text-button" type="button" onClick={() => setView("software")}>Manage watchlist<Icon name="arrow" size={16} /></button></section><p className="source-note">Risk signals from NVD, the CVE Program, CISA KEV and FIRST EPSS. Always confirm your installed version before taking action.</p></aside></div>
        </>}
        {view === "software" && <div className="software-layout"><section className="panel"><div className="panel-heading"><div><h2>Software watchlist <span className="count-pill">{watchlist.length}</span></h2><p>Keep this list aligned with what your team runs.</p></div></div><div className="watchlist-body">{!watchlist.length && <div className="empty-state"><Icon name="software" size={36} /><h3>Your watchlist starts here</h3><p>Search for a product family to follow vulnerabilities across all versions.</p></div>}{watchlist.map((product) => <article className="watchlist-row" key={product.id}><span className="product-avatar"><Icon name="software" /></span><div><h3>{product.product_name}</h3><p>{product.vendor} <span>·</span> {productVersionLabel(product)}</p>{intelligence.data?.product_syncs.find((item) => item.product_id === product.id)?.error && <p className="search-error">Historical import needs attention. {intelligence.data?.product_syncs.find((item) => item.product_id === product.id)?.error}</p>}</div><span className="tracking-badge"><span />{(() => { const sync = intelligence.data?.product_syncs.find((item) => item.product_id === product.id); return sync?.status === "failed" ? "Import failed" : sync && ["pending", "queued", "running", "syncing"].includes(sync.status) ? "Importing CVEs…" : "Subscribed"; })()}</span>{canEdit && <button className="icon-button remove-button" type="button" aria-label={`Stop tracking ${product.product_name}`} disabled={!!busy} onClick={() => void mutate(`remove-${product.id}`, async () => { await requestJson(`/api/watchlist?product_id=${product.id}`, { method: "DELETE" }); setRemoved(product); }, `${product.product_name} removed from your watchlist.`)}><Icon name="close" size={17} /></button>}</article>)}</div></section><section className="panel search-panel"><span className="empty-icon"><Icon name="plus" size={25} /></span><h2>Add a subscription</h2><p>Follow a product family across all versions, or subscribe to every product from a vendor. Check affected versions on each vulnerability record.</p>{canEdit ? <><form onSubmit={(event) => void searchCatalog(event)}><div className="segmented catalog-kind" aria-label="Subscription type">{(["products", "vendors"] as const).map((kind) => <button key={kind} type="button" className={searchKind === kind ? "selected" : ""} aria-pressed={searchKind === kind} onClick={() => { searchRequest.current++; setSearchKind(kind); setResults([]); setSearched(false); setSearching(false); }}>{kind === "products" ? "Products" : "Vendors · all products"}</button>)}</div><label htmlFor="software-search">{searchKind === "products" ? "Product name" : "Vendor name"}</label><div className="search-input"><Icon name="search" size={18} /><input id="software-search" name="software" value={search} onChange={(event) => { searchRequest.current++; setSearch(event.target.value); setSearched(false); setResults([]); setSearching(false); }} placeholder={searchKind === "products" ? "e.g. Jira, Windows, Chrome…" : "e.g. Atlassian, Microsoft…"} autoComplete="off" minLength={2} maxLength={100} required /></div><button className="button button-primary" disabled={searching} type="submit">{searching ? "Searching…" : searchKind === "products" ? "Find products" : "Find vendors"}<Icon name="search" size={17} /></button></form>{searchError && <p className="search-error" role="alert">{searchError}</p>}<div aria-live="polite">{searched && results.length > 0 && <p className="search-empty">{searchKind === "products" ? "Product subscriptions cover all versions. Confirm the affected versions on each CVE." : "Vendor subscriptions cover all of that vendor’s products and versions."}</p>}{searched && results.length === 0 && <p className="search-empty">No matching subscriptions found. Try a name without a version. Check the import progress above; results may be incomplete.</p>}{results.map((product) => { const tracked = watchlist.some((item) => item.id === product.id); return <article className="search-result" key={product.id}><div><strong>{product.product_name}</strong><small>{product.vendor} · {productVersionLabel(product)}</small></div><button className="button button-small" type="button" disabled={tracked || !!busy} onClick={() => add(product)} aria-label={`${tracked ? "Tracking" : "Track"} ${product.product_name} ${product.version}`}>{tracked ? <Icon name="check" size={16} /> : <Icon name="plus" size={16} />}{tracked ? "Tracked" : "Track"}</button></article>; })}</div></> : <p className="message">An owner, admin or member can add software. Your viewer access lets you review the watchlist.</p>}</section></div>}
        {view === "billing" && <BillingPanel canManage={canManageBilling} initialAvailable={billing.available} initialPlans={billing.plans} initialSubscription={billing.subscription} />}
        <footer className="page-footer"><span>CVE Monitor</span><span>A clearer view of your software risk.</span></footer>
      </div>
    </main>
  </div>;
}

function Metric({ label, value, caption, icon, danger, onClick, selected }: { label: string; value?: number; caption: string; icon: "bell" | "warning" | "shield" | "software"; danger?: boolean; onClick?: () => void; selected?: boolean }) {
  const content = <><span className="metric-top">{label}<Icon name={icon} size={19} /></span><strong className={danger && !!value ? "risk-value" : undefined}>{value ?? "—"}</strong><small>{caption}</small></>;
  return onClick ? <button type="button" className={`metric ${selected ? "metric-selected" : ""}`} onClick={onClick}>{content}</button> : <div className="metric">{content}</div>;
}

function AlertCard({ alert, canEdit, busy, onStatus }: { alert: Alert; canEdit: boolean; busy: boolean; onStatus: (status: AlertStatus) => void }) {
  const demo = alert.cve_id.startsWith("CVE-DEMO");
  return <article className={`alert-card ${alert.is_kev ? "alert-urgent" : ""}`}><div className="alert-title"><div><span className={`severity severity-${alert.severity}`}><span />{alert.severity === "unknown" ? "Unscored" : alert.severity}</span>{alert.is_kev && <span className="exploited-badge"><Icon name="warning" size={12} />Known exploited</span>}{demo && <span className="demo-badge">Demo data</span>}</div><span className="alert-date">{alert.published_at ? formatDate(alert.published_at) : "Date unavailable"}</span></div><h3>{demo ? alert.cve_id : <Link href={`/dashboard/cves/${encodeURIComponent(alert.cve_id)}`} className="cve-link">{alert.cve_id}</Link>}</h3><p className="alert-summary">{alert.summary || "Review the affected product’s security guidance and check whether your installed version needs an update."}</p><div className="affected-products">{alert.products.map((product) => <span key={product.id}><Icon name="software" size={13} />{product.product_name}{` · ${productVersionLabel(product)}`}</span>)}</div><div className="alert-bottom"><div className="risk-scores"><span title="CVSS measures technical severity on a scale of 0 to 10.">Severity <strong>{alert.cvss_score ?? "—"}<small>/10</small></strong></span><span title="EPSS estimates the probability of exploitation in the next 30 days.">Exploit likelihood <strong>{alert.epss_score === null ? "—" : `${(alert.epss_score * 100).toFixed(1)}%`}</strong></span></div><div className="alert-actions">{!demo && <a className="icon-button" href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(alert.cve_id)}`} target="_blank" rel="noopener noreferrer" aria-label={`Read official details for ${alert.cve_id}`}><Icon name="external" size={15} /></a>}{canEdit && <>{alert.status === "new" ? <><button className="text-button muted" type="button" disabled={busy} onClick={() => onStatus("dismissed")}>Dismiss</button><button className="button button-small" type="button" disabled={busy} onClick={() => onStatus("read")}><Icon name="check" size={14} />Mark reviewed</button></> : <button className="button button-small" type="button" disabled={busy} onClick={() => onStatus("new")}>Return to inbox<Icon name="arrow" size={14} /></button>}</>}</div></div></article>;
}

function formatDate(value: string) { return new Intl.DateTimeFormat("en", { month: "short", day: "numeric", year: "numeric" }).format(new Date(value)); }
