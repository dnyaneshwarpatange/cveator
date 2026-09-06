"use client";

import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";
import { Icon } from "@/components/icon";
import { requestJson } from "@/lib/api-client";
import type { IntelligenceStatus, VulnerabilityPage } from "@/lib/types";

export function useIntelligenceStatus(revision: number) {
  const [data, setData] = useState<IntelligenceStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    let pending = false;
    async function load() {
      if (pending || controller.signal.aborted) return;
      pending = true;
      try {
        const result = await requestJson<IntelligenceStatus>("/api/intelligence/status", { signal: controller.signal });
        if (!controller.signal.aborted) { setData(result); setError(null); }
      } catch (reason) {
        if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : "Data status is unavailable.");
      } finally { pending = false; }
    }
    void load();
    const interval = setInterval(() => void load(), 20_000);
    return () => { controller.abort(); clearInterval(interval); };
  }, [revision]);
  return { data, error };
}

export function DataStatus({ data, error }: { data: IntelligenceStatus | null; error: string | null }) {
  if (error) return <div className="message message-error" role="status"><Icon name="warning" /><span>Data status unavailable: {error} Counts below may be out of date.</span></div>;
  if (!data) return <div className="data-status muted" role="status">Checking imported data and synchronization…</div>;
  const complete = ["complete", "completed", "ready"].includes(data.catalog.status);
  const failed = ["failed", "error"].includes(data.catalog.status);
  const running = data.product_syncs.filter((item) => ["pending", "queued", "running", "syncing"].includes(item.status));
  const historyImports = (data.imports ?? []).filter((item) => /^nvd_cves_\d{4}$/.test(item.source));
  const completedYears = historyImports.filter((item) => item.status === "complete").length;
  const expectedYears = new Date().getFullYear() - 1999 + 1;
  return <section className={`data-status ${complete ? "" : "data-status-incomplete"}`} aria-label="Data coverage and synchronization">
    <div className="data-status-top"><div><Icon name={failed ? "warning" : "refresh"} size={17} /><strong>{failed ? "Catalog import needs attention" : complete ? "Product catalog imported" : "Product catalog import is incomplete"}</strong></div><span>{data.cves.toLocaleString()} CVEs · {data.product_families.toLocaleString()} product families</span></div>
    <p>{complete ? "Search covers the imported catalog. Vulnerabilities are updated from public sources on a schedule." : `${data.catalog.processed.toLocaleString()}${data.catalog.total === null ? "" : ` of ${data.catalog.total.toLocaleString()}`} catalog records processed. Search and vulnerability results can be incomplete while importing.`}{running.length > 0 && ` Loading historical vulnerabilities for ${running.length} subscribed ${running.length === 1 ? "product" : "products"}.`}</p>
    <p><strong>Historical CVE coverage: {completedYears} of {expectedYears} yearly feeds imported.</strong> {completedYears < expectedYears ? "The global vulnerability database is still incomplete." : "Full yearly baseline imported; scheduled updates continue."}</p>
    {data.catalog.error && <p className="search-error">{data.catalog.error}</p>}
    <details><summary>Source freshness and import progress</summary><div className="source-status-grid">{data.sources.map((source) => <div key={source.source}><strong>{sourceLabel(source.source)}</strong><span>Updated {formatTimestamp(source.updated_at)}</span><small>Source checked through {formatTimestamp(source.high_watermark)}</small></div>)}</div>{data.sources.length === 0 && <p>No completed source synchronization has been recorded.</p>}{historyImports.length > 0 && <div className="import-year-list">{[...historyImports].sort((a, b) => b.source.localeCompare(a.source)).map((item) => <div key={item.source}><strong>{item.source.slice(-4)}</strong><span>{item.status.replaceAll("_", " ")} · {item.processed.toLocaleString()} records{item.total !== null ? ` / ${item.total.toLocaleString()}` : ""}</span>{item.error && <small className="search-error">{item.error}</small>}</div>)}</div>}<p className="muted">Catalog: {data.catalog.status.replaceAll("_", " ")}{data.catalog.updated_at ? ` · ${formatTimestamp(data.catalog.updated_at)}` : ""}. Status refreshes every 20 seconds.</p></details>
  </section>;
}

export function VulnerabilityExplorer({ revision }: { revision: number }) {
  const [filters, setFilters] = useState({ q: "", vendor: "", product: "", kev: false, min_cvss: "", min_epss: "" });
  const [query, setQuery] = useState("");
  const [searchRevision, setSearchRevision] = useState(0);
  const [page, setPage] = useState(1);
  const [data, setData] = useState<VulnerabilityPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    requestJson<VulnerabilityPage>(`/api/intelligence/cves?${query}&page=${page}&page_size=20`, { signal: controller.signal })
      .then((result) => { if (!controller.signal.aborted) { setData(result); setError(null); } })
      .catch((reason) => { if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : "Vulnerabilities could not be loaded."); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [page, query, revision, searchRevision]);
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const params = new URLSearchParams();
    for (const key of ["q", "vendor", "product", "min_cvss"] as const) if (filters[key].trim()) params.set(key, filters[key].trim());
    if (filters.min_epss) params.set("min_epss", String(Number(filters.min_epss) / 100));
    if (filters.kev) params.set("kev", "true");
    setLoading(true); setPage(1); setQuery(params.toString()); setSearchRevision((value) => value + 1);
  }
  return <section className="panel intelligence-panel" aria-labelledby="intelligence-heading">
    <div className="panel-heading"><div><h2 id="intelligence-heading">Vulnerability database <span className="count-pill">{data?.total.toLocaleString() ?? "—"}</span></h2><p>Browse every imported CVE, including products outside your watchlist. Newest source updates first.</p></div></div>
    <form className="intelligence-filters" onSubmit={submit}>
      <label className="intelligence-search">CVE ID or description<input value={filters.q} onChange={(event) => setFilters({ ...filters, q: event.target.value })} placeholder="e.g. CVE-2024-3094 or authentication" maxLength={120} /></label>
      <label>Vendor<input value={filters.vendor} onChange={(event) => setFilters({ ...filters, vendor: event.target.value })} placeholder="e.g. atlassian" maxLength={100} /></label>
      <label>Product<input value={filters.product} onChange={(event) => setFilters({ ...filters, product: event.target.value })} placeholder="e.g. jira" maxLength={100} /></label>
      <label>Minimum CVSS<select value={filters.min_cvss} onChange={(event) => setFilters({ ...filters, min_cvss: event.target.value })}><option value="">Any score</option><option value="9">Critical · 9+</option><option value="7">High · 7+</option><option value="4">Medium · 4+</option></select></label>
      <label>Minimum EPSS<select value={filters.min_epss} onChange={(event) => setFilters({ ...filters, min_epss: event.target.value })}><option value="">Any likelihood</option><option value="10">10%</option><option value="50">50%</option><option value="90">90%</option></select></label>
      <div className="intelligence-filter-actions"><label className="checkbox-label"><input type="checkbox" checked={filters.kev} onChange={(event) => setFilters({ ...filters, kev: event.target.checked })} />Known exploited only</label><button className="button button-primary" type="submit"><Icon name="search" size={16} />Search CVEs</button></div>
    </form>
    {error && <div className="message message-error" role="alert">{error}</div>}
    <div aria-busy={loading}>{loading ? <div className="loading-state" role="status"><span className="loader" />Loading vulnerabilities…</div> : data?.items.length ? data.items.map((cve) => <article key={cve.cve_id} className="vulnerability-row"><div className="vulnerability-row-top"><Link href={`/dashboard/cves/${encodeURIComponent(cve.cve_id)}`} className="cve-link">{cve.cve_id}</Link><RiskBadges score={cve.cvss_score} kev={cve.is_kev} /><span className="alert-date">Updated {formatTimestamp(cve.last_modified_at, true)}</span></div><p className="vulnerability-description">{cve.description || "The source has not provided a description."}</p><div className="vulnerability-row-bottom"><div className="affected-products">{cve.products.slice(0, 5).map((product) => <span key={product}>{product.replaceAll("_", " ")}</span>)}{cve.products.length > 5 && <span>+{cve.products.length - 5} more</span>}</div><span>EPSS {cve.epss_score === null ? "unavailable" : `${(cve.epss_score * 100).toFixed(2)}%`}</span></div></article>) : <div className="empty-state"><Icon name="search" size={28} /><h3>No imported CVEs match these filters</h3><p>Try a broader query. Check the data coverage panel above if a product is still importing.</p></div>}</div>
    {!!data?.total && <footer className="pagination"><span>{((page - 1) * 20 + 1).toLocaleString()}–{Math.min(page * 20, data.total).toLocaleString()} of {data.total.toLocaleString()} vulnerabilities</span><div><button type="button" className="button button-small" disabled={loading || page === 1} onClick={() => { setLoading(true); setPage(page - 1); }}>Previous</button><span>Page {page}</span><button type="button" className="button button-small" disabled={loading || page * 20 >= data.total} onClick={() => { setLoading(true); setPage(page + 1); }}>Next</button></div></footer>}
  </section>;
}

export function RiskBadges({ score, kev }: { score: number | null; kev: boolean }) {
  const severity = score === null ? "unknown" : score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";
  return <><span className={`severity severity-${severity}`}><span />{score === null ? "Unscored" : `CVSS ${score} · ${severity}`}</span>{kev && <span className="exploited-badge"><Icon name="warning" size={12} />Known exploited</span>}</>;
}

export function formatTimestamp(value: string | null, dateOnly = false) {
  if (!value) return "not yet recorded";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "unknown";
  return new Intl.DateTimeFormat("en", { year: "numeric", month: "short", day: "numeric", ...(dateOnly ? {} : { hour: "2-digit", minute: "2-digit" }) }).format(date);
}

function sourceLabel(value: string) {
  return ({ nvd: "NVD vulnerabilities", nvd_cpe_dictionary: "NVD product catalog", mitre: "CVE Program", cisa_kev: "CISA KEV", epss: "FIRST EPSS" } as Record<string, string>)[value] ?? value.replaceAll("_", " ");
}
