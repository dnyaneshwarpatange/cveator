export type OrganizationRole = "owner" | "admin" | "member" | "viewer";
export type AlertStatus = "new" | "read" | "dismissed";
export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

export interface SessionUser {
  id: string;
  organization_id: string;
  email: string;
  role: OrganizationRole;
  is_application_admin?: boolean;
}

export interface AuthResponse {
  access_token: string;
  token_type: "bearer";
  expires_in_seconds: number;
  user: SessionUser;
}

export interface Product {
  id: number;
  vendor: string;
  product_name: string;
  version: string;
}

export interface IntelligenceStatus {
  cves: number;
  products: number;
  product_families: number;
  catalog: { status: string; processed: number; total: number | null; updated_at: string | null; error: string | null };
  imports?: { source: string; status: string; processed: number; total: number | null; updated_at: string | null; error: string | null }[];
  sources: { source: string; high_watermark: string; updated_at: string }[];
  product_syncs: { product_id: number; status: string; records: number; updated_at: string | null; error: string | null }[];
}

export interface Vulnerability {
  cve_id: string;
  description: string;
  cvss_score: number | null;
  epss_score: number | null;
  is_kev: boolean;
  published_at: string | null;
  last_modified_at: string | null;
  vendors: string[];
  products: string[];
}

export interface VulnerabilityPage {
  items: Vulnerability[];
  total: number;
  page: number;
  page_size: number;
}

export interface VulnerabilityDetail extends Vulnerability {
  sources?: string[];
  normalized: Record<string, unknown>;
  history: { id: number; source: string; kind: string; changes: Record<string, { old: unknown; new: unknown }>; observed_at: string; source_modified_at: string | null }[];
}

export interface Alert {
  id: number;
  cve_id: string;
  status: AlertStatus;
  severity: Severity;
  cvss_score: number | null;
  epss_score: number | null;
  is_kev: boolean;
  published_at: string | null;
  matched_at: string | null;
  created_at: string;
  summary: string | null;
  summary_provider: string | null;
  products: Product[];
}

export interface AlertPage {
  items: Alert[];
  total: number;
  page: number;
  page_size: number;
}

export interface DashboardOverview {
  active_alerts: number;
  critical_alerts: number;
  kev_alerts: number;
  watched_products: number;
}

export interface BillingPlan {
  id: string;
  name: string;
  description: string;
  amount_paise: number;
  currency: string;
  interval: string;
}

export interface BillingSubscription {
  provider: string;
  plan_id: string;
  status: string;
  current_period_end: string | null;
  created_at: string;
}

export interface BillingSnapshot {
  available: boolean;
  plans: BillingPlan[];
  subscription: BillingSubscription | null;
}

export interface CheckoutPayload {
  provider: string;
  [key: string]: unknown;
}
