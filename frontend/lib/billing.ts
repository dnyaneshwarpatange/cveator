import "server-only";

import { sessionBackendRequest } from "@/lib/backend";
import type { BillingPlan, BillingSnapshot, BillingSubscription } from "@/lib/types";

export type { BillingSnapshot } from "@/lib/types";

export async function currentBilling(): Promise<BillingSnapshot> {
  const [plansResponse, subscriptionResponse] = await Promise.all([
    sessionBackendRequest("/billing/plans"),
    sessionBackendRequest("/billing/subscription")
  ]);
  if (!plansResponse || !subscriptionResponse || plansResponse.status === 503) {
    return { available: false, plans: [], subscription: null };
  }
  if (!plansResponse.ok || !subscriptionResponse.ok) {
    return { available: false, plans: [], subscription: null };
  }
  return {
    available: true,
    plans: (await plansResponse.json()) as BillingPlan[],
    subscription: (await subscriptionResponse.json()) as BillingSubscription | null
  };
}
