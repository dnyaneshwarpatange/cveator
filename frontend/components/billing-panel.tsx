"use client";

import { useState } from "react";
import { requestJson } from "@/lib/api-client";

import { launchProviderCheckout } from "@/lib/provider-checkout";
import type { BillingPlan, BillingSubscription, CheckoutPayload } from "@/lib/types";

interface BillingPanelProps {
  canManage: boolean;
  initialAvailable: boolean;
  initialPlans: BillingPlan[];
  initialSubscription: BillingSubscription | null;
}

export function BillingPanel({
  canManage,
  initialAvailable,
  initialPlans,
  initialSubscription
}: BillingPanelProps) {
  const [subscription, setSubscription] = useState(initialSubscription);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmCancel, setConfirmCancel] = useState(false);

  if (!initialAvailable) {
    return (
      <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm sm:p-6">
        <h2 className="text-xl font-semibold text-slate-950">Billing</h2>
        <p className="mt-2 text-sm leading-6 text-slate-600">
          Online billing is not available for this workspace yet. You can continue reviewing
          alerts and managing your software watchlist.
        </p>
      </section>
    );
  }

  async function choosePlan(plan: BillingPlan) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const result = await requestJson<{
        subscription: BillingSubscription;
        checkout_payload: CheckoutPayload;
      }>("/api/billing/checkout", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ plan_id: plan.id })
      });
      setSubscription(result.subscription);
      await launchProviderCheckout(result.checkout_payload, (success) => {
        void verifyCheckout(success);
      });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "We could not start checkout.");
    } finally {
      setBusy(false);
    }
  }

  async function verifyCheckout(payload: {
    provider_subscription_id: string;
    provider_payment_id: string;
    signature: string;
  }) {
    setBusy(true);
    try {
    await requestJson("/api/billing/checkout/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload)
    });
    setNotice("Payment received for verification. Refresh your plan status in a moment to check confirmation.");
    } catch { setError("We couldn’t verify the payment yet. Refresh your plan status before trying checkout again."); }
    finally { setBusy(false); }
  }

  async function refreshSubscription() {
    setBusy(true); setError(null);
    try { setSubscription(await requestJson<BillingSubscription | null>("/api/billing/subscription")); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Couldn’t refresh your plan."); }
    finally { setBusy(false); }
  }

  async function cancelSubscription() {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await requestJson("/api/billing/subscription", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ at_period_end: true })
      });
      setNotice("Cancellation requested for the end of your billing period. Refresh your plan status to check confirmation.");
      setConfirmCancel(false);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "We could not send the cancellation request."
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm sm:p-6">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
        <div>
          <h2 className="text-xl font-semibold text-slate-950">Billing</h2>
          <p className="mt-1 text-sm leading-6 text-slate-600">
            Review your subscription, payment status, and renewal date.
          </p>
        </div>
        {subscription ? (
          <span className="rounded-full bg-slate-100 px-3 py-1.5 text-sm font-semibold capitalize text-slate-700">
            {subscription.status.replace("_", " ")}
          </span>
        ) : null}
      </div>
      <button className="text-button mt-4" disabled={busy} type="button" onClick={() => void refreshSubscription()}>Refresh plan status</button>
      {notice ? <p role="status" className="mt-4 rounded-lg bg-emerald-50 p-3 text-sm text-emerald-800">{notice}</p> : null}
      {error ? <p role="alert" className="mt-4 rounded-lg bg-rose-50 p-3 text-sm text-rose-800">{error}</p> : null}
      {subscription ? (
        <div className="mt-5 rounded-xl bg-slate-50 p-4">
          <p className="text-sm font-semibold text-slate-900">Current plan: {initialPlans.find((plan) => plan.id === subscription.plan_id)?.name ?? subscription.plan_id}</p>
          {subscription.current_period_end ? (
            <p className="mt-1 text-sm text-slate-600">
              Current period ends {formatDate(subscription.current_period_end)}
            </p>
          ) : (
            <p className="mt-1 text-sm text-slate-600">Waiting for the first payment confirmation.</p>
          )}
          {canManage && subscription.status !== "cancelled" ? (
            <button
              className="mt-3 text-sm font-semibold text-rose-700 hover:underline disabled:opacity-60"
              disabled={busy}
              onClick={() => setConfirmCancel(true)}
              type="button"
            >
              Cancel at the end of this period
            </button>
          ) : null}
          {confirmCancel && <div className="mt-4 rounded-lg border border-rose-200 p-4" role="alert"><p className="text-sm">Cancel renewal at the end of this billing period?</p><div className="mt-3 flex gap-3"><button className="button" disabled={busy} type="button" onClick={() => setConfirmCancel(false)}>Keep my plan</button><button className="button" disabled={busy} type="button" onClick={() => void cancelSubscription()}>Confirm cancellation</button></div></div>}
        </div>
      ) : null}
      {(!subscription || subscription.status === "cancelled") && canManage ? (
        <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {initialPlans.map((plan) => (
            <article className="rounded-xl border border-slate-200 p-4" key={plan.id}>
              <h3 className="font-semibold text-slate-950">{plan.name}</h3>
              <p className="mt-1 text-sm leading-6 text-slate-600">{plan.description}</p>
              <p className="mt-4 text-lg font-semibold text-slate-950">
                {formatMoney(plan.amount_paise, plan.currency)}
                <span className="text-sm font-normal text-slate-600"> / {plan.interval}</span>
              </p>
              <button
                className="mt-4 rounded-lg bg-sky-700 px-3 py-2 text-sm font-semibold text-white hover:bg-sky-800 disabled:cursor-not-allowed disabled:opacity-60"
                disabled={busy}
                onClick={() => void choosePlan(plan)}
                type="button"
              >
                Choose {plan.name}
              </button>
            </article>
          ))}
        </div>
      ) : null}
      {!subscription && !canManage ? (
        <p className="mt-5 text-sm text-slate-600">An owner or administrator can manage the billing plan.</p>
      ) : null}
    </section>
  );
}

function formatMoney(amountPaise: number, currency: string): string {
  return new Intl.NumberFormat("en-IN", { style: "currency", currency }).format(amountPaise / 100);
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date(value));
}
