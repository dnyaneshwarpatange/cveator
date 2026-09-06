import type { CheckoutPayload } from "@/lib/types";

export interface CheckoutSuccess {
  provider_subscription_id: string;
  provider_payment_id: string;
  signature: string;
}

export type CheckoutAdapter = {
  launchCheckout(payload: CheckoutPayload, onSuccess: (success: CheckoutSuccess) => void): Promise<void>;
};

export async function launchProviderCheckout(
  payload: CheckoutPayload,
  onSuccess: (success: CheckoutSuccess) => void
): Promise<void> {
  const adapter = (await import(`../providers/${payload.provider}/checkout`)) as CheckoutAdapter;
  await adapter.launchCheckout(payload, onSuccess);
}
