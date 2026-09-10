import type { CheckoutPayload } from "@/lib/types";
import type { CheckoutSuccess } from "@/lib/provider-checkout";

declare global {
  interface Window {
    Razorpay?: new (options: RazorpayOptions) => { open(): void };
  }
}

interface RazorpayOptions {
  key: string;
  subscription_id: string;
  name: string;
  handler(response: {
    razorpay_subscription_id: string;
    razorpay_payment_id: string;
    razorpay_signature: string;
  }): void;
}

export async function launchCheckout(
  payload: CheckoutPayload,
  onSuccess: (success: CheckoutSuccess) => void
): Promise<void> {
  const key = requiredText(payload, "key_id");
  const subscriptionId = requiredText(payload, "provider_subscription_id");
  await loadScript(requiredText(payload, "script_url"));
  if (!window.Razorpay) {
    throw new Error("Razorpay checkout did not load");
  }
  const checkout = new window.Razorpay({
    key,
    subscription_id: subscriptionId,
    name: optionalText(payload, "display_name") ?? "cveator",
    handler(response) {
      onSuccess({
        provider_subscription_id: response.razorpay_subscription_id,
        provider_payment_id: response.razorpay_payment_id,
        signature: response.razorpay_signature
      });
    }
  });
  checkout.open();
}

function requiredText(payload: CheckoutPayload, field: string): string {
  const value = optionalText(payload, field);
  if (!value) {
    throw new Error("Razorpay checkout configuration is incomplete");
  }
  return value;
}

function optionalText(payload: CheckoutPayload, field: string): string | null {
  const value = payload[field];
  return typeof value === "string" && value.trim() ? value : null;
}

async function loadScript(source: string): Promise<void> {
  const existing = document.querySelector<HTMLScriptElement>(`script[src="${source}"]`);
  if (existing?.dataset.loaded === "true") return;
  if (existing) {
    await new Promise<void>((resolve, reject) => {
      existing.addEventListener("load", () => resolve(), { once: true });
      existing.addEventListener("error", () => reject(new Error("Razorpay checkout failed to load")), {
        once: true
      });
    });
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const script = document.createElement("script");
    script.src = source;
    script.async = true;
    script.addEventListener(
      "load",
      () => {
        script.dataset.loaded = "true";
        resolve();
      },
      { once: true }
    );
    script.addEventListener("error", () => reject(new Error("Razorpay checkout failed to load")), {
      once: true
    });
    document.head.append(script);
  });
}
