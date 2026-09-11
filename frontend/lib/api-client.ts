export function apiErrorMessage(payload: unknown, fallback: string): string {
  if (!payload || typeof payload !== "object" || !("detail" in payload)) return fallback;
  const detail = payload.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const messages = detail.flatMap((item: unknown) => {
      if (!item || typeof item !== "object" || !("msg" in item) || typeof item.msg !== "string") return [];
      return [item.msg.replace(/^Value error, /, "")];
    });
    return messages.join(" ") || fallback;
  }
  return fallback;
}

export class ApiError extends Error {
  constructor(message: string, public status: number) { super(message); }
}

export async function requestJson<T>(url: string, init: RequestInit & { timeoutMs?: number } = {}): Promise<T> {
  const { timeoutMs = 15000, ...requestInit } = init;
  let response: Response;
  try {
    const timeout = AbortSignal.timeout(timeoutMs);
    const signal = init.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
    response = await fetch(url, { cache: "no-store", ...requestInit, signal });
  } catch (error) {
    if (init.signal?.aborted) throw error;
    throw new ApiError("We couldn’t reach the service. Check your connection and try again.", 0);
  }
  const data: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    throw new ApiError(apiErrorMessage(data, response.status === 429
      ? "Too many attempts. Please wait a few minutes before trying again."
      : "That didn’t go through. Please try again."), response.status);
  }
  return data as T;
}
