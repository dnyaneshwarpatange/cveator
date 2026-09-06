import "server-only";

import { sessionBackendRequest } from "@/lib/backend";
import type { SessionUser } from "@/lib/types";

export async function currentSession(): Promise<SessionUser | null> {
  const response = await sessionBackendRequest("/auth/me");
  if (!response?.ok) {
    return null;
  }
  return (await response.json()) as SessionUser;
}
