export const signupStorageKey = "cveator.signup.challenge";
export type SignupChallenge = {id: string; email: string; expiresAt: number; resendAt: number};
export function newSignupChallenge(id: string, email: string): SignupChallenge {
  return {id, email, expiresAt: Date.now() + 600_000, resendAt: Date.now() + 60_000};
}
export function readSignupChallenge(raw: string | null): SignupChallenge | null {
  try {
    const value = JSON.parse(raw ?? "null");
    if (!value || typeof value.id !== "string" || typeof value.email !== "string" ||
        typeof value.expiresAt !== "number" || typeof value.resendAt !== "number" ||
        value.expiresAt + 3600_000 < Date.now()) return null;
    return {id: value.id, email: value.email, expiresAt: value.expiresAt, resendAt: value.resendAt};
  } catch { return null; }
}
