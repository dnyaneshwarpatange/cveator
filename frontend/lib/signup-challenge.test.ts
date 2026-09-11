import { expect, it } from "vitest";
import { newSignupChallenge, readSignupChallenge } from "./signup-challenge";
it("restores verification metadata without retaining password or OTP", () => {
  const challenge = newSignupChallenge("id", "test@example.com");
  expect(readSignupChallenge(JSON.stringify({...challenge, password: "never-store", code: "123456"}))).toEqual(challenge);
});
it("discards broken and stale state", () => {
  expect(readSignupChallenge("invalid")).toBeNull();
  expect(readSignupChallenge(JSON.stringify({id:"id", email:"a", expiresAt:0, resendAt:0}))).toBeNull();
});
