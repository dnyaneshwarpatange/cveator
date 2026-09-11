"use client";

import { FormEvent, useEffect, useState } from "react";
import { requestJson } from "@/lib/api-client";

export function DeleteAccount({email}: {email: string}) {
  const [open, setOpen] = useState(false);
  const [challenge, setChallenge] = useState("");
  const [code, setCode] = useState("");
  const [wait, setWait] = useState(0);
  const [busy, setBusy] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    const timer = setInterval(() => setWait(v => Math.max(0, v - 1)), 1000);
    return () => clearInterval(timer);
  }, []);
  async function send() {
    setBusy(true); setError("");
    try {
      const result = await requestJson<{challenge_id: string}>("/api/account/deletion", {method: "POST", timeoutMs: 75000});
      setChallenge(result.challenge_id); setCode(""); setWait(60);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to send code."); }
    finally { setBusy(false); }
  }
  async function remove(event: FormEvent) {
    event.preventDefault(); if (!confirmed || busy) return;
    setBusy(true); setError("");
    try {
      await requestJson("/api/account/deletion", {method: "DELETE", headers: {"content-type": "application/json"},
        body: JSON.stringify({challenge_id: challenge, code})});
      window.location.replace("/login?account_deleted=1");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Deletion failed."); setBusy(false); }
  }
  return <section className="panel p-5 mt-6" aria-label="Account settings">
    <h2>Account settings</h2>
    <button type="button" className="text-button mt-3" onClick={() => setOpen(!open)} disabled={busy}>{open ? "Close account deletion" : "Delete my account"}</button>
    {open && <div className="mt-4">
      <p>This permanently deletes your login account and signs you out on every device. Organization data and billing records are retained; this does not cancel the organization’s subscription.</p>
      <p className="mt-3">The main application administrator and the last organization owner cannot self-delete. Contact the application administrator to arrange ownership transfer or workspace closure.</p>
      <button type="button" className="button button-small mt-4" onClick={() => void send()} disabled={busy || wait > 0}>
        {wait ? `Resend in ${wait}s` : challenge ? "Resend deletion code" : "Email deletion code"}
      </button>
      {challenge && <form onSubmit={remove} className="mt-4">
        <p role="status">Code sent to {email}. Check your spam folder too. It expires in 10 minutes; only the latest code works.</p>
        <label htmlFor="delete-otp">Deletion verification code</label>
        <input id="delete-otp" className="block border rounded p-3 mt-2" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required value={code} onChange={e => setCode(e.target.value.replace(/[^0-9]/g, ""))} />
        <label className="checkbox-label mt-4"><input type="checkbox" required checked={confirmed} onChange={e => setConfirmed(e.target.checked)} />I understand my login account will be permanently deleted.</label>
        <button className="button button-primary mt-4" type="submit" disabled={busy || !confirmed || code.length !== 6}>{busy ? "Please wait…" : "Verify OTP and permanently delete my account"}</button>
      </form>}
      {error && <p className="message message-error mt-3" role="alert">{error}</p>}
    </div>}
  </section>;
}
