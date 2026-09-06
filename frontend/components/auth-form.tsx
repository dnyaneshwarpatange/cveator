"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";
import { Icon } from "@/components/icon";
import { requestJson } from "@/lib/api-client";

type FormMode = "login" | "register";

interface AuthFormProps {
  mode: FormMode;
}

export function AuthForm({ mode }: AuthFormProps) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const isRegister = mode === "register";

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    const form = new FormData(event.currentTarget);
    const payload = {
      email: String(form.get("email") ?? ""),
      password: String(form.get("password") ?? ""),
      ...(isRegister ? { organization_name: String(form.get("organization_name") ?? "") } : {})
    };
    try {
      await requestJson(`/api/session/${mode}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload)
      });
      router.replace("/dashboard");
      router.refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The service could not be reached. Please try again shortly.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="auth-shell">
      <aside className="auth-story">
        <Link href="/" className="brand"><span className="brand-mark"><Icon name="shield" size={25} /></span><span>CVE Monitor<small>STAY ONE STEP AHEAD</small></span></Link>
        <div className="auth-story-content"><span className="eyebrow">LESS NOISE. MORE CERTAINTY.</span><h2>Know what matters.<br /><em>Act with confidence.</em></h2><p>Security visibility for the software your business depends on. Clear priorities. Practical next steps.</p><div className="auth-features"><span><Icon name="check" size={18} /> Watch the products your team actually uses</span><span><Icon name="check" size={18} /> See actively exploited risks first</span><span><Icon name="check" size={18} /> Turn vulnerability data into a clear action</span></div></div>
        <p className="auth-story-footer">Built for small businesses and the teams who support them.</p>
      </aside>
      <div className="auth-form-side"><section className="auth-card">
        <span className="empty-icon"><Icon name="shield" size={25} /></span>
        <h1 className="text-2xl font-semibold text-slate-950">
          {isRegister ? "Set up your workspace" : "Welcome back"}
        </h1>
        <p className="mt-2 text-sm leading-6 text-slate-600">
          {isRegister
            ? "Create an organization to start tracking the software you run."
            : "Sign in to review vulnerabilities affecting your watchlist."}
        </p>
        <form onSubmit={submit} aria-busy={submitting}>
          {isRegister ? (
            <label className="block text-sm font-medium text-slate-800">
              Organization name
              <input
                className="mt-1.5 w-full rounded-lg border border-slate-300 px-3 py-2.5"
                name="organization_name"
                required
                minLength={2}
                maxLength={255}
                autoComplete="organization"
              />
            </label>
          ) : null}
          <label className="block text-sm font-medium text-slate-800">
            Work email
            <input
              className="mt-1.5 w-full rounded-lg border border-slate-300 px-3 py-2.5"
              name="email"
              type="email"
              required
              autoComplete="email"
              placeholder="you@company.com"
            />
          </label>
          <div className="block text-sm font-medium text-slate-800">
            <label htmlFor="password">Password</label>
            <div className="password-field"><input
              id="password"
              className="mt-1.5 w-full rounded-lg border border-slate-300 px-3 py-2.5"
              name="password"
              type={showPassword ? "text" : "password"}
              required
              minLength={isRegister ? 12 : 1}
              maxLength={128}
              autoComplete={isRegister ? "new-password" : "current-password"}
              aria-describedby={isRegister ? "password-help" : undefined}
            /><button type="button" aria-label={showPassword ? "Hide password" : "Show password"} onClick={() => setShowPassword(!showPassword)}>{showPassword ? "Hide" : "Show"}</button></div>
            {isRegister ? (
              <span id="password-help" className="mt-1 block text-xs font-normal text-slate-500">
                Use at least 12 characters.
              </span>
            ) : null}
          </div>
          {error ? <p className="message message-error" role="alert">{error}</p> : null}
          <button
            className="button button-primary"
            disabled={submitting}
            type="submit"
          >
            {submitting ? "Please wait…" : isRegister ? "Create workspace" : "Sign in"}
            <Icon name="arrow" size={16} />
          </button>
        </form>
        <p className="auth-switch">
          {isRegister ? "Already have a workspace?" : "New here?"}{" "}
          <Link className="font-semibold text-sky-700 hover:underline" href={isRegister ? "/login" : "/register"}>
            {isRegister ? "Sign in" : "Create one"}
          </Link>
        </p>
        <p className="auth-security"><Icon name="shield" size={14} />Your workspace. Your team. Your peace of mind.</p>
      </section></div>
    </main>
  );
}
