"use client";

import { useState } from "react";

type State =
  | { kind: "idle" }
  | { kind: "submitting" }
  | { kind: "sent"; email: string }
  | { kind: "error"; message: string };

export default function SignupForm({ headline, subline }: { headline?: string; subline?: string }) {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<State>({ kind: "idle" });

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!email.trim()) return;
    setState({ kind: "submitting" });
    try {
      const r = await fetch("/v1/integrations/public-signup", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: email.trim() }),
      });
      if (r.ok) {
        setState({ kind: "sent", email: email.trim() });
      } else if (r.status === 429) {
        setState({ kind: "error", message: "Too many signups for this email — wait an hour." });
      } else if (r.status === 422) {
        setState({ kind: "error", message: "That doesn't look like a valid email." });
      } else {
        const body = await r.json().catch(() => ({}));
        setState({ kind: "error", message: body.detail ?? `Error ${r.status}` });
      }
    } catch (err) {
      setState({ kind: "error", message: String(err) });
    }
  }

  if (state.kind === "sent") {
    return (
      <div className="rounded-xl border border-emerald-900/50 bg-emerald-500/5 p-6">
        <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">credentials emailed</div>
        <h3 className="mt-3 text-xl font-semibold text-zinc-100">Check {state.email}</h3>
        <p className="mt-3 text-sm leading-7 text-zinc-400">
          Open the link in the email to reveal your <code>appId</code> and <code>sharedSecret</code>. The page shows them once. The link expires in 30 minutes.
        </p>
        <p className="mt-2 text-xs text-zinc-500">
          Didn&apos;t arrive in 2 min? Check spam, then{" "}
          <button
            type="button"
            onClick={() => setState({ kind: "idle" })}
            className="underline hover:text-zinc-300"
          >
            try again
          </button>
          .
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-emerald-900/50 bg-emerald-500/5 p-6">
      <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">
        {headline ?? "next: wrap these call-sites"}
      </div>
      <h3 className="mt-3 text-xl font-semibold text-zinc-100">Get supervisor credentials — free</h3>
      <p className="mt-3 text-sm leading-7 text-zinc-400">
        {subline ?? (
          <>
            Drop in <code>@runtime-supervisor/guards</code> + 5 lines of config and your wrapped call-sites start logging would-have-blocks to the dashboard. Shadow mode by default — nothing breaks in prod.
          </>
        )}
      </p>

      <form onSubmit={onSubmit} className="mt-5 flex flex-col gap-3 sm:flex-row">
        <input
          type="email"
          required
          placeholder="you@example.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          disabled={state.kind === "submitting"}
          className="flex-1 rounded-lg border border-zinc-800 bg-black/40 px-4 py-2.5 font-mono text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-emerald-700 focus:outline-none"
        />
        <button
          type="submit"
          disabled={state.kind === "submitting" || !email.trim()}
          className="rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-black hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {state.kind === "submitting" ? "sending…" : "email me credentials →"}
        </button>
      </form>

      {state.kind === "error" && (
        <p className="mt-3 text-sm text-rose-400">{state.message}</p>
      )}

      <p className="mt-4 text-xs text-zinc-500">
        Free for any public repo. No credit card. Builder ($29/mo) unlocks private repos, history, CI comments.
      </p>
    </div>
  );
}
