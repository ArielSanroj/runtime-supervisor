"use client";

import { useEffect, useMemo, useState } from "react";

const STORAGE_KEY = "vibefixing.client_id";

type ClaimState =
  | { kind: "idle" }
  | { kind: "submitting" }
  | { kind: "sent"; email: string }
  | { kind: "error"; message: string };

function newClientId(): string {
  // Crypto.randomUUID is available in modern browsers + Node 19+. Fallback
  // to a Math.random-derived id only if the API is missing (very old
  // browsers); good enough for an attribution tag.
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return "anon-" + Math.random().toString(36).slice(2, 12);
}

function readOrMintClientId(): string {
  if (typeof window === "undefined") return "";
  try {
    const existing = window.localStorage.getItem(STORAGE_KEY);
    if (existing) return existing;
    const fresh = newClientId();
    window.localStorage.setItem(STORAGE_KEY, fresh);
    return fresh;
  } catch {
    return newClientId();
  }
}

export default function ZeroConfigPanel() {
  const [clientId, setClientId] = useState<string>("");
  const [email, setEmail] = useState("");
  const [claimState, setClaimState] = useState<ClaimState>({ kind: "idle" });
  const [activeTab, setActiveTab] = useState<"ts" | "py">("ts");

  useEffect(() => {
    setClientId(readOrMintClientId());
  }, []);

  const tsSnippet = useMemo(
    () =>
      `// .env
SUPERVISOR_CLIENT_ID=${clientId || "<generates on first run>"}

// src/supervisor.ts
import { configure, guarded } from "@runtime-supervisor/guards";
configure();   // anonymous shadow mode, zero credentials

// before any unsafe action:
await guarded("payment", { amount: 4200 }, () =>
  stripe.refunds.create({ payment_intent: "pi_abc" }),
);`,
    [clientId],
  );

  const pySnippet = useMemo(
    () =>
      `# .env
SUPERVISOR_CLIENT_ID=${clientId || "<generates on first run>"}

# supervisor.py
from supervisor_guards import configure, guarded
configure()   # anonymous shadow mode, zero credentials

# before any unsafe action:
guarded(
    "payment",
    {"amount": 4200, "currency": "USD"},
    stripe.Refund.create,
    payment_intent="pi_abc",
)`,
    [clientId],
  );

  async function onClaim(e: React.FormEvent) {
    e.preventDefault();
    if (!email.trim()) return;
    setClaimState({ kind: "submitting" });
    try {
      const r = await fetch("/v1/integrations/public-signup", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: email.trim(), client_id: clientId }),
      });
      if (r.ok) {
        setClaimState({ kind: "sent", email: email.trim() });
      } else if (r.status === 429) {
        setClaimState({ kind: "error", message: "Too many signups for this email — wait an hour." });
      } else if (r.status === 422) {
        setClaimState({ kind: "error", message: "That doesn't look like a valid email." });
      } else {
        const body = await r.json().catch(() => ({}));
        setClaimState({ kind: "error", message: body.detail ?? `Error ${r.status}` });
      }
    } catch (err) {
      setClaimState({ kind: "error", message: String(err) });
    }
  }

  return (
    <div className="rounded-xl border border-emerald-900/50 bg-emerald-500/5 p-6">
      <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">
        next: 5 lines, zero credentials
      </div>
      <h3 className="mt-3 text-xl font-semibold text-zinc-100">Drop the SDK into your code</h3>
      <p className="mt-3 text-sm leading-7 text-zinc-400">
        Shadow mode by default. No signup. The SDK posts <em>would-have-blocked</em> events to the public
        supervisor under your <code className="text-zinc-300">client_id</code>. Claim them with an email below
        when you want to see the dashboard view.
      </p>

      <div className="mt-5">
        <div className="flex gap-1 border-b border-zinc-800">
          <TabButton active={activeTab === "ts"} onClick={() => setActiveTab("ts")}>
            TypeScript
          </TabButton>
          <TabButton active={activeTab === "py"} onClick={() => setActiveTab("py")}>
            Python
          </TabButton>
        </div>
        <CodeBlock
          code={activeTab === "ts" ? tsSnippet : pySnippet}
          install={
            activeTab === "ts" ? "npm i @runtime-supervisor/guards" : "pip install supervisor-guards"
          }
        />
      </div>

      <div className="mt-5 rounded-md border border-zinc-800 bg-black/40 p-4">
        <div className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">
          your client_id (saved in localStorage)
        </div>
        <div className="mt-2 flex items-center gap-2">
          <code className="flex-1 break-all font-mono text-xs text-zinc-300">{clientId || "…"}</code>
          <CopyButton text={clientId} />
        </div>
      </div>

      <hr className="my-6 border-zinc-800" />

      {claimState.kind === "sent" ? (
        <div>
          <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">
            check {claimState.email}
          </div>
          <p className="mt-2 text-sm leading-6 text-zinc-400">
            We sent a one-time link. Open it to see your <code>appId</code> + <code>sharedSecret</code> and
            link your <code>client_id</code> to a personal dashboard. The link expires in 30 minutes.
          </p>
        </div>
      ) : (
        <div>
          <div className="font-mono text-xs uppercase tracking-widest text-zinc-500">optional</div>
          <h4 className="mt-2 text-base font-semibold text-zinc-100">
            Want a dashboard for your shadow events?
          </h4>
          <p className="mt-2 text-sm leading-6 text-zinc-400">
            Drop your email — we&apos;ll claim your <code>client_id</code> events into a personal dashboard
            and send credentials for enforce mode. Free.
          </p>
          <form onSubmit={onClaim} className="mt-4 flex flex-col gap-3 sm:flex-row">
            <input
              type="email"
              required
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={claimState.kind === "submitting"}
              className="flex-1 rounded-lg border border-zinc-800 bg-black/40 px-4 py-2.5 font-mono text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-emerald-700 focus:outline-none"
            />
            <button
              type="submit"
              disabled={claimState.kind === "submitting" || !email.trim()}
              className="rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-black hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {claimState.kind === "submitting" ? "sending…" : "claim with email →"}
            </button>
          </form>
          {claimState.kind === "error" && (
            <p className="mt-3 text-sm text-rose-400">{claimState.message}</p>
          )}
        </div>
      )}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`px-3 py-2 font-mono text-xs ${
        active ? "border-b-2 border-emerald-500 text-zinc-100" : "border-b-2 border-transparent text-zinc-500"
      }`}
    >
      {children}
    </button>
  );
}

function CodeBlock({ code, install }: { code: string; install: string }) {
  return (
    <div>
      <div className="flex items-center justify-between gap-2 border-b border-zinc-800 bg-black/40 px-3 py-2 font-mono text-xs">
        <span className="text-emerald-400">$ {install}</span>
        <CopyButton text={install} small />
      </div>
      <div className="relative">
        <CopyButton
          text={code}
          className="absolute right-2 top-2"
          small
        />
        <pre className="overflow-auto rounded-b-md bg-black/60 p-4 font-mono text-[12.5px] leading-[1.55] text-zinc-200">
          {code}
        </pre>
      </div>
    </div>
  );
}

function CopyButton({
  text,
  className = "",
  small = false,
}: {
  text: string;
  className?: string;
  small?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  const onClick = async () => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked — silently no-op */
    }
  };
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded border border-zinc-700 bg-zinc-900/80 px-2 ${
        small ? "py-0.5 text-[11px]" : "py-1 text-xs"
      } font-mono text-zinc-300 hover:bg-zinc-800 ${className}`}
    >
      {copied ? "✓ copied" : "copy"}
    </button>
  );
}
