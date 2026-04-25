"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

type Creds = {
  app_id: string;
  shared_secret: string;
  base_url: string;
  scopes: string[];
  claimed_client_id?: string | null;
  claimed_actions?: number;
};

type State =
  | { status: "loading" }
  | { status: "ok"; creds: Creds }
  | { status: "error"; code: number; detail: string };

export default function OnboardClient({ token }: { token: string }) {
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    fetch(`/v1/integrations/onboard/${encodeURIComponent(token)}`, {
      method: "POST",
      cache: "no-store",
    })
      .then(async (r) => {
        if (cancelled) return;
        if (r.ok) {
          setState({ status: "ok", creds: (await r.json()) as Creds });
        } else {
          const body = await r.json().catch(() => ({ detail: r.statusText }));
          setState({ status: "error", code: r.status, detail: body.detail ?? r.statusText });
        }
      })
      .catch((e) => {
        if (cancelled) return;
        setState({ status: "error", code: 0, detail: String(e) });
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  if (state.status === "loading") {
    return (
      <Shell>
        <p className="muted">Issuing your credentials…</p>
      </Shell>
    );
  }

  if (state.status === "error") {
    return (
      <Shell>
        <h1 style={{ marginTop: 0 }}>Couldn&apos;t issue credentials</h1>
        <p className="muted">{describeError(state.code, state.detail)}</p>
        <Link href="/scan" className="button" style={{ marginTop: 16, display: "inline-block" }}>
          start over from /scan
        </Link>
      </Shell>
    );
  }

  return <CredsPanel creds={state.creds} />;
}

function describeError(code: number, detail: string): string {
  if (code === 404) return "This signup link doesn't exist. Request a new one.";
  if (code === 410) {
    if (detail.includes("expired")) return "This link expired (30-minute window). Request a new one.";
    return "This link was already used. Credentials are shown once — request a new signup if you lost them.";
  }
  return detail || "Unknown error.";
}

function CredsPanel({ creds }: { creds: Creds }) {
  return (
    <Shell>
      <div
        style={{
          background: "rgba(251, 191, 36, 0.08)",
          border: "1px solid rgba(251, 191, 36, 0.3)",
          borderRadius: 8,
          padding: "12px 16px",
          marginBottom: 24,
          fontSize: 13,
        }}
      >
        <strong style={{ color: "#fbbf24" }}>⚠ shown once</strong> — copy these into your{" "}
        <code>.env</code> now. We will not display them again. If you refresh this page, they&apos;re gone.
      </div>

      <h1 style={{ margin: "0 0 4px" }}>Your supervisor credentials</h1>
      <p className="muted" style={{ margin: "0 0 24px" }}>
        Use them with <code>@runtime-supervisor/guards</code> (Node) or{" "}
        <code>supervisor-guards</code> (Python).
      </p>

      {creds.claimed_actions !== undefined && creds.claimed_actions > 0 && (
        <div
          style={{
            background: "rgba(16, 185, 129, 0.08)",
            border: "1px solid rgba(16, 185, 129, 0.3)",
            borderRadius: 8,
            padding: "12px 16px",
            marginBottom: 24,
            fontSize: 13,
          }}
        >
          <strong style={{ color: "#34d399" }}>✓ {creds.claimed_actions} previous shadow event{creds.claimed_actions === 1 ? "" : "s"} migrated</strong>
          {" — "}
          your prior anonymous runs (client_id <code>{creds.claimed_client_id?.slice(0, 12)}…</code>) are now visible in this dashboard.
        </div>
      )}

      <CredRow label="SUPERVISOR_BASE_URL" value={creds.base_url} />
      <CredRow label="SUPERVISOR_APP_ID" value={creds.app_id} />
      <CredRow label="SUPERVISOR_SECRET" value={creds.shared_secret} secret />
      <CredRow label="SUPERVISOR_SCOPES" value={creds.scopes.join(",")} />

      <h2 style={{ marginTop: 32, fontSize: 18 }}>Use them in 10 lines</h2>

      <Tabs
        tabs={[
          {
            label: "TypeScript",
            content: (
              <CodeBlock
                code={`// .env
SUPERVISOR_BASE_URL=${creds.base_url}
SUPERVISOR_APP_ID=${creds.app_id}
SUPERVISOR_SECRET=${creds.shared_secret}

// src/supervisor.ts
import { configure, guarded } from "@runtime-supervisor/guards";
configure({});  // reads SUPERVISOR_* from process.env

// before any unsafe action:
await guarded("payment", { amount: 4200, currency: "USD" }, () =>
  stripe.refunds.create({ payment_intent: "pi_abc" }),
);`}
              />
            ),
          },
          {
            label: "Python",
            content: (
              <CodeBlock
                code={`# .env
SUPERVISOR_BASE_URL=${creds.base_url}
SUPERVISOR_APP_ID=${creds.app_id}
SUPERVISOR_SECRET=${creds.shared_secret}

# supervisor.py
from supervisor_guards import configure, guarded
configure()  # reads SUPERVISOR_* from os.environ

# before any unsafe action:
guarded(
    "payment",
    {"amount": 4200, "currency": "USD"},
    stripe.Refund.create,
    payment_intent="pi_abc",
)`}
              />
            ),
          },
        ]}
      />

      <div style={{ marginTop: 32, padding: 16, background: "rgba(255,255,255,0.03)", borderRadius: 8 }}>
        <strong>Defaults:</strong> shadow mode (logs &quot;would-have-blocked&quot; without interrupting). Flip to{" "}
        <code>SUPERVISOR_ENFORCEMENT_MODE=enforce</code> when you&apos;ve seen enough shadow data.
      </div>

      <div style={{ marginTop: 24, display: "flex", gap: 12 }}>
        <Link href="/dashboard" className="button">
          open dashboard →
        </Link>
        <a
          href="https://www.npmjs.com/package/@runtime-supervisor/guards"
          target="_blank"
          rel="noopener noreferrer"
          className="button-secondary"
        >
          npm package
        </a>
      </div>
    </Shell>
  );
}

function CredRow({ label, value, secret = false }: { label: string; value: string; secret?: boolean }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div style={{ marginBottom: 12 }}>
      <div className="mono muted" style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 4 }}>
        {label}
      </div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "10px 14px",
          background: "rgba(255,255,255,0.04)",
          border: "1px solid rgba(255,255,255,0.08)",
          borderRadius: 6,
          fontFamily: "ui-monospace, monospace",
          fontSize: 13,
        }}
      >
        <span style={{ flex: 1, wordBreak: "break-all", color: secret ? "#fb7185" : "#e4e4e7" }}>{value}</span>
        <button
          type="button"
          onClick={onCopy}
          className="button-secondary"
          style={{ flexShrink: 0, fontSize: 12, padding: "4px 10px" }}
        >
          {copied ? "✓ copied" : "copy"}
        </button>
      </div>
    </div>
  );
}

function Tabs({ tabs }: { tabs: { label: string; content: React.ReactNode }[] }) {
  const [active, setActive] = useState(0);
  return (
    <div>
      <div style={{ display: "flex", gap: 4, borderBottom: "1px solid #27272a", marginBottom: 12 }}>
        {tabs.map((t, i) => (
          <button
            key={t.label}
            type="button"
            onClick={() => setActive(i)}
            style={{
              padding: "8px 14px",
              background: "transparent",
              border: 0,
              borderBottom: active === i ? "2px solid #10b981" : "2px solid transparent",
              color: active === i ? "#e4e4e7" : "#71717a",
              fontFamily: "ui-monospace, monospace",
              fontSize: 13,
              cursor: "pointer",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div>{tabs[active].content}</div>
    </div>
  );
}

function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div style={{ position: "relative" }}>
      <button
        type="button"
        onClick={onCopy}
        className="button-secondary"
        style={{ position: "absolute", top: 8, right: 8, fontSize: 11, padding: "3px 8px" }}
      >
        {copied ? "✓ copied" : "copy"}
      </button>
      <pre
        style={{
          background: "rgba(0,0,0,0.4)",
          border: "1px solid #27272a",
          borderRadius: 6,
          padding: 16,
          fontSize: 12.5,
          lineHeight: 1.55,
          overflow: "auto",
          margin: 0,
        }}
      >
        <code>{code}</code>
      </pre>
    </div>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ maxWidth: 720, margin: "32px auto", padding: 24 }}>{children}</div>
  );
}
