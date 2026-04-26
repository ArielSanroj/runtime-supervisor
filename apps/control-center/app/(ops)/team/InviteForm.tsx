"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

type State =
  | { kind: "idle" }
  | { kind: "submitting" }
  | { kind: "sent"; email: string }
  | { kind: "error"; message: string };

const ROLES = [
  { value: "ops", label: "ops — view + decide reviews" },
  { value: "compliance", label: "compliance — read-only audit access" },
  { value: "auditor", label: "auditor — read-only" },
  { value: "admin", label: "admin — manage everything" },
];

export default function InviteForm() {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("ops");
  const [state, setState] = useState<State>({ kind: "idle" });
  const router = useRouter();

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!email.trim()) return;
    setState({ kind: "submitting" });
    try {
      const r = await fetch("/api/team/invite", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: email.trim(), role }),
      });
      if (r.ok) {
        setState({ kind: "sent", email: email.trim() });
        setEmail("");
        // Refresh members list.
        router.refresh();
      } else if (r.status === 409) {
        const body = await r.json().catch(() => ({}));
        setState({
          kind: "error",
          message: body.detail ?? "Already exists under a different workspace.",
        });
      } else {
        const body = await r.json().catch(() => ({}));
        setState({ kind: "error", message: body.detail ?? body.error ?? `HTTP ${r.status}` });
      }
    } catch (err) {
      setState({ kind: "error", message: String(err) });
    }
  }

  return (
    <div className="card" style={{ padding: 16 }}>
      <h2 style={{ marginTop: 0, fontSize: 16 }}>Invite a teammate</h2>
      <p className="muted" style={{ fontSize: 13, marginTop: 4 }}>
        They get a magic link by email. No password setup needed.
      </p>
      <form onSubmit={onSubmit} className="row" style={{ gap: 8, marginTop: 12, flexWrap: "wrap" }}>
        <input
          type="email"
          required
          placeholder="teammate@example.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          disabled={state.kind === "submitting"}
          className="mono"
          style={{
            flex: "1 1 240px",
            padding: "8px 12px",
            background: "rgba(0,0,0,0.3)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            color: "#e4e4e7",
            fontSize: 13,
          }}
        />
        <select
          value={role}
          onChange={(e) => setRole(e.target.value)}
          disabled={state.kind === "submitting"}
          className="mono"
          style={{
            padding: "8px 12px",
            background: "rgba(0,0,0,0.3)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            color: "#e4e4e7",
            fontSize: 13,
          }}
        >
          {ROLES.map((r) => (
            <option key={r.value} value={r.value}>
              {r.label}
            </option>
          ))}
        </select>
        <button type="submit" className="button" disabled={state.kind === "submitting" || !email.trim()}>
          {state.kind === "submitting" ? "sending…" : "send invite →"}
        </button>
      </form>
      {state.kind === "sent" && (
        <p style={{ marginTop: 12, color: "var(--ok)", fontSize: 13 }}>
          ✓ Magic link sent to <strong>{state.email}</strong>. They&apos;ll appear below once they sign in.
        </p>
      )}
      {state.kind === "error" && (
        <p style={{ marginTop: 12, color: "var(--danger)", fontSize: 13 }}>{state.message}</p>
      )}
    </div>
  );
}
