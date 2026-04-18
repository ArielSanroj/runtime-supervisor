"use client";

import { useState } from "react";

type Window = "24h" | "7d" | "30d";

type Divergence = {
  action_id: string;
  created_at: string;
  from_decision: "allow" | "deny" | "review";
  to_decision: "allow" | "deny" | "review";
  to_reasons: string[];
};

type Result = {
  window: string;
  total: number;
  same: number;
  differ: number;
  would_tighten: number;
  would_loosen: number;
  divergences: Divergence[];
};

function badge(d: string): string {
  if (d === "allow") return "approved";
  if (d === "deny") return "rejected";
  return "pending";
}

export default function ReplayPanel({ id }: { id: string }) {
  const [window, setWindow] = useState<Window>("7d");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<Result | null>(null);

  async function run() {
    setBusy(true);
    setErr(null);
    setResult(null);
    try {
      const r = await fetch(`/api/policies/${id}/replay?window=${window}`, { method: "POST" });
      if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
      setResult(await r.json());
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <p className="muted" style={{ marginBottom: 10 }}>
        Re-evaluate recent actions of this action_type against this policy's rules.
        Shows how many decisions <strong>would have changed</strong> if this policy had been active.
      </p>
      <div className="row" style={{ gap: 10, alignItems: "center" }}>
        <span className="muted">Window:</span>
        {(["24h", "7d", "30d"] as Window[]).map((w) => (
          <button key={w} className={window === w ? "primary" : ""} onClick={() => setWindow(w)}>{w}</button>
        ))}
        <button className="primary" onClick={run} disabled={busy}>
          {busy ? "Running…" : "Run replay"}
        </button>
      </div>

      {err && <p className="chain-bad" style={{ marginTop: 10 }}>{err}</p>}

      {result && (
        <div style={{ marginTop: 16 }}>
          <div className="grid cols-3" style={{ gap: 10 }}>
            <div className="card kpi">{result.total}<span className="label">Actions in window</span></div>
            <div className="card kpi" style={{ color: "var(--warn)" }}>
              {result.would_tighten}
              <span className="label" style={{ color: "var(--muted)" }}>Would tighten (allow → review/deny)</span>
            </div>
            <div className="card kpi">
              {result.would_loosen}
              <span className="label">Would loosen (deny/review → allow)</span>
            </div>
          </div>

          {result.divergences.length === 0 ? (
            <p className="muted" style={{ marginTop: 12 }}>
              No divergences — this policy produces the same decisions for every action in the {result.window} window.
            </p>
          ) : (
            <>
              <h3 className="muted" style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: "0.08em", marginTop: 20 }}>
                Divergent decisions ({result.differ})
              </h3>
              <div className="card" style={{ padding: 0, marginTop: 8 }}>
                <table>
                  <thead>
                    <tr><th>When</th><th>From</th><th></th><th>To</th><th>New reason</th><th>action_id</th></tr>
                  </thead>
                  <tbody>
                    {result.divergences.map((d) => (
                      <tr key={d.action_id}>
                        <td className="muted mono">{new Date(d.created_at).toLocaleString()}</td>
                        <td><span className={`badge ${badge(d.from_decision)}`}>{d.from_decision}</span></td>
                        <td className="muted mono">→</td>
                        <td><span className={`badge ${badge(d.to_decision)}`}>{d.to_decision}</span></td>
                        <td className="mono">{d.to_reasons.join(", ")}</td>
                        <td className="mono muted">{d.action_id.slice(0, 8)}…</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {result.differ > result.divergences.length && (
                <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>
                  Showing first {result.divergences.length} of {result.differ} divergences.
                </p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
