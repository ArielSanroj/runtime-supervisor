"use client";

import { useState } from "react";

type Result = {
  decision: "allow" | "deny" | "review";
  reasons: string[];
  hits: Array<{ rule_id: string; action: string; reason: string }>;
};

export default function TestPanel({ id, samplePayload }: { id: string; samplePayload: string }) {
  const [payload, setPayload] = useState(samplePayload);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setErr(null);
    setResult(null);
    try {
      const body = JSON.parse(payload);
      const r = await fetch(`/api/policies/${id}/test`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ payload: body }),
      });
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
      <textarea
        value={payload}
        onChange={(e) => setPayload(e.target.value)}
        spellCheck={false}
        style={{ minHeight: 180, fontFamily: "var(--mono)", fontSize: 13 }}
      />
      <div className="row" style={{ marginTop: 10 }}>
        <button onClick={run} disabled={busy}>
          {busy ? "Running…" : "Run test"}
        </button>
      </div>
      {err && <p className="chain-bad" style={{ marginTop: 12, whiteSpace: "pre-wrap" }}>{err}</p>}
      {result && (
        <div style={{ marginTop: 16 }}>
          <p>
            Decision:{" "}
            <span className={`badge ${result.decision === "allow" ? "approved" : result.decision === "deny" ? "rejected" : "pending"}`}>
              {result.decision}
            </span>
          </p>
          {result.reasons.length > 0 && (
            <>
              <h3 className="muted" style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: "0.08em", margin: "12px 0 6px" }}>
                Reasons
              </h3>
              <ul className="mono">{result.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
            </>
          )}
          {result.hits.length > 0 && (
            <>
              <h3 className="muted" style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: "0.08em", margin: "12px 0 6px" }}>
                Rule hits
              </h3>
              <ul className="mono">{result.hits.map((h) => <li key={h.rule_id}>{h.rule_id} → {h.action} · {h.reason}</li>)}</ul>
            </>
          )}
        </div>
      )}
    </div>
  );
}
