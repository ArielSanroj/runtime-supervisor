"use client";

import { useState } from "react";

type Sibling = { id: string; version: number; name: string; is_active: boolean };

type DiffResult = {
  action_type: string;
  from: { id: string; name: string; version: number };
  to: { id: string; name: string; version: number };
  added_lines: number;
  removed_lines: number;
  diff: string;
};

function lineClass(line: string): { bg: string; color: string } {
  if (line.startsWith("+++") || line.startsWith("---")) return { bg: "transparent", color: "var(--muted)" };
  if (line.startsWith("@@")) return { bg: "rgba(122, 162, 255, 0.12)", color: "var(--accent)" };
  if (line.startsWith("+")) return { bg: "rgba(62, 207, 142, 0.10)", color: "var(--ok)" };
  if (line.startsWith("-")) return { bg: "rgba(239, 79, 90, 0.10)", color: "var(--danger)" };
  return { bg: "transparent", color: "var(--text)" };
}

export default function DiffPanel({ id, siblings }: { id: string; siblings: Sibling[] }) {
  const [against, setAgainst] = useState(siblings[0]?.id ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<DiffResult | null>(null);

  async function run() {
    if (!against) return;
    setBusy(true);
    setErr(null);
    setResult(null);
    try {
      const r = await fetch(`/api/policies/${id}/diff?against=${against}`);
      if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
      setResult(await r.json());
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (siblings.length === 0) {
    return (
      <p className="muted">
        No other versions of this action_type's policy to compare against. Create another draft in{" "}
        <a href="/policies/new">+ New policy</a> to enable diffs.
      </p>
    );
  }

  return (
    <div>
      <div className="row" style={{ gap: 10, alignItems: "center" }}>
        <span className="muted">Compare against:</span>
        <select value={against} onChange={(e) => setAgainst(e.target.value)} style={{ maxWidth: 320 }}>
          {siblings.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name} v{s.version}{s.is_active ? " (active)" : ""}
            </option>
          ))}
        </select>
        <button className="primary" onClick={run} disabled={busy || !against}>
          {busy ? "Computing…" : "Show diff"}
        </button>
      </div>

      {err && <p className="chain-bad" style={{ marginTop: 10 }}>{err}</p>}

      {result && (
        <div style={{ marginTop: 16 }}>
          <div className="row" style={{ gap: 16, marginBottom: 8 }}>
            <span className="muted mono" style={{ fontSize: 13 }}>
              {result.from.name}@v{result.from.version} → {result.to.name}@v{result.to.version}
            </span>
            <span className="chain-ok mono">+{result.added_lines}</span>
            <span className="chain-bad mono">-{result.removed_lines}</span>
          </div>
          {result.diff === "" ? (
            <p className="muted">Identical — no changes.</p>
          ) : (
            <pre
              style={{
                fontFamily: "var(--mono)",
                fontSize: 12.5,
                padding: 0,
                background: "var(--panel-2)",
                border: "1px solid var(--border)",
                borderRadius: 8,
                overflow: "auto",
                maxHeight: 500,
              }}
            >
              {result.diff.split("\n").map((line, i) => {
                const { bg, color } = lineClass(line);
                return (
                  <div
                    key={i}
                    style={{
                      background: bg,
                      color,
                      padding: "0 12px",
                      lineHeight: "1.6em",
                      whiteSpace: "pre",
                    }}
                  >
                    {line || " "}
                  </div>
                );
              })}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
