"use client";

import { useState } from "react";

type Decision = {
  decision: "allow" | "deny" | "review";
  reasons: string[];
  threat_level: "none" | "info" | "warn" | "critical";
};

type ThreatSignal = {
  detector_id: string;
  owasp_ref: string;
  level: string;
  message: string;
  evidence: Record<string, unknown>;
};

type SimResult = {
  threat_id: string;
  decision: Decision;
  threats: ThreatSignal[];
};

const API = process.env.NEXT_PUBLIC_SUPERVISOR_API_URL ?? "http://localhost:8000";

function badgeClasses(level: string): string {
  if (level === "critical" || level === "deny") return "bg-rose-100 text-rose-800 border-rose-200";
  if (level === "warn" || level === "review") return "bg-amber-100 text-amber-800 border-amber-200";
  if (level === "allow") return "bg-emerald-100 text-emerald-800 border-emerald-200";
  return "bg-slate-100 text-slate-700 border-slate-200";
}

export default function SimulateAttackButton({ threatId, title }: { threatId: string; title: string }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<SimResult | null>(null);
  const [open, setOpen] = useState(false);

  async function run() {
    setBusy(true);
    setErr(null);
    setResult(null);
    try {
      const r = await fetch(`${API}/v1/simulate/attack?type=${encodeURIComponent(threatId)}`, {
        method: "POST",
        headers: { "ngrok-skip-browser-warning": "true" },
      });
      if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
      setResult((await r.json()) as SimResult);
      setOpen(true);
    } catch (e) {
      setErr((e as Error).message);
      setOpen(true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button
        onClick={run}
        disabled={busy}
        className="mt-4 inline-flex items-center gap-1 rounded-full border border-slate-300 px-3 py-1 text-xs font-medium hover:bg-slate-900 hover:text-white transition disabled:opacity-50"
      >
        {busy ? "Running…" : "▶ Simulate"}
      </button>

      {open && (
        <div
          className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-end sm:items-center justify-center p-4"
          onClick={() => setOpen(false)}
        >
          <div
            className="w-full max-w-2xl rounded-2xl bg-white shadow-xl border border-slate-200 p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="text-xs font-medium text-slate-500">Simulated attack</div>
                <h3 className="text-xl font-semibold mt-1">{title}</h3>
              </div>
              <button onClick={() => setOpen(false)} className="text-slate-400 hover:text-slate-900 text-2xl leading-none">×</button>
            </div>

            {err && <div className="mt-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-rose-800 text-sm">{err}</div>}

            {result && (
              <>
                <div className="mt-5 rounded-xl bg-slate-50 p-4">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs text-slate-500">Supervisor decision:</span>
                    <span className={`rounded-full border px-3 py-0.5 text-xs font-semibold uppercase ${badgeClasses(result.decision.decision)}`}>
                      {result.decision.decision}
                    </span>
                    <span className="text-xs text-slate-500">threat level:</span>
                    <span className={`rounded-full border px-3 py-0.5 text-xs font-semibold uppercase ${badgeClasses(result.decision.threat_level)}`}>
                      {result.decision.threat_level}
                    </span>
                  </div>
                  {result.decision.reasons.length > 0 && (
                    <div className="mt-3 text-sm">
                      <div className="text-slate-500">Reasons:</div>
                      <ul className="mt-1 list-disc pl-5 space-y-0.5 text-slate-900">
                        {result.decision.reasons.map((r) => (
                          <li key={r} className="font-mono">{r}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                <div className="mt-4">
                  <div className="text-sm font-medium text-slate-900">Signals raised ({result.threats.length})</div>
                  <div className="mt-2 space-y-2">
                    {result.threats.map((t, i) => (
                      <div key={i} className="rounded-lg border border-slate-200 p-3 text-sm">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`rounded px-2 py-0.5 text-xs font-semibold uppercase ${badgeClasses(t.level)}`}>{t.level}</span>
                          <span className="font-mono text-xs text-slate-600">{t.detector_id}</span>
                          <span className="font-mono text-xs text-slate-500">{t.owasp_ref}</span>
                        </div>
                        <div className="text-slate-900">{t.message}</div>
                        {Object.keys(t.evidence).length > 0 && (
                          <pre className="mt-2 text-xs bg-slate-50 rounded p-2 overflow-auto">{JSON.stringify(t.evidence, null, 2)}</pre>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="mt-5 text-xs text-slate-500">
                  Not persisted — this was a dry run against the real pipeline. Real integrations produce the same output + an audited evidence record.
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
}
