"use client";

import { useEffect, useState } from "react";

/**
 * Live attack carousel — consumes /v1/threats/catalog for the menu and
 * /v1/simulate/attack?type=X for the response, so every scenario the
 * visitor sees is a real supervisor decision (not hardcoded copy).
 *
 * Caches each simulation per threat id so switching is instant after the
 * first roundtrip.
 */

const API = process.env.NEXT_PUBLIC_SUPERVISOR_API_URL ?? "http://localhost:8000";

interface ThreatSpec {
  id: string;
  title: string;
  owasp_ref: string;
  one_liner: string;
  severity: string;
  sample_attack: Record<string, unknown>;
}

interface ThreatSignal {
  detector_id: string;
  owasp_ref: string;
  level: string;
  message: string;
  evidence: Record<string, unknown>;
}

interface SimulatedAttack {
  threat_id: string;
  decision: {
    decision: "allow" | "deny" | "review";
    reasons: string[];
    threat_level: string;
    threats: ThreatSignal[];
  };
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    headers: { "ngrok-skip-browser-warning": "true" },
    cache: "no-store",
    ...init,
  });
  if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
  return (await res.json()) as T;
}

function decisionTone(d: string, level: string): { dot: string; text: string; label: string } {
  if (d === "deny") return { dot: "bg-rose-500", text: "text-rose-400", label: "BLOCKED" };
  if (d === "review") return { dot: "bg-amber-500", text: "text-amber-400", label: "NEEDS APPROVAL" };
  if (level === "critical") return { dot: "bg-rose-500", text: "text-rose-400", label: "BLOCKED" };
  return { dot: "bg-emerald-500", text: "text-emerald-400", label: "ALLOWED" };
}

export default function DemoCarousel() {
  const [catalog, setCatalog] = useState<ThreatSpec[] | null>(null);
  const [idx, setIdx] = useState(0);
  const [simByType, setSimByType] = useState<Record<string, SimulatedAttack>>({});
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // 1) Fetch the catalog once so the menu + titles come from the backend.
  useEffect(() => {
    fetchJson<ThreatSpec[]>("/v1/threats/catalog")
      .then((data) => setCatalog(data.length ? data : null))
      .catch((e) => setErr((e as Error).message));
  }, []);

  // 2) When the current threat changes, lazy-load its simulation (and cache).
  useEffect(() => {
    if (!catalog) return;
    const spec = catalog[idx];
    if (!spec || simByType[spec.id]) return;
    setBusy(true);
    fetchJson<SimulatedAttack>(`/v1/simulate/attack?type=${encodeURIComponent(spec.id)}`, {
      method: "POST",
    })
      .then((data) => setSimByType((prev) => ({ ...prev, [spec.id]: data })))
      .catch((e) => setErr((e as Error).message))
      .finally(() => setBusy(false));
  }, [catalog, idx, simByType]);

  if (err && !catalog) {
    return (
      <div className="rounded-xl border border-rose-900/50 bg-rose-500/5 p-5 text-sm text-rose-300">
        Supervisor unreachable: {err}
      </div>
    );
  }

  if (!catalog) {
    return (
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-5 text-sm text-zinc-500">
        Loading live threat catalog…
      </div>
    );
  }

  const spec = catalog[idx];
  const sim = simByType[spec.id] ?? null;
  const tone = decisionTone(sim?.decision.decision ?? "deny", spec.severity);
  const primary = sim?.decision.threats[0];

  return (
    <div>
      <div className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950">
        <div className="flex items-center justify-between border-b border-zinc-800 bg-zinc-900/60 px-5 py-3">
          <div className="flex items-center gap-3">
            <span className={`h-2.5 w-2.5 rounded-full ${tone.dot}`} />
            <span className="font-semibold text-zinc-100">{spec.title}</span>
          </div>
          <div className="font-mono text-xs text-zinc-500">
            {idx + 1} / {catalog.length}
          </div>
        </div>

        <div className="grid gap-0 md:grid-cols-2">
          <div className="border-zinc-800 p-5 md:border-r">
            <div className="mb-3 font-mono text-xs uppercase tracking-widest text-zinc-500">
              input{" "}
              <span className="text-zinc-600">· POST /v1/simulate/attack?type={spec.id}</span>
            </div>
            <pre className="overflow-auto whitespace-pre-wrap break-words font-mono text-sm leading-relaxed text-zinc-300">
              {JSON.stringify(spec.sample_attack, null, 2)}
            </pre>
          </div>
          <div className="p-5">
            <div className="mb-3 font-mono text-xs uppercase tracking-widest text-zinc-500">
              supervisor response {busy && <span className="text-zinc-600">· live…</span>}
            </div>
            {err && !sim ? (
              <pre className="whitespace-pre-wrap font-mono text-sm leading-relaxed text-rose-400">
                error: {err}
              </pre>
            ) : !sim ? (
              <pre className="whitespace-pre-wrap font-mono text-sm leading-relaxed text-zinc-500">
                loading…
              </pre>
            ) : (
              <pre className={`whitespace-pre-wrap font-mono text-sm leading-relaxed ${tone.text}`}>
                {tone.label}
                {"\n"}
                {primary?.message ?? spec.one_liner}
                {sim.decision.reasons.length > 0 && `\nreasons: ${sim.decision.reasons.join(", ")}`}
              </pre>
            )}
          </div>
        </div>

        <div className="border-t border-zinc-800 bg-black/40 px-5 py-3 font-mono text-xs text-zinc-600">
          detector: <span className="text-zinc-400">{primary?.detector_id ?? spec.id}</span>
          <span className="mx-3">·</span>
          OWASP <span className="text-zinc-400">{primary?.owasp_ref ?? spec.owasp_ref}</span>
          <span className="mx-3">·</span>
          level <span className="text-zinc-400">{primary?.level ?? spec.severity}</span>
        </div>
      </div>

      <div className="mt-4 flex items-center gap-3">
        <button
          onClick={() => setIdx((i) => (i - 1 + catalog.length) % catalog.length)}
          className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-2 font-mono text-xs text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
        >
          ← prev
        </button>
        <button
          onClick={() => setIdx((i) => (i + 1) % catalog.length)}
          className="rounded-lg bg-emerald-500 px-4 py-2 font-mono text-xs font-semibold text-black hover:bg-emerald-400"
        >
          next scenario →
        </button>
        <div className="ml-auto flex gap-1.5">
          {catalog.map((_, i) => (
            <button
              key={i}
              onClick={() => setIdx(i)}
              className={`h-1.5 w-6 rounded-full transition-colors ${
                i === idx ? "bg-emerald-400" : "bg-zinc-800 hover:bg-zinc-700"
              }`}
              aria-label={`scenario ${i + 1}`}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
