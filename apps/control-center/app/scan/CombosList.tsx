"use client";

import type { ScanCombo } from "@/lib/scans";

/**
 * Critical combos — attack paths the agent can chain, rendered per VOICE.md
 * template: Why it matters / Evidence / Minimum guard / Ideal guard.
 *
 * Source of truth is `detect_combos()` in supervisor-discover (backend).
 * This component only formats; drift between what the scanner detects and
 * what the UI shows is impossible by construction.
 */

const SEVERITY_BADGE: Record<ScanCombo["severity"], { dot: string; label: string; tone: string }> = {
  critical: { dot: "🔴", label: "critical combo", tone: "border-rose-900/60 bg-rose-500/5 text-rose-300" },
  high: { dot: "🟠", label: "high combo", tone: "border-amber-900/60 bg-amber-500/5 text-amber-300" },
  medium: { dot: "🟡", label: "combo", tone: "border-yellow-900/50 bg-yellow-500/5 text-yellow-200" },
};

export default function CombosList({ combos }: { combos: ScanCombo[] }) {
  if (!combos.length) return null;

  const ordered = [...combos].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

  return (
    <section className="rounded-xl border border-rose-900/40 bg-rose-950/10 p-6">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <div>
          <div className="font-mono text-xs uppercase tracking-widest text-rose-300">critical combos</div>
          <p className="mt-2 max-w-2xl text-sm text-zinc-300">
            Pairs of capabilities that are worse together than alone. Gate the combo, not just
            the individual tools.
          </p>
        </div>
        <span className="rounded border border-rose-900/60 bg-rose-500/10 px-2.5 py-1 font-mono text-xs text-rose-300">
          {combos.length} detected
        </span>
      </div>
      <div className="mt-5 grid gap-4">
        {ordered.map((c) => (
          <ComboCard key={c.id} combo={c} />
        ))}
      </div>
    </section>
  );
}

function ComboCard({ combo }: { combo: ScanCombo }) {
  const badge = SEVERITY_BADGE[combo.severity] ?? SEVERITY_BADGE.medium;
  const { minimumGuard, idealGuard } = splitMitigation(combo.mitigation);
  return (
    <article className={`rounded-lg border p-5 ${badge.tone}`}>
      <header className="flex flex-wrap items-center gap-3">
        <span className="text-lg leading-none">{badge.dot}</span>
        <h3 className="font-mono text-sm font-semibold tracking-wide text-zinc-100">{combo.title}</h3>
        <span className="ml-auto rounded bg-black/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-widest text-zinc-400">
          {badge.label}
        </span>
      </header>

      <div className="mt-4 space-y-4 text-sm leading-relaxed text-zinc-300">
        <ComboBlock label="Why it matters" body={combo.narrative} />

        {combo.evidence.length > 0 && (
          <div>
            <div className="font-mono text-xs uppercase tracking-widest text-zinc-500">Evidence</div>
            <ul className="mt-2 space-y-1 font-mono text-xs text-zinc-300">
              {combo.evidence.map((e, i) => (
                <li key={i}>
                  <span className="text-zinc-600">·</span> {e}
                </li>
              ))}
            </ul>
          </div>
        )}

        {minimumGuard && <ComboBlock label="Minimum guard" body={minimumGuard} />}
        {idealGuard && <ComboBlock label="Ideal guard" body={idealGuard} />}
        {!minimumGuard && !idealGuard && combo.mitigation && (
          <ComboBlock label="Guard" body={combo.mitigation} />
        )}
      </div>
    </article>
  );
}

function ComboBlock({ label, body }: { label: string; body: string }) {
  return (
    <div>
      <div className="font-mono text-xs uppercase tracking-widest text-zinc-500">{label}</div>
      <p className="mt-1">{body}</p>
    </div>
  );
}

function severityRank(s: ScanCombo["severity"]): number {
  return s === "critical" ? 0 : s === "high" ? 1 : 2;
}

/**
 * The scanner already emits mitigations in the VOICE.md shape, e.g.
 *   "Minimum guard: allowlist destination numbers… Ideal guard: any
 *    voice-clone + outbound pair in the same trace goes to human review."
 * Split on the literal anchors so we can render them as separate blocks
 * (and fall back to a single block if the shape isn't present).
 */
function splitMitigation(mitigation: string): { minimumGuard: string | null; idealGuard: string | null } {
  const minMatch = mitigation.match(/Minimum guard:\s*([\s\S]*?)(?=\s*Ideal guard:|$)/i);
  const idealMatch = mitigation.match(/Ideal guard:\s*([\s\S]*)$/i);
  return {
    minimumGuard: minMatch ? minMatch[1].trim().replace(/\.$/, "") : null,
    idealGuard: idealMatch ? idealMatch[1].trim().replace(/\.$/, "") : null,
  };
}
