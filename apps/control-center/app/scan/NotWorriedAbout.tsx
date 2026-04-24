"use client";

import type { RepoSummary, ScanFinding } from "@/lib/scans";

/**
 * "What I'm not worried about" — required by VOICE.md rule #9: present in
 * every report when applicable, reduces anxiety and signals criterion.
 *
 * Items are derived from RepoSummary + findings, never hardcoded. The UI only
 * emits a bullet when the underlying data backs it up.
 */
export default function NotWorriedAbout({
  summary,
  findings,
}: {
  summary: RepoSummary;
  findings: ScanFinding[];
}) {
  const items = deriveItems(summary, findings);
  if (items.length === 0) return null;

  return (
    <section className="rounded-xl border border-emerald-900/40 bg-emerald-500/5 p-5">
      <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">
        what I&apos;m not worried about
      </div>
      <ul className="mt-3 space-y-2 text-sm text-zinc-300">
        {items.map((line, i) => (
          <li key={i} className="flex gap-2">
            <span className="text-emerald-400">✓</span>
            <span>{line}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function deriveItems(summary: RepoSummary, findings: ScanFinding[]): string[] {
  const items: string[] = [];

  if (Object.keys(summary.payment_integrations).length === 0) {
    items.push("No payment SDKs detected.");
  }

  const sensitive = new Set((summary.sensitive_tables ?? []).map((t) => t.toLowerCase()));
  const hasCustomerMutation = findings.some((f) => {
    if (f.scanner !== "db-mutations") return false;
    const extra = (f.extra ?? {}) as Record<string, unknown>;
    const verb = String(extra.verb ?? "").toUpperCase();
    const table = String(extra.table ?? "").toLowerCase();
    return (verb === "UPDATE" || verb === "DELETE") && sensitive.has(table);
  });
  if (!hasCustomerMutation) {
    items.push("No direct UPDATE/DELETE on customer tables.");
  }

  if (summary.scheduled_jobs === 0) {
    items.push("No scheduled jobs detected.");
  }

  const hasToolSurface =
    (summary.agent_tools?.length ?? 0) > 0 || (summary.mcp_tools?.length ?? 0) > 0;
  if (!hasToolSurface) {
    items.push("No tool-use surface exposed.");
  }

  return items;
}
