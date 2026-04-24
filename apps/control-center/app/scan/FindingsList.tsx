"use client";

import { useState } from "react";
import type { ScanFinding, ScanResponse } from "@/lib/scans";

const TIER_ORDER = ["money", "real_world_actions", "customer_data", "business_data", "llm", "general"] as const;

const TIER_LABEL: Record<string, string> = {
  money: "money",
  real_world_actions: "real-world actions",
  customer_data: "customer data",
  business_data: "business data",
  llm: "llm",
  general: "general",
};

const TIER_COLOR: Record<string, string> = {
  money: "text-rose-400 border-rose-900/50",
  real_world_actions: "text-amber-400 border-amber-900/50",
  customer_data: "text-pink-400 border-pink-900/50",
  business_data: "text-yellow-400 border-yellow-900/50",
  llm: "text-cyan-400 border-cyan-900/50",
  general: "text-zinc-400 border-zinc-800",
};

export default function FindingsList({ scan }: { scan: ScanResponse }) {
  const findings = scan.findings ?? [];
  const summary = scan.repo_summary;
  const grouped = groupByTier(findings);
  const priorityCount = findings.filter((f) => isPriorityFinding(f)).length;
  const generalCount = grouped.general?.length ?? 0;

  return (
    <div className="mt-8 space-y-8">
      {summary && <SummaryCard summary={summary} elapsedMs={scan.elapsed_ms ?? 0} />}
      <BuilderUnlock
        findingsCount={findings.length}
        priorityCount={priorityCount}
        generalCount={generalCount}
        truncated={scan.findings_truncated}
      />

      {findings.length === 0 ? (
        <EmptyState />
      ) : (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-zinc-500">
            <span>
              <span className="font-mono text-emerald-400">{findings.length}</span> call-sites detected
              {scan.findings_truncated && (
                <span className="ml-2 text-xs text-amber-400">(truncated — run the CLI for the full set)</span>
              )}
            </span>
            <span className="font-mono text-xs">
              {scan.elapsed_ms ? `${(scan.elapsed_ms / 1000).toFixed(1)}s` : ""}
            </span>
          </div>

          <PriorityBrief grouped={grouped} />

          {TIER_ORDER.filter((t) => grouped[t]?.length).map((tier) => (
            <TierSection
              key={tier}
              tier={tier}
              findings={grouped[tier] ?? []}
              collapsed={tier === "general"}
              limit={tier === "general" ? 25 : 80}
            />
          ))}
        </>
      )}

      <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-5">
        <div className="grid gap-4 text-sm text-zinc-400 md:grid-cols-[1fr_auto] md:items-center">
          <div>
            Run the local CLI for the complete artifact bundle: stubs, YAML policies,
            combo playbooks, and CI workflow.
            <div className="mt-2">
              <code className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-xs text-zinc-200">
                pipx install supervisor-discover
              </code>{" "}
              <code className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-xs text-zinc-200">
                supervisor-discover scan
              </code>
            </div>
          </div>
          <BuilderUpgradeButton />
        </div>
      </div>

    </div>
  );
}

function BuilderUpgradeButton() {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setErr(null);
    try {
      const res = await fetch("/api/billing/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const data = (await res.json()) as { url?: string; detail?: string };
      if (!res.ok || !data.url) {
        throw new Error(data.detail ?? `checkout failed (${res.status})`);
      }
      window.location.href = data.url;
    } catch (e) {
      setErr((e as Error).message);
      setBusy(false);
    }
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="rounded-lg bg-emerald-500 px-4 py-2 text-center text-sm font-semibold text-black hover:bg-emerald-400"
      >
        unlock Builder — $29/mo
      </button>
    );
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-2 sm:flex-row sm:items-center">
      <input
        type="email"
        required
        autoFocus
        placeholder="you@company.com"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        className="w-full rounded-lg border border-zinc-800 bg-black/40 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 sm:w-64"
      />
      <button
        type="submit"
        disabled={busy || !email}
        className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-black hover:bg-emerald-400 disabled:opacity-50"
      >
        {busy ? "redirecting…" : "checkout →"}
      </button>
      {err && <span className="text-xs text-rose-400 sm:ml-2">{err}</span>}
    </form>
  );
}

function BuilderUnlock({
  findingsCount,
  priorityCount,
  generalCount,
  truncated,
}: {
  findingsCount: number;
  priorityCount: number;
  generalCount: number;
  truncated: boolean;
}) {
  return (
    <div className="rounded-xl border border-emerald-900/50 bg-emerald-500/5 p-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">free scan complete</div>
          <p className="mt-2 max-w-2xl text-sm leading-7 text-zinc-300">
            This preview shows the risk shape of the repo. Builder unlocks private repos,
            full exports, scan history, and CI comments so you can turn these findings into fixes.
          </p>
          {truncated && (
            <p className="mt-2 text-xs text-amber-400">
              Preview truncated after priority sorting. Builder and local CLI exports include the complete finding set.
            </p>
          )}
        </div>
        <div className="grid min-w-56 gap-3 rounded-lg border border-zinc-800 bg-black/40 p-4 text-right sm:grid-cols-3">
          <MiniStat value={String(priorityCount)} label="priority" />
          <MiniStat value={String(generalCount)} label="general" />
          <MiniStat value={String(findingsCount)} label="preview" />
        </div>
      </div>
    </div>
  );
}

function MiniStat({ value, label }: { value: string; label: string }) {
  return (
    <div>
      <div className="font-mono text-xl font-semibold text-zinc-100">{value}</div>
      <div className="mt-1 font-mono text-[10px] uppercase tracking-widest text-zinc-600">{label}</div>
    </div>
  );
}

function PriorityBrief({ grouped }: { grouped: Record<string, ScanFinding[]> }) {
  const rows = TIER_ORDER
    .filter((tier) => tier !== "general")
    .map((tier) => ({ tier, count: grouped[tier]?.length ?? 0 }))
    .filter((r) => r.count > 0);

  if (rows.length === 0) {
    return (
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5">
        <div className="font-mono text-xs uppercase tracking-widest text-zinc-500">priority findings</div>
        <p className="mt-2 text-sm text-zinc-400">
          No money, customer-data, real-world-action, business-data, or LLM findings appeared in this preview.
          General routes are listed below as context.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">priority findings</div>
          <p className="mt-2 text-sm text-zinc-400">
            Start here. These are the call-sites most likely to need a supervisor wrapper.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {rows.map(({ tier, count }) => (
            <span key={tier} className={`rounded border px-2.5 py-1 font-mono text-xs ${TIER_COLOR[tier] ?? TIER_COLOR.general}`}>
              {TIER_LABEL[tier] ?? tier}: {count}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

function TierSection({
  tier,
  findings,
  collapsed = false,
  limit = 80,
}: {
  tier: string;
  findings: ScanFinding[];
  collapsed?: boolean;
  limit?: number;
}) {
  const color = TIER_COLOR[tier] ?? TIER_COLOR.general;
  const visible = findings.slice(0, limit);
  const hiddenCount = Math.max(0, findings.length - visible.length);
  return (
    <div className={`rounded-xl border bg-zinc-900/40 ${color}`}>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-inherit px-5 py-3">
        <div>
          <div className={`font-mono text-xs uppercase tracking-widest ${color.split(" ")[0]}`}>
            # {TIER_LABEL[tier] ?? tier}
          </div>
          {tier === "general" && (
            <p className="mt-1 text-xs text-zinc-500">
              Route inventory and lower-confidence context. Use this after priority findings.
            </p>
          )}
        </div>
        <div className="font-mono text-xs text-zinc-500">
          {findings.length} call-sites{hiddenCount > 0 ? ` - showing ${visible.length}` : ""}
        </div>
      </div>
      {collapsed ? (
        <details>
          <summary className="cursor-pointer px-5 py-4 text-sm text-zinc-400 hover:text-zinc-200">
            Open general inventory
          </summary>
          <FindingRows findings={visible} />
        </details>
      ) : (
        <FindingRows findings={visible} />
      )}
      {hiddenCount > 0 && (
        <div className="border-t border-zinc-800 px-5 py-3 text-xs text-zinc-500">
          {hiddenCount} more in this tier. Run the CLI or Builder export for the full list.
        </div>
      )}
    </div>
  );
}

function FindingRows({ findings }: { findings: ScanFinding[] }) {
  return (
    <ul className="divide-y divide-zinc-800">
      {findings.map((f, i) => (
        <FindingRow key={`${f.file}:${f.line}:${f.scanner}:${i}`} f={f} />
      ))}
    </ul>
  );
}

function SummaryCard({ summary, elapsedMs }: { summary: NonNullable<ScanResponse["repo_summary"]>; elapsedMs: number }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-6">
      <div className="text-xs font-mono uppercase tracking-widest text-emerald-400">what we found</div>
      <p className="mt-3 text-xl leading-relaxed text-zinc-100">
        <OneLiner text={summary.one_liner || "no critical integrations detected"} />
      </p>
      <div className="mt-5 grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-3">
        {summary.frameworks.length > 0 && (
          <Stat label="stack" value={summary.frameworks.join(" + ")} />
        )}
        {summary.http_routes > 0 && <Stat label="http routes" value={String(summary.http_routes)} />}
        {Object.keys(summary.payment_integrations).length > 0 && (
          <Stat
            label="payments"
            value={Object.entries(summary.payment_integrations)
              .map(([vendor, caps]) => (caps.length ? `${vendor} (${caps.join(", ")})` : vendor))
              .join(", ")}
          />
        )}
        {summary.llm_providers.length > 0 && <Stat label="llm providers" value={summary.llm_providers.join(", ")} />}
        {Object.keys(summary.real_world_actions).length > 0 && (
          <Stat
            label="real-world actions"
            value={Object.entries(summary.real_world_actions)
              .map(([cap, providers]) => `${cap.split(" ")[0]} (${providers.join(", ")})`)
              .join(" · ")}
          />
        )}
        {summary.agent_chokepoints.length > 0 && (
          <Stat label="agent chokepoints" value={String(summary.agent_chokepoints.length)} />
        )}
        {summary.agent_tools.length > 0 && (
          <Stat label="tools exposed" value={String(summary.agent_tools.length)} />
        )}
        {summary.sensitive_tables.length > 0 && (
          <Stat label="sensitive tables" value={summary.sensitive_tables.slice(0, 5).join(", ")} />
        )}
        {summary.scheduled_jobs > 0 && <Stat label="scheduled jobs" value={String(summary.scheduled_jobs)} />}
        <Stat label="total findings" value={String(summary.total_findings)} />
        {elapsedMs > 0 && <Stat label="scan time" value={`${(elapsedMs / 1000).toFixed(1)}s`} />}
      </div>
    </div>
  );
}

function OneLiner({ text }: { text: string }) {
  // The one_liner from the backend can embed **bold** markers — render them.
  const parts = text.split(/(\*\*[^*]+\*\*)/);
  return (
    <>
      {parts.map((part, i) =>
        part.startsWith("**") && part.endsWith("**") ? (
          <strong key={i} className="font-semibold text-emerald-300">
            {part.slice(2, -2)}
          </strong>
        ) : (
          <span key={i}>{part}</span>
        ),
      )}
    </>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="font-mono text-xs uppercase tracking-widest text-zinc-500">{label}</div>
      <div className="mt-1 text-zinc-200">{value}</div>
    </div>
  );
}

function FindingRow({ f }: { f: ScanFinding }) {
  const [open, setOpen] = useState(false);
  const confDot =
    f.confidence === "high" ? "bg-emerald-500" : f.confidence === "medium" ? "bg-amber-500" : "bg-zinc-600";
  return (
    <li className="px-5 py-3 text-sm">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-3 text-left"
      >
        <span className={`mt-1.5 h-2 w-2 flex-shrink-0 rounded-full ${confDot}`} title={`confidence: ${f.confidence}`} />
        <div className="flex-1">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="font-mono text-xs text-emerald-400">{f.scanner}</span>
            <span className="font-mono text-zinc-300">{f.file}</span>
            <span className="font-mono text-xs text-zinc-500">:{f.line}</span>
            <span className="ml-auto rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-widest text-zinc-400">
              {f.suggested_action_type}
            </span>
          </div>
          <p className="mt-1 text-xs text-zinc-500">{f.rationale}</p>
        </div>
      </button>
      {open && (
        <pre className="mt-3 overflow-auto rounded-lg border border-zinc-800 bg-black/50 p-3 font-mono text-xs leading-relaxed text-zinc-300">
          {f.snippet}
        </pre>
      )}
    </li>
  );
}

function EmptyState() {
  return (
    <div className="rounded-xl border border-emerald-900/40 bg-emerald-500/5 p-6 text-center">
      <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">clean</div>
      <p className="mt-3 text-lg text-zinc-200">
        No unsafe actions detected in this repo.
      </p>
      <p className="mt-2 text-sm text-zinc-500">
        Either the code is already wrapping sensitive calls, or the repo doesn&apos;t contain agent-grade
        integrations (Stripe, DB mutations, LLM SDKs, etc).
      </p>
    </div>
  );
}

function groupByTier(findings: ScanFinding[]): Record<string, ScanFinding[]> {
  const out: Record<string, ScanFinding[]> = {};
  for (const f of findings) {
    const key = f.tier ?? "general";
    (out[key] ??= []).push(f);
  }
  return out;
}

function isPriorityFinding(f: ScanFinding): boolean {
  return (f.tier ?? "general") !== "general";
}
