"use client";

import { useState } from "react";
import { buildEnglishBanner, type ScanFinding, type ScanResponse } from "@/lib/scans";
import CombosList from "./CombosList";
import NotWorriedAbout from "./NotWorriedAbout";
import ZeroConfigPanel from "./ZeroConfigPanel";

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

// Family labels / colors for sub-grouping inside a tier. The fs-shell scanner
// emits `extra.family` ∈ {shell-exec, fs-delete, fs-write}; agent-orchestrators
// emits `extra.kind` ∈ {tool-registration, framework-import, agent-class,
// agent-method}. Map both to a friendly label + tone so groups render with
// distinct severity hints.
const FAMILY_LABEL: Record<string, string> = {
  "shell-exec": "Shell execution",
  "fs-delete": "Destructive filesystem",
  "fs-write": "Filesystem writes",
  "tool-registration": "Tool registrations",
  "framework-import": "Agent framework imports",
  "agent-class": "Agent orchestrator classes",
  "agent-method": "Agent orchestrator methods",
  // Skill / plugin artifacts — content-review surfaces, not code wraps.
  "skill": "Skill instructions",
  "agent-md": "Agent personas",
  "command-md": "Slash commands",
  "plugin-manifest": "Plugin manifest",
  "claude-md": "Repo-wide CLAUDE.md",
  // LLM call construction (new TS regex)
  "construction": "LLM client construction",
  "method-call": "LLM method calls",
};

const FAMILY_TONE: Record<string, string> = {
  "shell-exec": "text-rose-400",      // RCE-equivalent
  "fs-delete": "text-rose-400",       // irreversible
  "fs-write": "text-amber-400",       // context-dependent
  "tool-registration": "text-emerald-400",
  "framework-import": "text-emerald-400",
  "agent-class": "text-emerald-400",
  "agent-method": "text-emerald-300",
  "skill": "text-purple-400",
  "agent-md": "text-purple-400",
  "command-md": "text-purple-300",
  "plugin-manifest": "text-purple-400",
  "claude-md": "text-purple-300",
  "construction": "text-cyan-400",
  "method-call": "text-cyan-400",
};

function familyOf(f: ScanFinding): string {
  const extra = (f.extra ?? {}) as Record<string, unknown>;
  const key = (extra.family as string | undefined) ?? (extra.kind as string | undefined);
  return key ?? f.scanner;
}

// Copy-paste @supervised wrap pattern per family. Shown inline in each
// FamilyGroup so the dev gets a fix to try without leaving the page.
const FAMILY_REMEDY: Record<string, string> = {
  "shell-exec": `from supervisor_guards import supervised

@supervised("tool_use", payload=lambda cmd, **_: {"command": str(cmd)})
def safe_run(cmd, *args, **kw):
    return subprocess.run(cmd, *args, **kw)`,
  "fs-delete": `from supervisor_guards import supervised

@supervised("tool_use", payload=lambda path, **_: {"path": str(path)})
def safe_unlink(path):
    Path(path).unlink()`,
  "fs-write": `from supervisor_guards import supervised

@supervised("tool_use", payload=lambda path, **_: {"path": str(path)})
def safe_write(path, content):
    with open(path, "w") as f:
        f.write(content)`,
  "mcp-tool": `// Wrap each tool registration so every call goes through the supervisor.
import { supervised } from "@runtime-supervisor/guards";

server.tool("your-tool-name", supervised("tool_use",
  async (args) => { /* your existing handler */ }
));`,
  "mcp-dispatcher": `// Wrap the CallTool dispatcher — gates EVERY tool with one decorator.
import { supervised } from "@runtime-supervisor/guards";

server.setRequestHandler(CallToolRequestSchema, supervised("tool_use",
  async (request) => { /* your existing handler */ }
));`,
  "mcp-server-instance": `// Wrap the dispatcher (CallTool handler) on this Server instance —
// see "Shell execution" / "Filesystem" sections for handler wrap patterns.`,
  "tool-registration": `# Wrap the dispatcher OR each registered tool individually:
from supervisor_guards import supervised

@supervised("tool_use")
def your_tool_handler(args):
    # your existing handler
    pass`,
  "framework-import": `# Wrap the framework's executor entry-point — one wrap, all tools covered:
from supervisor_guards import supervised

executor = AgentExecutor(...)
executor.invoke = supervised("tool_use")(executor.invoke)`,
  "agent-class": `# Wrap the orchestrator method that dispatches to tools:
from supervisor_guards import supervised

class Controller:
    @supervised("tool_use")
    def handle(self, intent, ...):
        # your existing handler
        pass`,
  "agent-method": `# This method is the dispatch point — wrap it:
from supervisor_guards import supervised

class Orchestrator:
    @supervised("tool_use")
    def dispatch(self, ...):
        # your existing dispatch
        pass`,
  // Skill artifacts: there's no Python/TS to wrap. The fix is content-review.
  "skill": `# This is markdown, not code — no @supervised wrap.
# Treat it like an untrusted dependency:
#   1. Read SKILL.md before activating.
#   2. Pin to a commit you trust (don't follow the branch).
#   3. Re-audit on every update.`,
  "agent-md": `# Same as skills — read the persona before adopting.
# Pin the commit and re-audit on changes.`,
  "command-md": `# Read the command body for shell-out steps and parameter handling
# before installing into your Claude Code session.`,
  "plugin-manifest": `# Inspect declared scopes (file reads, shell commands, network)
# in the manifest before installing.`,
  "claude-md": `# Repo-wide instructions Claude reads first. Treat edits like a
# security review — anything here can grant tools or skip confirmations.`,
  "construction": `// Wrap whatever module exposes this client to its callers:
import { supervised } from "@runtime-supervisor/guards";

export const callLLM = supervised("tool_use",
  async (prompt: string) => client.responses.create({ model, prompt })
);`,
  "method-call": `// Wrap the call site (or the function that owns it):
import { supervised } from "@runtime-supervisor/guards";

const reply = await supervised("tool_use",
  async () => generateText({ model, prompt: userInput })
)();`,
};

export default function FindingsList({ scan }: { scan: ScanResponse }) {
  const rawFindings = scan.findings ?? [];
  const summary = scan.repo_summary;
  // Free tier: for priority tiers (money / real_world_actions / customer_data
  // / business_data / llm), show only confidence=high. Everything in the
  // `general` tier (http-routes inventory) stays visible regardless. Hidden
  // count powers the Builder upsell — the cut is transparent, not a silent trim.
  const { visible: findings, hidden: hiddenCount } = applyFreeConfidenceGate(rawFindings);
  const grouped = groupByTier(findings);
  const priorityCount = findings.filter((f) => isPriorityFinding(f)).length;
  const generalCount = grouped.general?.length ?? 0;

  const combos = scan.combos ?? [];

  return (
    <div className="mt-8 space-y-8">
      {summary && <SummaryCard summary={summary} elapsedMs={scan.elapsed_ms ?? 0} />}
      {combos.length > 0 && <CombosList combos={combos} />}
      {summary && <NotWorriedAbout summary={summary} findings={rawFindings} />}
      <ZeroConfigPanel />
      <BuilderUnlock
        findingsCount={findings.length}
        priorityCount={priorityCount}
        generalCount={generalCount}
        hiddenCount={hiddenCount}
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
            <pre className="mt-3 overflow-auto rounded-lg border border-zinc-800 bg-black/60 p-3 font-mono text-xs leading-6 text-zinc-200">
              <span className="text-zinc-500">$ </span>pipx install supervisor-discover{"\n"}
              <span className="text-zinc-500">$ </span>supervisor-discover scan
            </pre>
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
  hiddenCount,
  truncated,
}: {
  findingsCount: number;
  priorityCount: number;
  generalCount: number;
  hiddenCount: number;
  truncated: boolean;
}) {
  return (
    <div className="rounded-xl border border-emerald-900/50 bg-emerald-500/5 p-5">
      <div className="flex flex-wrap items-start justify-between gap-6">
        <div className="max-w-2xl">
          <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">free scan complete</div>
          <p className="mt-2 text-sm leading-7 text-zinc-300">
            This preview shows the risk shape of the repo.
          </p>
          <div className="mt-4 text-sm text-zinc-300">
            <div className="font-mono text-xs uppercase tracking-widest text-zinc-500">Builder unlocks</div>
            <ul className="mt-2 space-y-1 text-sm">
              <BuilderBullet>private GitHub repos</BuilderBullet>
              <BuilderBullet>full runtime-supervisor/ export</BuilderBullet>
              <BuilderBullet>copy-paste stubs</BuilderBullet>
              <BuilderBullet>YAML policies</BuilderBullet>
              <BuilderBullet>scan history and diffs</BuilderBullet>
              <BuilderBullet>CI and PR comments</BuilderBullet>
            </ul>
          </div>
          {hiddenCount > 0 && (
            <p className="mt-4 font-mono text-xs text-emerald-400">
              + {hiddenCount} medium-confidence finding{hiddenCount === 1 ? "" : "s"} hidden
            </p>
          )}
          {truncated && (
            <p className="mt-2 font-mono text-xs text-amber-400">
              preview truncated — Builder returns the full set
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

function BuilderBullet({ children }: { children: React.ReactNode }) {
  return (
    <li className="flex gap-2 text-zinc-300">
      <span className="text-emerald-400">✓</span>
      <span>{children}</span>
    </li>
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
  const groups = groupByFamily(visible);
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
          <FamilyGroups groups={groups} />
        </details>
      ) : (
        <FamilyGroups groups={groups} />
      )}
      {hiddenCount > 0 && (
        <div className="border-t border-zinc-800 px-5 py-3 text-xs text-zinc-500">
          {hiddenCount} more in this tier. Run the CLI or Builder export for the full list.
        </div>
      )}
    </div>
  );
}

function FamilyGroups({ groups }: { groups: ScanFinding[][] }) {
  return (
    <div className="divide-y divide-zinc-800">
      {groups.map((group, i) => {
        if (group.length === 1) {
          // Single finding — keep the original row layout so the rationale is
          // visible for the only call-site in the group.
          const f = group[0];
          return (
            <ul key={`${f.file}:${f.line}:${i}`} className="divide-y divide-zinc-800">
              <FindingRow f={f} />
            </ul>
          );
        }
        return <FamilyGroup key={i} findings={group} />;
      })}
    </div>
  );
}

function FamilyGroup({ findings }: { findings: ScanFinding[] }) {
  const [expanded, setExpanded] = useState(false);
  const [showRemedy, setShowRemedy] = useState(false);
  const first = findings[0];
  const family = familyOf(first);
  const label = FAMILY_LABEL[family] ?? family;
  const tone = FAMILY_TONE[family] ?? "text-zinc-400";
  const remedy = FAMILY_REMEDY[family];
  const visible = expanded ? findings : findings.slice(0, 5);
  const hidden = findings.length - visible.length;
  return (
    <div className="px-5 py-4">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className={`font-mono text-xs uppercase tracking-widest ${tone}`}>{label}</span>
        <span className="font-mono text-xs text-zinc-500">· {findings.length} call-sites</span>
        <span className="ml-auto rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-widest text-zinc-400">
          {first.suggested_action_type}
        </span>
      </div>
      <p className="mt-2 max-w-3xl text-xs leading-6 text-zinc-400">{first.rationale}</p>
      <ul className="mt-3 space-y-1">
        {visible.map((f, i) => (
          <li key={`${f.file}:${f.line}:${i}`} className="font-mono text-xs text-zinc-300">
            <span className="text-zinc-600">·</span>{" "}
            <span className="text-zinc-300">{f.file}</span>
            <span className="text-zinc-500">:{f.line}</span>
            {f.snippet && (
              <span className="ml-3 text-zinc-500">{shortSnippet(f.snippet)}</span>
            )}
          </li>
        ))}
      </ul>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        {hidden > 0 && (
          <button
            type="button"
            onClick={() => setExpanded(true)}
            className="font-mono text-xs text-emerald-400 hover:text-emerald-300"
          >
            show {hidden} more ▾
          </button>
        )}
        {remedy && (
          <button
            type="button"
            onClick={() => setShowRemedy((v) => !v)}
            className="font-mono text-xs text-zinc-500 hover:text-zinc-300"
          >
            {showRemedy ? "hide fix ▴" : "see fix snippet ▾"}
          </button>
        )}
      </div>
      {remedy && showRemedy && (
        <pre className="mt-3 overflow-auto rounded-lg border border-emerald-900/30 bg-emerald-500/5 p-3 font-mono text-xs leading-6 text-zinc-200">
          {remedy}
        </pre>
      )}
    </div>
  );
}

function shortSnippet(s: string): string {
  const flat = s.replace(/\s+/g, " ").trim();
  return flat.length > 60 ? flat.slice(0, 57) + "…" : flat;
}

function groupByFamily(findings: ScanFinding[]): ScanFinding[][] {
  // Preserve input order for first occurrences, then cluster.
  const keyOrder: string[] = [];
  const buckets = new Map<string, ScanFinding[]>();
  for (const f of findings) {
    const key = `${f.scanner}::${familyOf(f)}`;
    if (!buckets.has(key)) {
      keyOrder.push(key);
      buckets.set(key, []);
    }
    buckets.get(key)!.push(f);
  }
  return keyOrder.map((k) => buckets.get(k)!);
}

function SummaryCard({ summary, elapsedMs }: { summary: NonNullable<ScanResponse["repo_summary"]>; elapsedMs: number }) {
  // RepoSummary.one_liner is produced in Spanish by the scanner; rebuild in
  // English from structured fields (see buildEnglishBanner in lib/scans.ts).
  const banner = buildEnglishBanner(summary);
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-6">
      <div className="text-xs font-mono uppercase tracking-widest text-emerald-400">what we found</div>
      <p className="mt-3 text-xl leading-relaxed text-zinc-100">
        Scanned <strong className="font-semibold text-emerald-300">{banner}</strong>.
      </p>
      <RepoTypeCallout summary={summary} />
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
        {(summary.mcp_tools?.length ?? 0) > 0 && (
          <Stat label="mcp tools" value={String(summary.mcp_tools?.length ?? 0)} />
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

// Type-specific guidance shown above the stats grid. Each repo_type gets a
// short callout that tells the dev what the highest-leverage wrap is for
// THIS shape of repo, instead of the generic "review the findings list".
function RepoTypeCallout({ summary }: { summary: NonNullable<ScanResponse["repo_summary"]> }) {
  const type = summary.repo_type;
  if (!type) return null;
  const mcpToolCount = summary.mcp_tools?.length ?? 0;
  if (type === "mcp-server" || type === "mcp-server+langchain") {
    return (
      <div className="mt-4 rounded-lg border border-cyan-900/40 bg-cyan-500/5 p-4 text-sm leading-7 text-zinc-300">
        <span className="font-mono text-xs uppercase tracking-widest text-cyan-400">mcp server detected</span>
        <p className="mt-1">
          The MCP CallTool dispatcher is your highest-leverage wrap point. One{" "}
          <code className="rounded bg-zinc-800 px-1 py-0.5 font-mono text-xs">@supervised(&quot;tool_use&quot;)</code>{" "}
          on{" "}
          <code className="rounded bg-zinc-800 px-1 py-0.5 font-mono text-xs">setRequestHandler(CallToolRequestSchema, …)</code>{" "}
          gates all{mcpToolCount > 0 ? ` ${mcpToolCount}` : ""} tools at once — see the
          <span className="font-mono"> mcp-dispatcher</span> finding below for the snippet.
        </p>
      </div>
    );
  }
  if (type === "langchain-agent") {
    return (
      <div className="mt-4 rounded-lg border border-emerald-900/40 bg-emerald-500/5 p-4 text-sm leading-7 text-zinc-300">
        <span className="font-mono text-xs uppercase tracking-widest text-emerald-400">langchain agent detected</span>
        <p className="mt-1">
          The AgentExecutor is your chokepoint. Wrap{" "}
          <code className="rounded bg-zinc-800 px-1 py-0.5 font-mono text-xs">executor.invoke</code>{" "}
          with <code className="rounded bg-zinc-800 px-1 py-0.5 font-mono text-xs">@supervised(&quot;tool_use&quot;)</code>{" "}
          — covers every tool the agent calls, present and future. See the framework-import finding for the snippet.
        </p>
      </div>
    );
  }
  if (type === "claude-skill") {
    return (
      <div className="mt-4 rounded-lg border border-purple-900/40 bg-purple-500/5 p-4 text-sm leading-7 text-zinc-300">
        <span className="font-mono text-xs uppercase tracking-widest text-purple-400">claude code skill / plugin detected</span>
        <p className="mt-1">
          This repo distributes prompts Claude Code reads at runtime — there&apos;s no wrappable
          call-site here, the fix is <strong>content-review</strong>. Read every SKILL.md, agent persona,
          and slash command before activating, and pin to a commit you trust (don&apos;t follow the branch).
          Anyone with PR access to this repo can change Claude&apos;s behavior in your dev environment.
        </p>
      </div>
    );
  }
  return null;
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

/**
 * Free-tier confidence gate. Priority-tier findings with confidence below
 * `high` are hidden behind the Builder paywall; general-tier (route inventory)
 * passes through untouched so the repo context stays visible.
 *
 * Returns both the visible set and the hidden count so the BuilderUnlock card
 * can show an explicit upsell ("N findings hidden — unlock Builder…") rather
 * than silently trimming.
 */
function applyFreeConfidenceGate(
  findings: ScanFinding[],
): { visible: ScanFinding[]; hidden: number } {
  let hidden = 0;
  const visible: ScanFinding[] = [];
  for (const f of findings) {
    if (isPriorityFinding(f) && f.confidence !== "high") {
      hidden++;
      continue;
    }
    visible.push(f);
  }
  return { visible, hidden };
}
