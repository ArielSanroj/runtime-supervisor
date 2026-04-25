"use client";

/**
 * StartHere — vibe-coder entry view, mirrors runtime-supervisor/START_HERE.md.
 *
 * Renders the four-question contract from docs/SCAN_COMMUNICATION_RULES.md:
 *   1. Best place to wrap first
 *   2. What this repo can already do
 *   3. Highest-risk things to care about now
 *   4. Do this now
 *   5. Ignore this for now
 *
 * Data is built server-side in supervisor_discover/start_here.py and shipped
 * via the API on `repo_summary.start_here`. This component does NO derivation
 * — if a field is empty, the empty-state copy from the Python module already
 * landed here.
 */

import { useState } from "react";
import type { Risk, StartHere as StartHereData, WrapTarget } from "@/lib/scans";

const FAMILY_TONE: Record<string, string> = {
  "fs-shell-shell-exec": "border-rose-900/50 bg-rose-500/5",
  "fs-shell-fs-delete": "border-rose-900/50 bg-rose-500/5",
  "fs-shell-fs-write": "border-amber-900/50 bg-amber-500/5",
  "payment-calls": "border-rose-900/50 bg-rose-500/5",
  "email-sends": "border-amber-900/50 bg-amber-500/5",
  "messaging": "border-amber-900/50 bg-amber-500/5",
  "voice-actions": "border-amber-900/50 bg-amber-500/5",
  "calendar-actions": "border-amber-900/50 bg-amber-500/5",
  "db-mutations-write": "border-pink-900/50 bg-pink-500/5",
  "db-mutations-delete": "border-pink-900/50 bg-pink-500/5",
  "llm-calls": "border-cyan-900/50 bg-cyan-500/5",
  "agent-orchestrators": "border-emerald-900/50 bg-emerald-500/5",
};

function shortPath(path: string): string {
  // Mirror Python's _short_path for consistent display: keep the last 3 parts.
  const parts = path.split("/").filter(Boolean);
  if (parts.length <= 3) return path;
  return parts.slice(-3).join("/");
}

export default function StartHere({ data }: { data: StartHereData | null | undefined }) {
  if (!data) return null;
  const hidden = data.hidden_counter ?? {};
  const hiddenTotal = Object.values(hidden).reduce((a, b) => a + b, 0);

  return (
    <div className="space-y-8">
      <BestPlaceToWrap targets={data.top_wrap_targets ?? []} />
      <WhatThisRepoCanDo capabilities={data.repo_capabilities ?? []} />
      <HighestRiskThings risks={data.top_risks ?? []} />
      <DoThisNow markdown={data.do_this_now ?? ""} />
      <IgnoreForNow hiddenTotal={hiddenTotal} hiddenBreakdown={hidden} />
    </div>
  );
}

function BestPlaceToWrap({ targets }: { targets: WrapTarget[] }) {
  return (
    <section className="rounded-xl border border-emerald-900/40 bg-emerald-500/5 p-6">
      <h2 className="font-mono text-xs uppercase tracking-widest text-emerald-400">
        best place to wrap first
      </h2>
      {targets.length === 0 ? (
        <p className="mt-3 text-zinc-300">
          No obvious wrap target. Start with the entry-point of your agent loop —
          the function that decides which tool to call.
        </p>
      ) : (
        <>
          <ol className="mt-4 space-y-3">
            {targets.map((t, i) => (
              <li key={`${t.file}:${t.line}:${i}`}>
                <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                  <span className="font-mono text-sm text-emerald-300">
                    {i + 1}.
                  </span>
                  <span className="text-base font-semibold text-zinc-100">
                    {t.label}
                  </span>
                  <CopyablePath path={t.file} line={t.line} />
                </div>
                <p className="mt-1 ml-7 text-sm text-zinc-400 italic">
                  {t.why}
                </p>
              </li>
            ))}
          </ol>
          <p className="mt-5 text-xs text-zinc-500 italic">
            Why this first: one wrapper here covers most current and future tools.
          </p>
        </>
      )}
    </section>
  );
}

function CopyablePath({ path, line }: { path: string; line: number }) {
  const [copied, setCopied] = useState(false);
  const display = `${shortPath(path)}:${line}`;
  const onClick = async () => {
    try {
      await navigator.clipboard.writeText(`${path}:${line}`);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable; harmless */
    }
  };
  return (
    <button
      type="button"
      onClick={onClick}
      className="rounded bg-zinc-800/70 px-2 py-0.5 font-mono text-xs text-zinc-300 hover:bg-zinc-700"
      title="Copy full path"
    >
      {copied ? "copied" : display}
    </button>
  );
}

function WhatThisRepoCanDo({ capabilities }: { capabilities: string[] }) {
  return (
    <section className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-6">
      <h2 className="font-mono text-xs uppercase tracking-widest text-amber-400">
        what this repo can already do
      </h2>
      {capabilities.length === 0 ? (
        <p className="mt-3 text-zinc-300">
          No high-stakes capabilities detected in this preview.
        </p>
      ) : (
        <>
          <p className="mt-3 text-zinc-300">This repo can already:</p>
          <ul className="mt-2 space-y-1 text-zinc-200">
            {capabilities.map((cap) => (
              <li key={cap} className="flex gap-2">
                <span className="text-zinc-500">·</span>
                <span>{cap}</span>
              </li>
            ))}
          </ul>
        </>
      )}
      <p className="mt-4 text-xs text-zinc-500 italic">
        This is a capability statement, not proof that every path is agent-controlled.
      </p>
    </section>
  );
}

function HighestRiskThings({ risks }: { risks: Risk[] }) {
  return (
    <section>
      <h2 className="font-mono text-xs uppercase tracking-widest text-rose-400">
        highest-risk things to care about now
      </h2>
      {risks.length === 0 ? (
        <p className="mt-3 text-zinc-400">
          No high-confidence risk patterns surfaced — the repo may not expose
          agent-grade integrations yet.
        </p>
      ) : (
        <div className="mt-4 space-y-4">
          {risks.map((r, i) => (
            <RiskCard key={`${r.family}-${i}`} risk={r} />
          ))}
        </div>
      )}
    </section>
  );
}

function RiskCard({ risk }: { risk: Risk }) {
  const tone = FAMILY_TONE[risk.family] ?? "border-zinc-800 bg-zinc-900/40";
  return (
    <div className={`rounded-xl border p-5 ${tone}`}>
      <h3 className="text-base font-semibold text-zinc-100">{risk.title}</h3>
      <dl className="mt-3 space-y-2 text-sm leading-6 text-zinc-300">
        <div className="flex flex-col gap-1 sm:flex-row sm:gap-3">
          <dt className="shrink-0 font-mono text-xs uppercase tracking-widest text-zinc-500 sm:w-44">
            confirmed in code
          </dt>
          <dd
            className="text-zinc-200"
            // confirmed_in_code uses backticks → render code spans inline.
            dangerouslySetInnerHTML={{ __html: renderInlineCode(risk.confirmed_in_code) }}
          />
        </div>
        <div className="flex flex-col gap-1 sm:flex-row sm:gap-3">
          <dt className="shrink-0 font-mono text-xs uppercase tracking-widest text-zinc-500 sm:w-44">
            possible chain
          </dt>
          <dd>{risk.possible_chain}</dd>
        </div>
        <div className="flex flex-col gap-1 sm:flex-row sm:gap-3">
          <dt className="shrink-0 font-mono text-xs uppercase tracking-widest text-zinc-500 sm:w-44">
            do this now
          </dt>
          <dd
            className="text-zinc-200"
            dangerouslySetInnerHTML={{ __html: renderInlineCode(risk.do_this_now) }}
          />
        </div>
      </dl>
    </div>
  );
}

function renderInlineCode(text: string): string {
  // Minimal sanitizing: escape HTML, then turn `…` into <code>…</code>.
  // We don't render arbitrary markdown; only the backtick-wrapped spans the
  // Python module produces, so this is intentionally narrow.
  const escaped = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  return escaped.replace(
    /`([^`]+)`/g,
    '<code class="rounded bg-zinc-800 px-1 py-0.5 font-mono text-xs text-zinc-100">$1</code>',
  );
}

function DoThisNow({ markdown }: { markdown: string }) {
  // The Python module emits markdown with a fenced code block. Split on the
  // fence so we can style the code block separately from the prose lead-in.
  const fenceMatch = markdown.match(/^([\s\S]*?)```(?:\w+)?\n([\s\S]*?)```([\s\S]*)$/);
  const lead = fenceMatch ? fenceMatch[1].trim() : markdown.trim();
  const code = fenceMatch ? fenceMatch[2].trim() : "";
  const tail = fenceMatch ? fenceMatch[3].trim() : "";

  return (
    <section className="rounded-xl border border-emerald-900/40 bg-emerald-500/5 p-6">
      <h2 className="font-mono text-xs uppercase tracking-widest text-emerald-400">
        do this now
      </h2>
      {lead && (
        <p
          className="mt-3 text-zinc-200"
          dangerouslySetInnerHTML={{ __html: renderInlineCode(lead) }}
        />
      )}
      {code && (
        <pre className="mt-4 overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-950 p-4 text-xs text-zinc-200">
          <code>{code}</code>
        </pre>
      )}
      {tail && (
        <p
          className="mt-3 text-sm text-zinc-400"
          dangerouslySetInnerHTML={{ __html: renderInlineCode(tail) }}
        />
      )}
    </section>
  );
}

function IgnoreForNow({
  hiddenTotal,
  hiddenBreakdown,
}: {
  hiddenTotal: number;
  hiddenBreakdown: Record<string, number>;
}) {
  const breakdownEntries = Object.entries(hiddenBreakdown).filter(([, n]) => n > 0);
  return (
    <section className="rounded-xl border border-zinc-800/70 bg-zinc-900/30 p-6">
      <h2 className="font-mono text-xs uppercase tracking-widest text-zinc-400">
        ignore this for now
      </h2>
      <p className="mt-3 text-zinc-300">Ignore for now:</p>
      <ul className="mt-2 space-y-1 text-zinc-300">
        <li className="flex gap-2">
          <span className="text-zinc-500">·</span>
          <span>HTTP route inventory</span>
        </li>
        <li className="flex gap-2">
          <span className="text-zinc-500">·</span>
          <span>medium- and low-confidence findings</span>
        </li>
        <li className="flex gap-2">
          <span className="text-zinc-500">·</span>
          <span>tests / legacy / migrations / generated code</span>
        </li>
      </ul>
      {hiddenTotal > 0 ? (
        <p className="mt-4 text-xs text-zinc-500 italic">
          {hiddenTotal} findings hidden ({breakdownEntries.map(([cat, n]) => `${n} ${cat}`).join(", ")}).
          Open the full breakdown below — or run the CLI for everything.
        </p>
      ) : (
        <p className="mt-4 text-xs text-zinc-500 italic">
          If you need everything, open the full breakdown below.
        </p>
      )}
    </section>
  );
}
