import Link from "next/link";
import { getLandingData } from "@/lib/landing-data";
import type { ActionTypeSpec } from "@/lib/api";
import DemoCarousel from "./DemoCarousel";

export const revalidate = 30;

export default async function Landing() {
  const { actionTypes, threatCatalog, sourcedFromApi } = await getLandingData();

  // Stat metrics derived from the registry — never hardcoded numbers.
  const stats = {
    actionTypes: actionTypes.length,
    threatTypes: threatCatalog.length,
    // 3 axes is part of the product taxonomy (Security · Efficiency · Quality),
    // hardcoded but not a "literal number from a scan" — it's the schema itself.
    axes: 3,
  };

  const liveActionTypes = actionTypes.filter((a) => a.status === "live").slice(0, 4);
  const featuredActionTypes = liveActionTypes.length >= 4 ? liveActionTypes : actionTypes.slice(0, 4);

  return (
    <div className="min-h-screen bg-black text-zinc-100 selection:bg-emerald-500/30">
      <Header apiUp={sourcedFromApi} />

      {/* HERO — centered, single column. UPM educational-platform pacing. */}
      <section className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(52,211,153,0.10),transparent_60%)]" />
        <div className="relative mx-auto max-w-4xl px-6 py-20 text-center sm:py-28">
          <div className="animate-fade-in inline-flex items-center gap-2 rounded-full border border-emerald-700/40 bg-emerald-500/10 px-3.5 py-1.5 font-mono text-xs text-emerald-300">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-float" />
            for vibe coders shipping AI agents
          </div>
          <h1 className="animate-fade-in mt-7 text-balance text-5xl font-bold leading-[1.04] tracking-tight sm:text-6xl lg:text-7xl">
            Your agent sent{" "}
            <span className="bg-gradient-to-r from-emerald-300 via-emerald-400 to-emerald-200 bg-clip-text text-transparent">
              621 emails
            </span>{" "}
            before you got out of bed.
          </h1>
          <p className="mx-auto mt-7 max-w-2xl text-pretty text-lg leading-8 text-zinc-400">
            At 03:14 it re-planned a batch you cancelled at 23:47.
            At 13:00 three cron schedulers fired the same handler in the same minute.
            We catch the four wraps that would have stopped all of it &mdash; in 15 minutes,
            in shadow mode, without changing what your agent does.
          </p>
          <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
            <Link
              href="/scan"
              className="hover-glow rounded-xl bg-emerald-500 px-7 py-3.5 text-sm font-semibold text-black transition-colors hover:bg-emerald-400"
            >
              scan my repo (free, 30s) →
            </Link>
            <Link
              href="/blog/621-emails-overnight"
              className="rounded-xl border border-zinc-800 bg-zinc-900/60 px-7 py-3.5 text-sm font-semibold text-zinc-200 hover:border-emerald-700/50 hover:bg-zinc-900"
            >
              see the 621-email walkthrough
            </Link>
          </div>
          <p className="mt-5 text-xs text-zinc-500">
            shadow mode first · 4 lines of @supervised · enforce when you trust it
          </p>
        </div>
      </section>

      {/* STATS BAR — three real metrics, all from /v1/action-types and /v1/threats/catalog */}
      <section className="border-y border-zinc-900 bg-zinc-950/60">
        <div className="mx-auto grid max-w-5xl gap-px bg-zinc-900 sm:grid-cols-3">
          <Stat
            value={stats.actionTypes}
            label="action types supervised"
            sublabel={sourcedFromApi ? "live from /v1/action-types" : "preview catalog"}
          />
          <Stat
            value={stats.threatTypes}
            label="threat detectors"
            sublabel={sourcedFromApi ? "live from /v1/threats/catalog" : "preview catalog"}
          />
          <Stat
            value={stats.axes}
            label="risk axes"
            sublabel="security · efficiency · quality"
          />
        </div>
      </section>

      {/* FEATURED ACTION TYPES — UPM "popular courses" grid, 4 cards from registry */}
      <section id="what" className="mx-auto max-w-6xl px-6 py-20 scroll-mt-20">
        <div className="mx-auto mb-12 max-w-2xl text-center">
          <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">
            from the registry
          </div>
          <h2 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">
            What every scan gates
          </h2>
          <p className="mt-4 text-zinc-400">
            Each action type is a chokepoint where an LLM output triggers something irreversible.
            Status comes straight from <code className="rounded bg-zinc-900 px-1.5 py-0.5 font-mono text-sm">/v1/action-types</code>.
          </p>
        </div>
        <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          {featuredActionTypes.map((spec) => (
            <ActionTypeCard key={spec.id} spec={spec} />
          ))}
        </div>
        <div className="mt-10 text-center">
          <Link href="/scan" className="font-mono text-sm text-emerald-400 hover:text-emerald-300">
            scan your repo to see all matches →
          </Link>
        </div>
      </section>

      {/* WHY VIBEFIXING — UPM "why choose us" 4-col features */}
      <section id="why" className="border-y border-zinc-900 bg-zinc-950/40 scroll-mt-20">
        <div className="mx-auto max-w-6xl px-6 py-20">
          <div className="mx-auto mb-12 max-w-2xl text-center">
            <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">
              why vibefixing
            </div>
            <h2 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">
              Catches what tests can&apos;t
            </h2>
          </div>
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            <Feature
              icon="$"
              title="Static analysis"
              body="Walks your repo at the AST level — no API key, no runtime hooks, no instrumentation. Scan finishes in under 60s."
            />
            <Feature
              icon="◇"
              title="LLM-firable code"
              body="Flags every path an LLM tool call can fire at runtime — refunds, deletes, sends — even when your tests pass."
            />
            <Feature
              icon="↳"
              title="One-line guardrails"
              body="Every finding maps to a @supervised(...) decorator. Drop it in shadow mode first; flip to enforce when you trust it."
            />
            <Feature
              icon="↻"
              title="Continuous on PRs"
              body="The GitHub App diffs each PR against your last scan and comments only on new unsafe call-sites. Zero PR-spam."
            />
          </div>
        </div>
      </section>

      {/* GOVERNANCE PACK — every scan also drops a governance/ folder with
          one-pagers the dev can paste into AI vendor questionnaires. The
          three cards stay in vibe-coder voice (no compliance jargon) and
          sell what it prevents: writing the same one-pager at 11pm. */}
      <section id="governance" className="mx-auto max-w-6xl px-6 py-20 scroll-mt-20">
        <div className="mx-auto mb-12 max-w-2xl text-center">
          <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">
            governance pack
          </div>
          <h2 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">
            When your customer asks &ldquo;do you have AI policies?&rdquo;
          </h2>
          <p className="mt-4 text-zinc-400">
            Every scan also writes a <code className="rounded bg-zinc-900 px-1.5 py-0.5 font-mono text-emerald-300">governance/</code> folder.
            Paste the one-pagers into your next vendor questionnaire and stop
            writing them at 11pm.
          </p>
        </div>
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          <Feature
            icon="¶"
            title="Policy in one page"
            body="Lists your real LLM providers and what your agent actually does — pulled from the scan, not a template. If your repo has no LLM, the page says so."
          />
          <Feature
            icon="@"
            title="Owners named"
            body="One line per action type, pointing at the human who approves it. Override defaults by dropping owners.config.yaml at the repo root."
          />
          <Feature
            icon="≡"
            title="Audit trail you can paste"
            body="Self-attestation answers that cite the runtime review queue and the tamper-evident log already shipping with the supervisor."
          />
        </div>
      </section>

      {/* AGENT SHAPES — repo_type taxonomy. The labels are part of the
          product taxonomy (same status as the 3 risk axes); the scanner
          assigns one of these per scan. Hardcoded copy is fine here —
          we're naming the categories, not interpolating numbers from
          a finding. */}
      <section id="shapes" className="mx-auto max-w-6xl px-6 py-20 scroll-mt-20">
        <div className="mx-auto mb-12 max-w-2xl text-center">
          <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">
            agent shapes
          </div>
          <h2 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">
            What kind of agent are you building?
          </h2>
          <p className="mt-4 text-zinc-400">
            The scanner picks a shape per repo and adapts its priorities. A chatbot
            doesn&apos;t worry about agent loops; a tool-using agent doesn&apos;t worry
            about hallucinated entities. The framing is in the report.
          </p>
        </div>
        <div className="grid gap-6 md:grid-cols-3">
          <ShapeCard
            tone="agent"
            label="Tool-using agent"
            slug="langchain-agent · mcp-server"
            body="Orchestrator picks a tool and fires. Risk lives in what the tool does — payments, deletes, sends. Scanner leads with the agent chokepoint and every action call-site downstream."
            example="LangChain · CrewAI · MCP servers · custom OpenAI function-calling"
          />
          <ShapeCard
            tone="chatbot"
            label="Chatbot or RAG"
            slug="chatbot-rag"
            body="Direct LLM call, no tool dispatch. The model talks to users from your data. Risk is the model asserting a name, account, or fact that doesn't exist — and the user trusting it. Scanner leads with the LLM call and the path to the user."
            example="Anthropic + Express · OpenAI + FastAPI · vector-store RAG · Q&A bots"
          />
          <ShapeCard
            tone="skill"
            label="Claude skill or plugin"
            slug="claude-skill"
            body="No runtime to gate — you ship prompt content Claude reads at call time. Risk is what the prompt instructs Claude to do in the user's workspace. Scanner audits the SKILL.md and CLAUDE.md surface."
            example=".claude/skills/* · claude-code-plugin.json · CLAUDE.md packages"
          />
        </div>
        <p className="mx-auto mt-8 max-w-2xl text-center font-mono text-xs text-zinc-500">
          // each shape adjusts the report&apos;s priority order, the policy templates that ship,
          and the wrap example in <code className="rounded bg-zinc-900 px-1 py-0.5">stubs/</code>.
        </p>
      </section>

      {/* LIVE ATTACK CAROUSEL — kept, restyled */}
      <section className="mx-auto max-w-5xl px-6 py-20">
        <div className="mb-10 flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">
              live attack scenarios
            </div>
            <h2 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">
              Inputs hit the supervisor first
            </h2>
            <p className="mt-3 max-w-xl text-zinc-400">
              Every scenario below is a real supervisor decision against a real threat in the catalog.
              <span className="ml-2 font-mono text-xs text-zinc-600">
                {sourcedFromApi ? "// evaluated live" : "// static preview"}
              </span>
            </p>
          </div>
          <Link href="/scan" className="font-mono text-sm text-emerald-400 hover:text-emerald-300">
            scan your repo →
          </Link>
        </div>
        <DemoCarousel />
      </section>

      {/* RISK AXES — kept content, repacked as UPM-styled cards */}
      <section className="border-y border-zinc-900 bg-zinc-950/40">
        <div className="mx-auto max-w-6xl px-6 py-20">
          <div className="mx-auto mb-12 max-w-3xl text-center">
            <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">
              triage by axis
            </div>
            <h2 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">
              Each finding tells you what kind of pain dominates
            </h2>
            <p className="mt-4 text-zinc-400">
              Tiers tell you <em>what surface</em> is at risk. The axis chip tells you{" "}
              <em>what kind of pain</em> dominates — so you can skip past findings that don&apos;t match
              the triage you&apos;re running today.
            </p>
          </div>
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
            <AxisCard
              tone="security"
              title="Security"
              chip="[Security]"
              body="Adversarial paths: prompt injection moves money, voice-cloning + outbound calls become vishing, agent-orchestrators expose every tool. Anything an attacker would chain."
              example="voice-actions, payment-calls, agent-orchestrators, fs-shell · shell-exec"
            />
            <AxisCard
              tone="reliability"
              title="Reliability"
              chip="[Reliability]"
              body="Things your agent does that shouldn't have happened. Cron raced itself. The cancelled batch came back at 03:14. The chatbot named someone who doesn't exist. Normal traffic — wrong outcome."
              example="agent-loop, llm-calls (low-confidence drift), cron-overlap, hallucinated-entities"
            />
            <AxisCard
              tone="efficiency"
              title="Efficiency"
              chip="[Efficiency]"
              body="Runaway cost: an LLM call without a cap loops, a tool retries forever, premium-rate phone numbers run up the bill. Normal traffic — bad shape."
              example="llm-calls (high confidence), tool retries, oversized prompts"
            />
            <AxisCard
              tone="quality"
              title="Quality"
              chip="[Quality]"
              body="Auditability and reversibility: business-table mutations with no audit trail, fs-write without a path allowlist, tool calls without a tool name. The stuff that breaks incident response."
              example="db-mutations on business tables, fs-write, http-routes, cron-schedules"
            />
          </div>
        </div>
      </section>

      {/* BEFORE / AFTER CODE — kept */}
      <section className="mx-auto max-w-5xl px-6 py-20">
        <div className="mx-auto mb-12 max-w-2xl text-center">
          <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">
            the fix
          </div>
          <h2 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">
            One gate before execution
          </h2>
          <p className="mt-4 text-zinc-400">
            Your agent can still use tools. It just asks the supervisor before doing something
            expensive, destructive, or sensitive.
          </p>
        </div>
        <div className="grid gap-6 lg:grid-cols-2">
          <CodeBlock
            label="// before"
            tone="muted"
            code={`def handle_tool_call(tool, args):
    return TOOLS[tool](**args)`}
          />
          <CodeBlock
            label="// after"
            tone="good"
            code={`from supervisor_guards import supervised

@supervised("tool_use")
def handle_tool_call(tool, args):
    return TOOLS[tool](**args)`}
          />
        </div>
      </section>

      {/* WHAT IT CATCHES — kept Risk grid as testimonials-equivalent (real content, not fake quotes) */}
      <section className="border-y border-zinc-900 bg-zinc-950/40">
        <div className="mx-auto max-w-6xl px-6 py-20">
          <div className="mx-auto mb-12 max-w-2xl text-center">
            <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">
              field notes
            </div>
            <h2 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">
              Failure modes vibefixing has caught
            </h2>
            <p className="mt-4 text-zinc-400">
              Normal agent failure modes, not abstract security theater.
            </p>
          </div>
          <div className="grid gap-5 md:grid-cols-2 lg:grid-cols-3">
            <Risk title="Prompt-injected tool calls" body={'A ticket says "ignore previous instructions" and the agent tries to execute the user request.'} />
            <Risk title="Dangerous DB mutations" body="Generated SQL misses a tenant scope or a WHERE clause before touching customer tables." />
            <Risk title="Data leakage" body="The agent sends emails, PII, credit cards, or internal context into an LLM call." />
            <Risk title="Cost loops" body="Retry logic goes sideways and calls the same tool hundreds of times in a minute." />
            <Risk title="Unreviewed money movement" body="Refunds, transfers, payouts, and checkout sessions get a risk decision before the SDK call." />
            <Risk title="Role and account changes" body="Admin grants, password changes, and fresh-account edits get blocked or escalated." />
            <Risk
              title="Hallucinated entities reaching users"
              body="The chatbot names a person, account, or identifier that doesn't exist in your data — and the user reads it as fact. The taint scanner flags every path from an LLM call to a response, email, or message without a source-of-truth check in between."
            />
          </div>
          <div className="mt-12 grid gap-5 md:grid-cols-2 lg:grid-cols-3">
            <Link
              href="/blog/scanner-caught-itself"
              className="hover-glow group block overflow-hidden rounded-2xl border border-sky-800/50 bg-sky-950/20 p-6 transition-colors hover:border-sky-600/60 md:p-8"
            >
              <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
                <span className="rounded-full border border-sky-700/40 bg-sky-500/10 px-2.5 py-0.5 text-sky-300">
                  reliability · self-check + AST-first
                </span>
                <span className="text-zinc-500">may 22, 2026</span>
              </div>
              <h3 className="mt-4 text-xl font-bold leading-snug tracking-tight text-zinc-100 group-hover:text-sky-300 sm:text-2xl">
                How we caught our own scanner lying
              </h3>
              <p className="mt-3 leading-7 text-zinc-400">
                The scanner reported a comment line as RCE-equivalent. Two real bugs,
                eight false positives, one rule: the supervisor has to be more reliable
                than the agent it watches. The five layers we shipped so it can&apos;t
                lie that way again.
              </p>
              <span className="mt-5 inline-flex items-center gap-1 font-mono text-sm text-sky-400 group-hover:text-sky-300">
                read field note &rarr;
              </span>
            </Link>
            <Link
              href="/blog/chatbot-hallucination-andrea"
              className="hover-glow group block overflow-hidden rounded-2xl border border-zinc-800 bg-zinc-950 p-6 transition-colors hover:border-emerald-700/50 md:p-8"
            >
              <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
                <span className="rounded-full border border-amber-700/40 bg-amber-500/10 px-2.5 py-0.5 text-amber-300">
                  chatbot · hallucinated entities
                </span>
                <span className="text-zinc-500">april 30, 2026</span>
              </div>
              <h3 className="mt-4 text-xl font-bold leading-snug tracking-tight text-zinc-100 group-hover:text-emerald-300 sm:text-2xl">
                When the chatbot invents a person: the hallucination class your scanner missed
              </h3>
              <p className="mt-3 leading-7 text-zinc-400">
                A manager asked her CRM bot about her team. The bot confidently
                analyzed five people who didn&apos;t exist in her data. Three hours, 35
                messages, one lost user &mdash; and the wrap pattern that stops it.
              </p>
              <span className="mt-5 inline-flex items-center gap-1 font-mono text-sm text-emerald-400 group-hover:text-emerald-300">
                read field note &rarr;
              </span>
            </Link>
            <Link
              href="/blog/voice-phishing-langchain-agent"
              className="hover-glow group block overflow-hidden rounded-2xl border border-zinc-800 bg-zinc-950 p-6 transition-colors hover:border-emerald-700/50 md:p-8"
            >
              <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
                <span className="rounded-full border border-rose-700/40 bg-rose-500/10 px-2.5 py-0.5 text-rose-300">
                  combo · voice-clone + outbound-call
                </span>
                <span className="text-zinc-500">april 25, 2026</span>
              </div>
              <h3 className="mt-4 text-xl font-bold leading-snug tracking-tight text-zinc-100 group-hover:text-emerald-300 sm:text-2xl">
                The vishing recipe hiding in your LangChain agent
              </h3>
              <p className="mt-3 leading-7 text-zinc-400">
                Three innocent features &mdash; TTS, outbound calls, an ungated LLM
                &mdash; compose into a voice-phishing weapon under one calendar-event
                injection. The exploit, the code, and the gate.
              </p>
              <span className="mt-5 inline-flex items-center gap-1 font-mono text-sm text-emerald-400 group-hover:text-emerald-300">
                read field note &rarr;
              </span>
            </Link>
          </div>
        </div>
      </section>

      {/* OPEN BENCHMARK — referee, not contestant */}
      <section className="mx-auto max-w-5xl px-6 py-16">
        <div className="rounded-2xl border border-sky-800/40 bg-sky-950/15 p-8 lg:p-10">
          <div className="grid gap-8 lg:grid-cols-[1.4fr_1fr] lg:items-center">
            <div>
              <div className="font-mono text-xs uppercase tracking-widest text-sky-300">
                public benchmark
              </div>
              <h2 className="mt-3 text-3xl font-bold leading-tight tracking-tight sm:text-4xl">
                vf hallucination-rate
              </h2>
              <p className="mt-4 leading-7 text-zinc-300">
                Ten adversarial prompts. Deterministic scoring — no model
                judge, no LLM-as-judge. Score any agent stack against the
                same eval set and submit to the public leaderboard.
              </p>
              <p className="mt-3 text-sm leading-6 text-zinc-500">
                We publish the eval. We do not appear on the leaderboard.
              </p>
              <div className="mt-6 flex flex-wrap items-center gap-3">
                <Link
                  href="/benchmark"
                  className="rounded-xl bg-sky-500 px-6 py-2.5 text-sm font-semibold text-black hover:bg-sky-400"
                >
                  open the benchmark →
                </Link>
                <Link
                  href="/blog/scanner-caught-itself"
                  className="rounded-xl border border-zinc-800 bg-zinc-900/60 px-6 py-2.5 text-sm font-semibold text-zinc-200 hover:border-sky-700/50"
                >
                  why we built it
                </Link>
              </div>
            </div>
            <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-5 font-mono text-[12px] leading-relaxed text-zinc-300">
              <div className="text-zinc-500"># install + score any agent</div>
              <div>
                <span className="text-sky-300">$</span> npm i -g{" "}
                <span className="text-emerald-300">@vibefixing/hallucination-eval</span>
              </div>
              <div className="mt-2">
                <span className="text-sky-300">$</span> vf-hallucination-rate score{" "}
                <span className="text-zinc-500">\</span>
              </div>
              <div className="pl-4">
                --cmd <span className="text-emerald-300">&apos;python my_agent.py&apos;</span>
              </div>
              <div className="mt-3 text-zinc-500"># sample output</div>
              <div>eval-set: v0.1.0</div>
              <div>total: 10 · passed: 7 · failed: 3</div>
              <div>hallucination rate: 30.0%</div>
            </div>
          </div>
        </div>
      </section>

      {/* PR / GITHUB APP — kept */}
      <section className="border-y border-zinc-900 bg-gradient-to-br from-zinc-950 via-emerald-950/10 to-zinc-950">
        <div className="mx-auto max-w-6xl px-6 py-20">
          <div className="grid gap-12 lg:grid-cols-[1fr_1.2fr] lg:items-center">
            <div>
              <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">
                continuous protection
              </div>
              <h2 className="mt-3 text-3xl font-bold leading-tight tracking-tight sm:text-4xl">
                Every PR, auto-scanned.
                <br />
                <span className="text-zinc-400">New unsafe code can&apos;t slip in.</span>
              </h2>
              <p className="mt-5 leading-7 text-zinc-400">
                The first scan tells you what&apos;s unsafe today. The GitHub App keeps it that way.
                When you (or a teammate) open a PR that adds a new ungated <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm">stripe.refunds.create</code> or
                <code className="ml-1 rounded bg-zinc-900 px-1.5 py-0.5 text-sm">fs.unlink</code>, vibefixing comments before review.
              </p>
              <ul className="mt-6 space-y-3 text-sm leading-7 text-zinc-300">
                <li className="flex gap-3"><span className="font-mono text-emerald-400">→</span><span><strong className="text-zinc-100">5 seconds</strong> from PR open to comment posted.</span></li>
                <li className="flex gap-3"><span className="font-mono text-emerald-400">→</span><span>Diffs against your previous scans — only <strong className="text-zinc-100">new</strong> findings flagged.</span></li>
                <li className="flex gap-3"><span className="font-mono text-emerald-400">→</span><span>Catches what tests can&apos;t — code your LLM can fire, not what your tests cover.</span></li>
                <li className="flex gap-3"><span className="font-mono text-emerald-400">→</span><span>Same UX whether you ship 1 PR/week or 100.</span></li>
              </ul>
              <div className="mt-8 flex flex-wrap items-center gap-3">
                <a
                  href="https://github.com/apps/vibefixing/installations/new"
                  className="hover-glow rounded-xl bg-emerald-500 px-7 py-3.5 text-sm font-semibold text-black transition-colors hover:bg-emerald-400"
                >
                  install on a repo →
                </a>
                <span className="font-mono text-xs text-zinc-500">free for public repos</span>
              </div>
            </div>
            <PrCommentMockup />
          </div>
        </div>
      </section>

      {/* PRICING — kept */}
      <section id="pricing" className="mx-auto max-w-6xl px-6 py-20 scroll-mt-20">
        <div className="mx-auto mb-12 max-w-2xl text-center">
          <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">
            pricing
          </div>
          <h2 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">
            For builders and teams
          </h2>
          <p className="mt-4 text-zinc-400">
            Start with a public scan. Pay when the scanner becomes part of your shipping workflow,
            then move up when you need team review.
          </p>
        </div>
        <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          <Plan
            name="Free"
            price="$0"
            tagline="See the prompt-injection paths your agent ships with — scan in 60 seconds."
            cta="scan a public repo"
            href="/scan"
            items={["Public GitHub repo scan", "Top findings preview", "Risk tier summary", "Local CLI install"]}
          />
          <Plan
            name="Builder"
            price="$29/mo"
            tagline="Every PR your agent helps write gets the same hallucination + injection check, before merge."
            cta="upgrade to builder"
            href="/scan?upgrade=builder"
            items={["Private repo scans", "Full runtime-supervisor export", "Stubs and YAML policies", "Scan history and diffs", "CI/GitHub PR comments"]}
          />
          <Plan
            featured
            name="Pro"
            price="$99/workspace/mo"
            tagline="Your team sees every blocked action with the reason, so debugging an agent decision takes minutes not days."
            cta="contact us"
            href="mailto:ariel@vibefixing.me?subject=Pro%20pricing%20-%20Vibefixing"
            items={[
              "Everything in Builder, for your team",
              "Unlimited repos in this workspace",
              "Shared fix queue + team review",
              "Audit retention + webhooks",
              "SSO (rolling out — email us)",
            ]}
          />
          <Plan
            name="Enterprise"
            price="Talk to us"
            tagline="Tamper-evident evidence chain you can hand an auditor, mapped to the controls they actually ask about."
            cta="email sales"
            href="mailto:ariel@vibefixing.me?subject=Enterprise%20-%20Vibefixing"
            items={[
              "Multi-workspace",
              "Custom retention + audit export",
              "Priority support + SLAs",
              "Dedicated infrastructure",
              "Mono-repos >200MB / high-volume scans",
            ]}
          />
        </div>
      </section>

      {/* CTA BAND — UPM-style closer */}
      <section className="border-y border-zinc-900 bg-gradient-to-br from-zinc-950 via-emerald-950/15 to-zinc-950">
        <div className="mx-auto max-w-3xl px-6 py-20 text-center">
          <h2 className="text-balance text-4xl font-bold tracking-tight sm:text-5xl">
            Ready to ship safer agents?
          </h2>
          <p className="mx-auto mt-5 max-w-xl text-pretty text-lg leading-8 text-zinc-400">
            One repo URL. Under 60 seconds. You get a list of unsafe call-sites and the SDK lines that gate them.
          </p>
          <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
            <Link
              href="/scan"
              className="hover-glow rounded-xl bg-emerald-500 px-7 py-3.5 text-sm font-semibold text-black hover:bg-emerald-400"
            >
              scan free →
            </Link>
            <Link
              href="/risks"
              className="rounded-xl border border-zinc-800 bg-zinc-900 px-7 py-3.5 text-sm font-semibold text-zinc-200 hover:border-emerald-700/50 hover:bg-zinc-900"
            >
              browse the 5 risks
            </Link>
          </div>
          <p className="mt-5 text-xs text-zinc-500">
            no credit card · public repos free forever
          </p>
        </div>
      </section>

      {/* FAQ — kept verbatim for the FAQPage schema in layout.tsx */}
      <section className="mx-auto max-w-3xl px-6 py-24" aria-label="Frequently asked questions">
        <h2 className="mb-12 text-center text-3xl font-bold tracking-tight text-zinc-100">
          Frequently Asked Questions
        </h2>
        <div className="space-y-8">
          <FaqItem q="What is Vibefixing and what does it scan?">
            Vibefixing is a runtime supervisor and security scanner for AI agents. It statically
            analyzes your codebase to find unsafe tool calls your AI agent can execute before
            they reach production: unguarded Stripe charges, raw database mutations,
            filesystem writes, and shell commands.
          </FaqItem>
          <FaqItem q="How does Vibefixing prevent prompt injection in AI agents?">
            Vibefixing identifies tool calls that lack input validation or guardrails, which are the
            primary attack surface for prompt injection. By flagging every path where an LLM output
            can trigger an irreversible action without a human confirmation step, it eliminates the
            conditions that make injection exploits dangerous.
          </FaqItem>
          <FaqItem q="Is Vibefixing safe to use for vibe coders shipping with AI-generated code?">
            Yes. Vibefixing is designed for vibe coders: developers shipping fast with AI assistants
            like Claude, Cursor, or Copilot. It catches risky patterns LLMs commonly generate:
            unguarded API calls, database deletes without confirmation, and credential exposure
            in tool call arguments.
          </FaqItem>
          <FaqItem q="Does Vibefixing work with any AI agent framework?">
            Vibefixing analyzes your repository at the code level, so it works with any agent
            framework: LangChain, LlamaIndex, CrewAI, custom OpenAI function-calling, Anthropic
            tool use, or plain Python scripts. No instrumentation or runtime hooks required.
          </FaqItem>
          <FaqItem q="I'm not building an AI agent — does Vibefixing still help?">
            Yes. The same patterns an agent can misuse — Stripe checkout sessions, account
            mutations, webhook handlers that re-deliver and double-charge — are what get
            exploited by prompt injection, a careless contractor, or a runaway script.
            Vibefixing flags them whether or not an LLM is in the call chain. Supported stacks
            include Next.js App Router (route handlers and Server Actions), Stripe
            (TypeScript and Python), Supabase (service-role writes and row-level security
            checks on migrations), Prisma, and SQLAlchemy.
          </FaqItem>
          <FaqItem q="What unsafe actions does Vibefixing detect?">
            Vibefixing detects: Stripe charges, refunds, subscription changes, and customer
            portal sessions (TypeScript and Python); raw SQL mutations and Supabase writes
            that bypass row-level security; Next.js Server Actions and API route handlers;
            webhook handlers that replay database writes on retry; filesystem deletes; shell
            execution; emails sent without per-call confirmation. Each finding includes the
            file, line, and a one-line wrap.
          </FaqItem>
          <FaqItem q="How long does a Vibefixing scan take?">
            A public repository scan typically completes in under 60 seconds. Vibefixing uses
            static analysis and does not run your code or require an API key for the scan.
            Results include a risk score, a list of unsafe actions, and copy-paste guardrail
            code for each finding.
          </FaqItem>
          <FaqItem q="Does Vibefixing scan every pull request automatically?">
            Yes. Install the Vibefixing GitHub App on your repo and every pull request gets
            scanned automatically. Within 5 seconds of opening a PR, vibefixing diffs the head
            ref against your previous scan and posts a comment listing only the <em>new</em>{" "}
            unsafe call-sites. Clean PRs get nothing — no spam. Free for public repos; private
            repos and CI integration are part of Builder ($29/mo), while team workflows and org-level
            controls start at Pro ($99/workspace/mo).
          </FaqItem>
          <FaqItem q="How is Vibefixing different from regular code review or static analysis?">
            Code review and SAST tools catch bugs in code your tests already cover. Vibefixing
            catches what your tests <em>can&apos;t</em>: actions an LLM can fire at runtime in
            ways no test case anticipated. Refunds the model decides to issue, files it decides
            to delete, emails it decides to send. Each detector maps to a runtime guard you can
            drop in with one line.
          </FaqItem>
        </div>
      </section>

      <Footer />
    </div>
  );
}

/* ───────────── components ───────────── */

function Header({ apiUp }: { apiUp: boolean }) {
  return (
    <header className="sticky top-0 z-20 border-b border-zinc-900 bg-black/80 backdrop-blur">
      <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-6 py-4">
        <Link href="/" className="flex items-baseline gap-2 font-mono text-sm hover:opacity-80">
          <span className="text-emerald-400">$</span>
          <span className="font-semibold text-zinc-100">vibefixing</span>
          <span className="hidden text-xs text-zinc-500 sm:inline">// runtime-supervisor</span>
        </Link>
        <nav className="hidden items-center gap-7 font-mono text-xs text-zinc-400 md:flex">
          <Link href="/scan" className="transition-colors hover:text-emerald-400">scan</Link>
          <a href="#what" className="transition-colors hover:text-emerald-400">what it gates</a>
          <a href="#why" className="transition-colors hover:text-emerald-400">why</a>
          <a href="#pricing" className="transition-colors hover:text-emerald-400">pricing</a>
          <Link href="/blog" className="transition-colors hover:text-emerald-400">blog</Link>
        </nav>
        <div className="flex items-center gap-3 text-sm">
          <span
            className={`hidden items-center gap-1.5 rounded-full border px-2.5 py-1 font-mono text-xs sm:inline-flex ${
              apiUp
                ? "border-emerald-700/50 bg-emerald-500/10 text-emerald-400"
                : "border-zinc-800 bg-zinc-900 text-zinc-500"
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${apiUp ? "bg-emerald-400 animate-float" : "bg-zinc-600"}`} />
            {apiUp ? "api up" : "api down"}
          </span>
          <Link
            href="/dashboard"
            className="hover-glow rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-black hover:bg-emerald-400"
          >
            dashboard
          </Link>
        </div>
      </div>
    </header>
  );
}

function Stat({ value, label, sublabel }: { value: number; label: string; sublabel: string }) {
  return (
    <div className="bg-black/60 px-6 py-10 text-center sm:px-8 sm:py-12">
      <div className="text-4xl font-bold tracking-tight text-emerald-400 sm:text-5xl">{value}</div>
      <div className="mt-2 text-sm font-medium text-zinc-200">{label}</div>
      <div className="mt-1 font-mono text-[11px] uppercase tracking-widest text-zinc-600">{sublabel}</div>
    </div>
  );
}

function ActionTypeCard({ spec }: { spec: ActionTypeSpec }) {
  const live = spec.status === "live";
  return (
    <div className="hover-glow flex h-full flex-col rounded-2xl border border-zinc-800 bg-zinc-950/60 p-6">
      <div className="flex items-center justify-between">
        <span className="font-mono text-xs text-zinc-500">{spec.id}</span>
        <span
          className={`rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest ${
            live
              ? "border-emerald-700/40 bg-emerald-500/10 text-emerald-400"
              : "border-zinc-800 bg-zinc-900 text-zinc-500"
          }`}
        >
          {spec.status}
        </span>
      </div>
      <h3 className="mt-4 text-lg font-semibold leading-snug text-zinc-100">{spec.title}</h3>
      <p className="mt-2 flex-1 text-sm leading-7 text-zinc-400">{spec.one_liner}</p>
      <div className="mt-5 border-t border-zinc-900 pt-4 font-mono text-[11px] text-zinc-500">
        signals · <span className="text-zinc-300">{spec.intercepted_signals.length}</span>
        {spec.policy_ref && (
          <>
            <span className="mx-2 text-zinc-700">·</span>
            policy <span className="text-zinc-300">{spec.policy_ref}</span>
          </>
        )}
      </div>
    </div>
  );
}

function Feature({ icon, title, body }: { icon: string; title: string; body: string }) {
  return (
    <div className="hover-glow rounded-2xl border border-zinc-800 bg-zinc-950/60 p-6">
      <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-emerald-700/40 bg-emerald-500/10 font-mono text-lg text-emerald-300">
        {icon}
      </div>
      <h3 className="mt-5 text-lg font-semibold text-zinc-100">{title}</h3>
      <p className="mt-2 text-sm leading-7 text-zinc-400">{body}</p>
    </div>
  );
}

function AxisCard({
  tone,
  title,
  chip,
  body,
  example,
}: {
  tone: "security" | "reliability" | "efficiency" | "quality";
  title: string;
  chip: string;
  body: string;
  example: string;
}) {
  const palette = {
    security: { border: "border-red-900/50", text: "text-red-300", bg: "bg-red-500/10" },
    reliability: { border: "border-sky-900/50", text: "text-sky-300", bg: "bg-sky-500/10" },
    efficiency: { border: "border-amber-900/50", text: "text-amber-300", bg: "bg-amber-500/10" },
    quality: { border: "border-zinc-700/60", text: "text-zinc-300", bg: "bg-zinc-500/10" },
  }[tone];
  return (
    <div className={`hover-glow flex h-full flex-col rounded-2xl border ${palette.border} bg-zinc-950/60 p-6`}>
      <div className="flex items-center gap-2">
        <span className={`font-mono text-xs ${palette.text}`}>{chip}</span>
        <span className="font-semibold text-zinc-100">{title}</span>
      </div>
      <p className="mt-3 flex-1 text-sm leading-7 text-zinc-300">{body}</p>
      <div className={`mt-4 rounded-lg border border-zinc-800 ${palette.bg} px-3 py-2 font-mono text-[11px] text-zinc-400`}>
        <span className="text-zinc-600">e.g.</span> <span className="text-zinc-300">{example}</span>
      </div>
    </div>
  );
}

function ShapeCard({
  tone,
  label,
  slug,
  body,
  example,
}: {
  tone: "agent" | "chatbot" | "skill";
  label: string;
  slug: string;
  body: string;
  example: string;
}) {
  const palette = {
    agent: { border: "border-emerald-700/50", text: "text-emerald-300", bg: "bg-emerald-500/10" },
    chatbot: { border: "border-cyan-700/50", text: "text-cyan-300", bg: "bg-cyan-500/10" },
    skill: { border: "border-violet-700/50", text: "text-violet-300", bg: "bg-violet-500/10" },
  }[tone];
  return (
    <div className={`hover-glow flex h-full flex-col rounded-2xl border ${palette.border} bg-zinc-950/60 p-6`}>
      <div className="flex items-baseline justify-between gap-3">
        <h3 className="text-lg font-semibold text-zinc-100">{label}</h3>
        <span className={`font-mono text-[10px] uppercase tracking-widest ${palette.text}`}>{slug}</span>
      </div>
      <p className="mt-3 flex-1 text-sm leading-7 text-zinc-300">{body}</p>
      <div className={`mt-4 rounded-lg border border-zinc-800 ${palette.bg} px-3 py-2 font-mono text-[11px] text-zinc-400`}>
        <span className="text-zinc-600">e.g.</span> <span className="text-zinc-300">{example}</span>
      </div>
    </div>
  );
}

function CodeBlock({ label, code, tone }: { label: string; code: string; tone: "muted" | "good" }) {
  return (
    <div>
      <div className={`mb-3 font-mono text-xs uppercase tracking-widest ${tone === "good" ? "text-emerald-400" : "text-zinc-500"}`}>
        {label}
      </div>
      <pre className={`overflow-auto rounded-2xl border p-6 font-mono text-sm leading-relaxed ${
        tone === "good" ? "border-emerald-900/50 bg-emerald-500/5 text-zinc-100" : "border-zinc-800 bg-zinc-900/60 text-zinc-300"
      }`}>
        {code}
      </pre>
    </div>
  );
}

function Risk({ title, body }: { title: string; body: string }) {
  return (
    <div className="hover-glow rounded-2xl border border-zinc-800 bg-zinc-900/40 p-6">
      <div className="font-semibold text-zinc-100">{title}</div>
      <p className="mt-2 text-sm leading-7 text-zinc-400">{body}</p>
    </div>
  );
}

function Plan({
  name,
  price,
  tagline,
  cta,
  href,
  items,
  featured = false,
}: {
  name: string;
  price: string;
  tagline?: string;
  cta: string;
  href: string;
  items: string[];
  featured?: boolean;
}) {
  return (
    <div className={`hover-glow rounded-2xl border p-7 ${featured ? "border-emerald-700 bg-emerald-500/10" : "border-zinc-800 bg-zinc-900/40"}`}>
      <div className="flex items-baseline justify-between gap-4">
        <h3 className="text-xl font-semibold">{name}</h3>
        {featured && <span className="rounded-full bg-emerald-500 px-2 py-1 font-mono text-[10px] uppercase tracking-widest text-black">best first paid plan</span>}
      </div>
      <div className="mt-4 text-3xl font-bold">{price}</div>
      {tagline && (
        <p className="mt-3 text-sm leading-6 text-zinc-300">{tagline}</p>
      )}
      <ul className="mt-5 space-y-2 text-sm text-zinc-400">
        {items.map((item) => (
          <li key={item} className="flex gap-2">
            <span className="text-emerald-400">✓</span>
            <span>{item}</span>
          </li>
        ))}
      </ul>
      <Link
        href={href}
        className={`mt-6 inline-flex w-full justify-center rounded-xl px-4 py-2.5 text-sm font-semibold ${
          featured ? "bg-emerald-500 text-black hover:bg-emerald-400" : "border border-zinc-800 bg-zinc-950 text-zinc-200 hover:bg-zinc-900"
        }`}
      >
        {cta}
      </Link>
    </div>
  );
}

function PrCommentMockup() {
  return (
    <div className="hover-glow overflow-hidden rounded-2xl border border-zinc-800 bg-zinc-950 shadow-2xl shadow-emerald-950/20">
      <div className="flex items-center gap-3 border-b border-zinc-800 bg-zinc-900/80 px-4 py-3">
        <div className="flex h-7 w-7 items-center justify-center rounded-full bg-emerald-500 font-mono text-[11px] font-bold text-black">V</div>
        <span className="text-sm font-semibold text-zinc-200">vibefixing</span>
        <span className="text-xs text-zinc-500">commented on PR #142</span>
        <span className="ml-auto font-mono text-[10px] text-zinc-600">5 seconds ago</span>
      </div>
      <div className="px-5 py-4">
        <p className="text-sm text-zinc-200">
          🔒 <strong>vibefixing detected 2 new unsafe call-sites</strong> in this PR
        </p>
        <div className="mt-4 overflow-hidden rounded-md border border-zinc-800">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-zinc-900/60 text-left text-zinc-400">
                <th className="px-3 py-2 font-normal">File</th>
                <th className="px-3 py-2 font-normal">Type</th>
                <th className="px-3 py-2 font-normal">Conf</th>
                <th className="px-3 py-2 font-normal">Why</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-t border-zinc-800">
                <td className="px-3 py-2 font-mono text-zinc-200">src/api/refund.ts:42</td>
                <td className="px-3 py-2"><span className="rounded bg-rose-500/10 px-1.5 py-0.5 font-mono text-rose-300">payment</span></td>
                <td className="px-3 py-2">🔴 high</td>
                <td className="px-3 py-2 text-zinc-400">stripe.refunds.create without @supervised</td>
              </tr>
              <tr className="border-t border-zinc-800">
                <td className="px-3 py-2 font-mono text-zinc-200">src/workers/cleanup.ts:8</td>
                <td className="px-3 py-2"><span className="rounded bg-amber-500/10 px-1.5 py-0.5 font-mono text-amber-300">tool_use</span></td>
                <td className="px-3 py-2">🔴 high</td>
                <td className="px-3 py-2 text-zinc-400">fs.unlink in user-input path</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="mt-4 text-sm text-zinc-300">
          Wrap them with <code className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs">@supervised(...)</code> before merging — or this lands in production ungated.
        </p>
        <p className="mt-4 border-t border-zinc-800 pt-3 text-xs text-zinc-500">
          Plus 1 previously-flagged finding fixed — nice. <span className="text-emerald-400 underline">Full diff →</span>
        </p>
      </div>
    </div>
  );
}

function FaqItem({ q, children }: { q: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-lg font-semibold text-zinc-100">{q}</h3>
      <p className="mt-2 leading-7 text-zinc-400">{children}</p>
    </div>
  );
}

function Footer() {
  return (
    <footer className="border-t border-zinc-900 bg-black">
      <div className="mx-auto max-w-6xl px-6 py-14">
        <div className="grid gap-10 sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <div className="font-mono text-sm">
              <span className="text-emerald-400">$</span>{" "}
              <span className="font-semibold text-zinc-200">vibefixing</span>
            </div>
            <p className="mt-3 max-w-xs text-sm leading-7 text-zinc-500">
              Runtime supervisor and security scanner for AI agents. Guardrails for code that
              ships fast.
            </p>
          </div>
          <FooterCol
            title="Product"
            links={[
              { label: "Scan", href: "/scan" },
              { label: "Dashboard", href: "/dashboard" },
              { label: "Reviews", href: "/review?status=pending" },
              { label: "Threats", href: "/threats" },
              { label: "Policies", href: "/policies" },
            ]}
          />
          <FooterCol
            title="Resources"
            links={[
              { label: "Blog", href: "/blog" },
              { label: "GitHub", href: "https://github.com/ArielSanroj/runtime-supervisor" },
              { label: "Install GitHub App", href: "https://github.com/apps/vibefixing/installations/new" },
            ]}
          />
          <FooterCol
            title="Company"
            links={[
              { label: "Pro pricing", href: "mailto:ariel@vibefixing.me?subject=Pro%20pricing%20-%20Vibefixing" },
              { label: "Enterprise", href: "mailto:ariel@vibefixing.me?subject=Enterprise%20-%20Vibefixing" },
              { label: "Contact", href: "mailto:ariel@vibefixing.me" },
            ]}
          />
        </div>
        <div className="mt-12 flex flex-wrap items-center justify-between gap-4 border-t border-zinc-900 pt-6 font-mono text-xs text-zinc-600">
          <span>© {new Date().getFullYear()} vibefixing · guardrails for agents that ship</span>
          <span>built with <span className="text-emerald-400">@supervised</span></span>
        </div>
      </div>
    </footer>
  );
}

function FooterCol({ title, links }: { title: string; links: { label: string; href: string }[] }) {
  return (
    <div>
      <div className="font-mono text-xs uppercase tracking-widest text-zinc-500">{title}</div>
      <ul className="mt-4 space-y-2.5 text-sm">
        {links.map((l) => (
          <li key={l.label}>
            <Link href={l.href} className="text-zinc-300 hover:text-emerald-400">
              {l.label}
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
