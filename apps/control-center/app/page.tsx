import Link from "next/link";
import { getLandingData } from "@/lib/landing-data";
import DemoCarousel from "./DemoCarousel";

export const revalidate = 30;

export default async function Landing() {
  const { sourcedFromApi } = await getLandingData();

  return (
    <div className="min-h-screen bg-black text-zinc-100 selection:bg-emerald-500/30">
      <Header apiUp={sourcedFromApi} />

      <section className="mx-auto grid min-h-[calc(100vh-64px)] max-w-6xl items-center gap-10 px-6 py-16 lg:grid-cols-[1.05fr_0.95fr]">
        <div>
          <div className="inline-flex items-center gap-2 rounded-full border border-zinc-800 bg-zinc-900/60 px-3 py-1 text-xs font-mono text-zinc-400">
            <span className="text-pink-400">#</span> for vibe coders shipping agents
          </div>
          <h1 className="mt-6 max-w-3xl text-5xl font-bold leading-[1.03] tracking-tight sm:text-6xl">
              Scan your AI agent for unsafe actions before shipping.
          </h1>
          <p className="mt-6 max-w-2xl text-lg leading-8 text-zinc-400">
            Paste a repo, get the risky tool calls, and ship with guardrails before an LLM
            touches Stripe, your DB, filesystem, or customer data.
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-3">
            <Link
              href="/scan"
              className="rounded-lg bg-emerald-500 px-6 py-3 text-sm font-semibold text-black transition-colors hover:bg-emerald-400"
            >
              scan your repo free
            </Link>
            <Cmd cmd="npm i @runtime-supervisor/guards" />
          </div>
          <p className="mt-4 text-sm text-zinc-500">
            Free scan + free SDK + free credentials by email. Builder ($29/mo) unlocks private repos,
            history, and CI comments.
          </p>
        </div>

        <ScanPreview />
      </section>

      <section className="border-y border-zinc-900 bg-zinc-950/70">
        <div className="mx-auto grid max-w-6xl gap-6 px-6 py-14 md:grid-cols-3">
          <Outcome
            title="1. Scan"
            body="Paste a GitHub URL — we map money movement, DB writes, LLM calls, shell/filesystem access, and agent chokepoints."
          />
          <Outcome
            title="2. Drop the SDK in"
            body="npm i @runtime-supervisor/guards. 5 lines, no signup. Shadow mode by default — your wrapped calls start streaming would-have-blocks immediately."
          />
          <Outcome
            title="3. Claim when you want the dashboard"
            body="Drop your email in 30 seconds — your shadow events show up in a personal dashboard, and you unlock enforce mode + review queue."
          />
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-6 py-16">
        <div className="mb-10">
          <h2 className="text-3xl font-bold tracking-tight">What each scan tier means</h2>
          <p className="mt-3 max-w-3xl text-zinc-400">
            The scanner groups by worst-case blast radius, not by SDK. Money-burning surfaces at the top;
            informational at the bottom. These 6 categories are exactly what you see in the CLI output.
          </p>
        </div>
        <div className="grid gap-5 md:grid-cols-2 lg:grid-cols-3">
          <Tier
            title="Money movement"
            danger
            body="Refunds, charges, subscriptions, payouts. Without a gate, a prompt injection can fire a money move nobody authorized."
            wraps="@supervised('payment')"
          />
          <Tier
            title="Real-world actions"
            danger
            body="Phone calls, SMS, email, Slack posts, calendar events, file writes or deletes, shell commands. Each is irreversible if the args come from an LLM."
            wraps="@supervised('tool_use')"
          />
          <Tier
            title="Customer data"
            body="UPDATE/DELETE on customer tables (users, accounts, customers, orders). A DELETE without a WHERE doesn't undo; an UPDATE that flips email + phone + password at once doesn't either."
            wraps="@supervised('account_change')"
          />
          <Tier
            title="Business data"
            body="Mutations on business-state tables (trades, positions, inventory, events). Not PII, but a bad-SQL prompt can corrupt the books or fire unauthorized trades."
            wraps="@supervised('data_access')"
          />
          <Tier
            title="LLM tool-use"
            body="Ungated LLM calls. Prompt injection (someone wrote 'ignore previous instructions' in a ticket), jailbreak of the model guardrail, or a loop that burns tokens."
            wraps="@supervised('tool_use')"
          />
          <Tier
            title="General / informational"
            muted
            body="HTTP routes and cron schedules. They map the surface of the repo but don't move money or touch sensitive data directly. Useful to know what logic still isn't supervised."
            wraps="(no wrap needed)"
          />
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-6 py-16">
        <div className="mb-8">
          <h2 className="text-3xl font-bold tracking-tight">The fix is one gate before execution</h2>
          <p className="mt-3 max-w-2xl text-zinc-400">
            Your agent can still use tools. It just asks the supervisor before doing something expensive, destructive, or sensitive.
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

      <section className="mx-auto max-w-5xl px-6 py-16">
        <div className="mb-8">
          <h2 className="text-3xl font-bold tracking-tight">What it catches before production</h2>
          <p className="mt-3 max-w-2xl text-zinc-400">
            These are normal agent failure modes, not abstract security theater.
          </p>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <Risk title="Prompt-injected tool calls" body={'A ticket says "ignore previous instructions" and the agent tries to execute the user request.'} />
          <Risk title="Dangerous DB mutations" body="Generated SQL misses a tenant scope or a WHERE clause before touching customer tables." />
          <Risk title="Data leakage" body="The agent sends emails, PII, credit cards, or internal context into an LLM call." />
          <Risk title="Cost loops" body="Retry logic goes sideways and calls the same tool hundreds of times in a minute." />
          <Risk title="Unreviewed money movement" body="Refunds, transfers, payouts, and checkout sessions get a risk decision before the SDK call." />
          <Risk title="Role and account changes" body="Admin grants, password changes, and fresh-account edits get blocked or escalated." />
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-6 py-16">
        <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
          <div>
            <h2 className="text-3xl font-bold tracking-tight">Live attack scenarios</h2>
            <p className="mt-3 text-zinc-400">
              Inputs hit the supervisor before your action runs.
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

      <section className="border-y border-zinc-900 bg-zinc-950">
        <div className="mx-auto max-w-6xl px-6 py-16">
          <div className="mb-8">
            <h2 className="text-3xl font-bold tracking-tight">Pricing for solo builders</h2>
            <p className="mt-3 max-w-2xl text-zinc-400">
              Start with a public scan. Pay when the scanner becomes part of your shipping workflow.
            </p>
          </div>
          <div className="grid gap-5 md:grid-cols-3">
            <Plan
              name="Free"
              price="$0"
              cta="scan a public repo"
              href="/scan"
              items={["Public GitHub repo scan", "Top findings preview", "Risk tier summary", "Local CLI install"]}
            />
            <Plan
              featured
              name="Builder"
              price="$29/mo"
              cta="upgrade to builder"
              href="/scan?upgrade=builder"
              items={["Private repo scans", "Full runtime-supervisor export", "Stubs and YAML policies", "Scan history and diffs", "CI/GitHub PR comments"]}
            />
            <Plan
              name="Team"
              price="Later"
              cta="open dashboard"
              href="/dashboard"
              items={["Shared fix queue", "Team review workflow", "Audit retention", "Webhooks", "SSO when needed"]}
            />
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-6 py-16">
        <h2 className="text-3xl font-bold tracking-tight">Install path</h2>
        <div className="mt-10 grid gap-5 md:grid-cols-3">
          <Step num="01" title="scan your repo" command="supervisor-discover scan" />
          <Step num="02" title="start the supervisor" command="uv run ac start" />
          <Step num="03" title="wrap risky calls" command={'@supervised("payment")'} />
        </div>
        <div className="mt-10 flex flex-wrap gap-3">
          <Link href="/scan" className="rounded-lg bg-emerald-500 px-6 py-3 text-sm font-semibold text-black hover:bg-emerald-400">
            scan free
          </Link>
          <Link href="/dashboard" className="rounded-lg border border-zinc-800 bg-zinc-900 px-6 py-3 text-sm font-semibold text-zinc-200 hover:bg-zinc-800">
            open dashboard
          </Link>
          <Link href="https://github.com/ArielSanroj/runtime-supervisor" className="rounded-lg border border-zinc-800 bg-zinc-900 px-6 py-3 text-sm font-semibold text-zinc-200 hover:bg-zinc-800">
            github ↗
          </Link>
        </div>
      </section>

      <Footer />
    </div>
  );
}

function Header({ apiUp }: { apiUp: boolean }) {
  return (
    <header className="sticky top-0 z-10 border-b border-zinc-800 bg-black/80 backdrop-blur">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <Link href="/" className="flex items-baseline gap-2 font-mono text-sm">
          <span className="text-emerald-400">$</span>
          <span className="font-semibold text-zinc-100">vibefixing</span>
          <span className="text-xs text-zinc-500">// runtime-supervisor</span>
        </Link>
        <div className="flex items-center gap-3 text-sm">
          <span
            className={`hidden items-center gap-1.5 rounded-full border px-2.5 py-1 font-mono text-xs sm:inline-flex ${
              apiUp
                ? "border-emerald-700/50 bg-emerald-500/10 text-emerald-400"
                : "border-zinc-800 bg-zinc-900 text-zinc-500"
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${apiUp ? "bg-emerald-400" : "bg-zinc-600"}`} />
            {apiUp ? "api up" : "api down"}
          </span>
          <Link href="/scan" className="font-mono text-xs text-zinc-400 hover:text-zinc-200">
            /scan
          </Link>
          <Link href="/dashboard" className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-black hover:bg-emerald-400">
            dashboard
          </Link>
        </div>
      </div>
    </header>
  );
}

function ScanPreview() {
  // Real output of `supervisor-discover scan` against this repo
  // (agentic-internal-controls itself), in the new START HERE format. The CLI
  // now leads with "Best place to wrap first / This repo can already / Top
  // risks" — the per-tier breakdown is opt-in via --full or runtime-supervisor/
  // FULL_REPORT.md. Numbers are derived from the latest scan; refresh when the
  // repo changes shape.
  return (
    <div className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950 shadow-2xl shadow-emerald-950/20">
      <div className="flex items-center gap-2 border-b border-zinc-800 bg-zinc-900/80 px-4 py-2.5 font-mono text-xs text-zinc-500">
        <span className="h-2 w-2 rounded-full bg-rose-500" />
        <span className="h-2 w-2 rounded-full bg-amber-500" />
        <span className="h-2 w-2 rounded-full bg-emerald-500" />
        <span className="ml-2">terminal</span>
        <span className="ml-auto text-[10px] uppercase tracking-widest text-zinc-600">
          // real output, agentic-internal-controls repo
        </span>
      </div>
      <pre className="overflow-auto p-5 font-mono text-[13px] leading-relaxed text-zinc-200">
{`$ supervisor-discover scan
scanned /your-repo in 13.0s

Best place to wrap first:
  1. SupervisorAgent.handle      services/api/agents/supervisor.py:42
  2. tool: pay_order             services/api/agents/tools.py:18
  3. AgentExecutor framework     services/api/agents/executor.py:7

This repo can already:
  - move money
  - send emails
  - call messaging tools
  - run shell commands
  - call LLMs (Anthropic Claude, OpenAI)

Top risks:
  - money movement present
  - shell execution present
  - email sending present

Next:
  open runtime-supervisor/START_HERE.md      ← do this first
  runtime-supervisor/FULL_REPORT.md          ← all findings
  runtime-supervisor/ROLLOUT.md              ← phased deploy

-> wrote runtime-supervisor/
-> 6 combos detected — open first: agent-orchestrator.md`}
      </pre>
      <div className="grid border-t border-zinc-800 md:grid-cols-3">
        <PreviewMetric label="wrap targets surfaced" value="3" tone="good" />
        <PreviewMetric label="capabilities found" value="5" tone="danger" />
        <PreviewMetric label="combos detected" value="6" tone="muted" />
      </div>
    </div>
  );
}

function PreviewMetric({ label, value, tone }: { label: string; value: string; tone: "danger" | "good" | "muted" }) {
  const color = tone === "danger" ? "text-rose-400" : tone === "good" ? "text-emerald-400" : "text-zinc-300";
  return (
    <div className="border-b border-zinc-800 px-4 py-3 md:border-b-0 md:border-r last:md:border-r-0">
      <div className={`font-mono text-lg font-semibold ${color}`}>{value}</div>
      <div className="mt-1 font-mono text-[11px] uppercase tracking-widest text-zinc-600">{label}</div>
    </div>
  );
}

function Tier({
  title,
  body,
  wraps,
  danger,
  muted,
}: {
  title: string;
  body: string;
  wraps: string;
  danger?: boolean;
  muted?: boolean;
}) {
  const accent = danger ? "text-rose-400" : muted ? "text-zinc-500" : "text-emerald-400";
  const border = danger ? "border-rose-900/40" : muted ? "border-zinc-800" : "border-emerald-900/40";
  return (
    <div className={`flex h-full flex-col rounded-xl border ${border} bg-zinc-950/60 p-5`}>
      <div className={`font-mono text-xs uppercase tracking-widest ${accent}`}>{title}</div>
      <p className="mt-3 flex-1 text-sm leading-7 text-zinc-300">{body}</p>
      <div className="mt-4 inline-flex items-center gap-2 self-start rounded-md border border-zinc-800 bg-black/60 px-2.5 py-1.5 font-mono text-[11px] text-zinc-400">
        <span className="text-zinc-600">wrap:</span>
        <span className="text-zinc-200">{wraps}</span>
      </div>
    </div>
  );
}

function Cmd({ cmd }: { cmd: string }) {
  return (
    <div className="inline-flex max-w-full items-center gap-3 overflow-auto rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-2.5 font-mono text-sm">
      <span className="text-emerald-400">$</span>
      <span className="text-zinc-200">{cmd}</span>
    </div>
  );
}

function Outcome({ title, body }: { title: string; body: string }) {
  return (
    <div>
      <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">{title}</div>
      <p className="mt-3 text-sm leading-7 text-zinc-400">{body}</p>
    </div>
  );
}

function CodeBlock({ label, code, tone }: { label: string; code: string; tone: "muted" | "good" }) {
  return (
    <div>
      <div className={`mb-3 font-mono text-xs uppercase tracking-widest ${tone === "good" ? "text-emerald-400" : "text-zinc-500"}`}>
        {label}
      </div>
      <pre className={`overflow-auto rounded-xl border p-5 font-mono text-sm leading-relaxed ${
        tone === "good" ? "border-emerald-900/50 bg-emerald-500/5 text-zinc-100" : "border-zinc-800 bg-zinc-900/60 text-zinc-300"
      }`}>
        {code}
      </pre>
    </div>
  );
}

function Risk({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-5">
      <div className="font-semibold text-zinc-100">{title}</div>
      <p className="mt-2 text-sm leading-7 text-zinc-400">{body}</p>
    </div>
  );
}

function Plan({
  name,
  price,
  cta,
  href,
  items,
  featured = false,
}: {
  name: string;
  price: string;
  cta: string;
  href: string;
  items: string[];
  featured?: boolean;
}) {
  return (
    <div className={`rounded-xl border p-6 ${featured ? "border-emerald-700 bg-emerald-500/10" : "border-zinc-800 bg-zinc-900/40"}`}>
      <div className="flex items-baseline justify-between gap-4">
        <h3 className="text-xl font-semibold">{name}</h3>
        {featured && <span className="rounded-full bg-emerald-500 px-2 py-1 font-mono text-[10px] uppercase tracking-widest text-black">best first paid plan</span>}
      </div>
      <div className="mt-4 text-3xl font-bold">{price}</div>
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
        className={`mt-6 inline-flex w-full justify-center rounded-lg px-4 py-2.5 text-sm font-semibold ${
          featured ? "bg-emerald-500 text-black hover:bg-emerald-400" : "border border-zinc-800 bg-zinc-950 text-zinc-200 hover:bg-zinc-900"
        }`}
      >
        {cta}
      </Link>
    </div>
  );
}

function Step({ num, title, command }: { num: string; title: string; command: string }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5">
      <div className="font-mono text-xs text-zinc-600">{num}</div>
      <div className="mt-3 font-semibold text-zinc-100">{title}</div>
      <pre className="mt-3 overflow-auto rounded-lg border border-zinc-800 bg-black/60 p-3 font-mono text-xs text-zinc-300">
        {command}
      </pre>
    </div>
  );
}

function Footer() {
  return (
    <footer className="border-t border-zinc-900 bg-black">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-6 py-8 text-sm text-zinc-600">
        <div className="font-mono">
          <span className="text-emerald-400">$</span>{" "}
          <span className="text-zinc-400">vibefixing</span>{" "}
          <span className="text-zinc-700">guardrails for agents that ship</span>
        </div>
        <div className="flex gap-6 font-mono">
          <Link href="/scan" className="hover:text-zinc-300">/scan</Link>
          <Link href="/dashboard" className="hover:text-zinc-300">/dashboard</Link>
          <Link href="/review?status=pending" className="hover:text-zinc-300">/review</Link>
          <Link href="https://github.com/ArielSanroj/runtime-supervisor" className="hover:text-zinc-300">/github</Link>
        </div>
      </div>
    </footer>
  );
}
