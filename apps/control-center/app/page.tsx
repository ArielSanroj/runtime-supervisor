import Link from "next/link";
import { getLandingData } from "@/lib/landing-data";
import DemoCarousel from "./DemoCarousel";

export const revalidate = 30;

export default async function Landing() {
  const { sourcedFromApi } = await getLandingData();

  return (
    <div className="min-h-screen bg-black text-zinc-100 selection:bg-emerald-500/30">
      <Header apiUp={sourcedFromApi} />

      {/* 1. HERO — 5 segundos de lectura */}
      <section className="mx-auto max-w-4xl px-6 pt-24 pb-14">
        <div className="inline-flex items-center gap-2 rounded-full border border-zinc-800 bg-zinc-900/50 px-3 py-1 text-xs font-mono text-zinc-400">
          <span className="text-pink-400">#</span> for vibe coders shipping agents
        </div>
        <h1 className="mt-6 text-5xl font-bold leading-[1.05] tracking-tight sm:text-6xl">
          Your AI agent will eventually do something unsafe.
          <br />
          <span className="text-emerald-400">This stops it before it happens.</span>
        </h1>
        <p className="mt-6 max-w-2xl text-lg text-zinc-400">
          Intercept actions · Evaluate risk · Block or escalate — in real time.
        </p>
        <div className="mt-8 flex flex-wrap gap-3 font-mono text-sm">
          <Cmd cmd="pipx install supervisor-discover" />
          <Cmd cmd="uv run ac start" />
        </div>
        <div className="mt-4 text-sm text-zinc-500">
          <span className="text-emerald-400">→</span> 30 seconds, zero infra.
        </div>
      </section>

      {/* 2. BEFORE / AFTER */}
      <section className="mx-auto max-w-5xl px-6 py-14">
        <div className="grid gap-6 lg:grid-cols-2">
          <CodeBlock
            label="// before — your agent decides, then executes"
            labelClass="text-zinc-500"
            borderClass="border-zinc-800"
            bgClass="bg-zinc-900/60"
            lines={[
              ["def ", "pink"],
              ["handle_tool_call", "cyan"],
              ["(tool, args):", "zinc-400"],
              ["\n    ", "none"],
              ["return", "pink"],
              [" TOOLS[tool](**args)", "zinc-400"],
            ]}
          />
          <CodeBlock
            label="// after — supervisor gates every execution"
            labelClass="text-emerald-400"
            borderClass="border-emerald-900/40"
            bgClass="bg-emerald-500/5"
            lines={[
              ["from", "pink"],
              [" supervisor_guards ", "cyan"],
              ["import", "pink"],
              [" supervised", "zinc-200"],
              ["\n\n", "none"],
              ["@", "zinc-500"],
              ["supervised", "emerald"],
              ["(", "zinc-400"],
              ["\"tool_use\"", "yellow"],
              [")", "zinc-400"],
              ["\n", "none"],
              ["def", "pink"],
              [" ", "none"],
              ["handle_tool_call", "cyan"],
              ["(tool, args):", "zinc-400"],
              ["\n    ", "none"],
              ["return", "pink"],
              [" TOOLS[tool](**args)", "zinc-400"],
            ]}
          />
        </div>
        <p className="mt-6 text-sm text-zinc-500">
          <span className="text-emerald-400">→</span> one decorator. works with any tool — LLMs, DBs, APIs, filesystem, payment SDKs.
        </p>
      </section>

      {/* 3. QUICK WIN DEMO — what happens in 30 seconds */}
      <section className="mx-auto max-w-4xl px-6 py-14">
        <h2 className="text-3xl font-bold tracking-tight">What happens in 30 seconds</h2>
        <p className="mt-3 text-zinc-400">Point it at any Python or TS repo. It finds every action your agent could execute.</p>

        <div className="mt-8 overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950">
          <div className="flex items-center gap-2 border-b border-zinc-800 bg-zinc-900/60 px-4 py-2.5 font-mono text-xs text-zinc-500">
            <span className="h-2 w-2 rounded-full bg-rose-500" />
            <span className="h-2 w-2 rounded-full bg-amber-500" />
            <span className="h-2 w-2 rounded-full bg-emerald-500" />
            <span className="ml-2">terminal</span>
          </div>
          <pre className="overflow-auto p-5 font-mono text-sm leading-relaxed text-zinc-200">
{`$ supervisor-discover scan
scanned your repo in 9.5s

  ✔ 5 LLM calls
  ✔ 853 DB mutations
  ✔ 569 HTTP routes
  ✔ 2 payment actions
  ✔ 3 cron schedules

→ wrote runtime-supervisor/ (report, stubs, policies)
`}
          </pre>
        </div>
        <p className="mt-5 text-sm text-zinc-400">
          Real numbers from a real repo scan. Every call-site that could touch customer data, move money, or invoke an LLM — indexed in seconds.
        </p>
      </section>

      {/* 4. WHAT THIS PREVENTS — error-first, zero jargon */}
      <section className="mx-auto max-w-4xl px-6 py-14">
        <h2 className="text-3xl font-bold tracking-tight">What this prevents in production</h2>
        <p className="mt-3 text-zinc-400">Not theoretical attacks. Things that happen when agents ship without gates.</p>

        <div className="mt-10 space-y-5">
          <Bullet
            severity="high"
            title="Agent runs a prompt-injected tool call"
            body={'Someone writes "ignore previous instructions..." in a support ticket, your agent does what they said.'}
          />
          <Bullet
            severity="high"
            title="Agent deletes the wrong table"
            body="LLM generates SQL from natural language, passes DELETE FROM users. With WHERE missing. In prod."
          />
          <Bullet
            severity="high"
            title="Agent leaks customer data through the LLM"
            body="Agent echoes back an email address, a credit card, an SSN. Now it's in the model provider's logs."
          />
          <Bullet
            severity="mid"
            title="Agent loops and burns tokens"
            body="Retry logic goes wrong, same tool call 400 times in 30 seconds. Rate limits, cost spike, or worse."
          />
          <Bullet
            severity="mid"
            title="Agent makes a high-risk decision unsupervised"
            body="Refunds, account changes, admin role grants, compliance closures — actions that need a human in the loop when they hit a threshold."
          />
        </div>
      </section>

      {/* 5. ATTACK SCENARIOS — live demo rotativo */}
      <section className="mx-auto max-w-4xl px-6 py-14">
        <h2 className="text-3xl font-bold tracking-tight">Live attack scenarios</h2>
        <p className="mt-3 text-zinc-400">
          What happens when these inputs hit the supervisor.
          <span className="ml-2 font-mono text-xs text-zinc-600">
            {sourcedFromApi ? "// evaluated live" : "// static preview — start supervisor for live"}
          </span>
        </p>

        <div className="mt-8">
          <DemoCarousel />
        </div>
      </section>

      {/* 6. RULES (renombrado de policies) */}
      <section className="mx-auto max-w-5xl px-6 py-14">
        <h2 className="text-3xl font-bold tracking-tight">Rules that ship by default</h2>
        <p className="mt-3 text-zinc-400">
          Editable YAML. Promote a new version via API, takes effect on the next call.
        </p>

        <div className="mt-10 grid gap-4 md:grid-cols-2">
          <RuleCard
            title="Stops unsafe refunds"
            deny={["amount > 10,000", "amount ≤ 0 (invalid)"]}
            review={["reason is \"fraud_dispute\""]}
            policyName="refund.base.v1"
          />
          <RuleCard
            title="Stops unsafe payments"
            deny={["hard-cap exceeded", "destination is a sanctioned country"]}
            review={["approval chain missing on large amount", "bank account changed mid-transfer"]}
            policyName="payment.base.v1"
          />
          <RuleCard
            title="Stops risky tool calls"
            deny={["tool is system.exec / fs.delete / network.raw", "no tool name provided"]}
            review={["prompt exceeds 50k chars"]}
            policyName="tool_use.base.v1"
          />
          <RuleCard
            title="Stops account takeovers"
            deny={["email + phone + password in one call", "role escalated to admin/owner/superuser"]}
            review={["email changed on a fresh account (<30 days)"]}
            policyName="account_change.base.v1"
          />
          <RuleCard
            title="Stops mass data exports"
            deny={["projection includes credit_card / ssn / cvv", "query without tenant scope"]}
            review={["row limit > 1,000 or unbounded"]}
            policyName="data_access.base.v1"
          />
          <RuleCard
            title="Stops compliance shortcuts"
            deny={[]}
            review={["every compliance action (placeholder until your compliance officer writes real rules)"]}
            policyName="compliance.base.v1"
          />
        </div>
      </section>

      {/* 7. SCANNERS */}
      <section className="mx-auto max-w-5xl px-6 py-14">
        <h2 className="text-3xl font-bold tracking-tight">What the scanner finds in your code</h2>
        <p className="mt-3 text-zinc-400">5 static scanners. Run once, get a map of every call-site worth gating.</p>

        <div className="mt-10 grid gap-4 md:grid-cols-2">
          <ScannerList
            header="customer data"
            color="amber"
            items={["UPDATE users / accounts / customers", "DELETE FROM orders", "prisma.user.update()", "typeorm remove()"]}
          />
          <ScannerList
            header="llm"
            color="cyan"
            items={["anthropic.messages.create", "openai.chat.completions.create", "langchain.invoke", "llama_index.query"]}
          />
          <ScannerList
            header="payment"
            color="emerald"
            items={["stripe.Refund.create", "stripe.checkout.Session.create", "paypal.payouts.create", "plaid.Transfer.create"]}
          />
          <ScannerList
            header="ops-surface"
            color="zinc"
            items={["@app.route / @router.get", "cron schedules", "celery beat_schedule", "node-cron schedule()"]}
          />
        </div>
      </section>

      {/* 8. INSTALL — 3 steps */}
      <section className="border-t border-zinc-900 bg-zinc-950">
        <div className="mx-auto max-w-5xl px-6 py-16">
          <h2 className="text-3xl font-bold tracking-tight">Install</h2>

          <div className="mt-10 space-y-8">
            <Step num="01" title="scan your repo" command="supervisor-discover scan" result="shows every call-site that needs supervision" />
            <Step
              num="02"
              title="start the local supervisor"
              command="uv run ac start"
              result="SQLite, zero infra, panel on localhost:3099"
            />
            <Step
              num="03"
              title="wrap your code"
              command={`@supervised("payment")\ndef create_checkout(...): ...`}
              result="shadow mode by default. flip to enforce when you trust the policy."
            />
          </div>

          <div className="mt-12 flex flex-wrap gap-3">
            <Link
              href="/dashboard"
              className="rounded-lg bg-emerald-500 px-6 py-3 text-sm font-semibold text-black hover:bg-emerald-400"
            >
              open panel →
            </Link>
            <Link
              href="https://github.com/ArielSanroj/runtime-supervisor"
              className="rounded-lg border border-zinc-800 bg-zinc-900 px-6 py-3 text-sm font-semibold text-zinc-200 hover:bg-zinc-800"
            >
              github ↗
            </Link>
          </div>
        </div>
      </section>

      {/* 9. tl;dr */}
      <section className="mx-auto max-w-4xl px-6 py-16">
        <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-8">
          <div className="text-xs font-mono uppercase tracking-widest text-zinc-500">tl;dr</div>
          <p className="mt-4 text-xl leading-relaxed text-zinc-200">
            Every agent running <span className="font-mono text-emerald-400">@tool</span> in prod can execute whatever the LLM
            decides. Today you trust the prompt is clean. Tomorrow someone sends{" "}
            <span className="font-mono text-rose-400">&quot;ignore previous instructions&quot;</span> and your agent does what they
            asked — a refund, a DELETE, a role grant, a leak of your system prompt.
          </p>
          <p className="mt-4 text-xl leading-relaxed text-zinc-400">This catches it on line 1.</p>
        </div>
      </section>

      <Footer />
    </div>
  );
}

// ── Components ─────────────────────────────────────────────────

function Header({ apiUp }: { apiUp: boolean }) {
  return (
    <header className="sticky top-0 z-10 border-b border-zinc-800 bg-black/70 backdrop-blur">
      <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
        <div className="flex items-baseline gap-2 font-mono text-sm">
          <span className="text-emerald-400">$</span>
          <span className="font-semibold text-zinc-100">vibefixing</span>
          <span className="text-xs text-zinc-500">// runtime-supervisor</span>
        </div>
        <div className="flex items-center gap-3 text-sm">
          <span
            className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-mono ${
              apiUp
                ? "border-emerald-700/50 bg-emerald-500/10 text-emerald-400"
                : "border-zinc-800 bg-zinc-900 text-zinc-500"
            }`}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                apiUp ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" : "bg-zinc-600"
              }`}
            />
            {apiUp ? "api up" : "api down"}
          </span>
          <Link
            href="/dashboard"
            className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-black hover:bg-emerald-400"
          >
            open panel
          </Link>
        </div>
      </div>
    </header>
  );
}

function Cmd({ cmd }: { cmd: string }) {
  return (
    <div className="inline-flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-2.5">
      <span className="text-emerald-400">$</span>
      <span className="text-zinc-200">{cmd}</span>
    </div>
  );
}

function CodeBlock({
  label,
  labelClass,
  borderClass,
  bgClass,
  lines,
}: {
  label: string;
  labelClass: string;
  borderClass: string;
  bgClass: string;
  lines: Array<[string, string]>;
}) {
  const colorMap: Record<string, string> = {
    pink: "text-pink-400",
    cyan: "text-cyan-300",
    emerald: "text-emerald-400",
    yellow: "text-yellow-300",
    "zinc-200": "text-zinc-200",
    "zinc-400": "text-zinc-400",
    "zinc-500": "text-zinc-500",
    none: "",
  };
  return (
    <div>
      <div className={`mb-3 text-xs font-mono uppercase tracking-widest ${labelClass}`}>{label}</div>
      <pre className={`overflow-auto rounded-xl border ${borderClass} ${bgClass} p-5 font-mono text-sm leading-relaxed`}>
        {lines.map(([text, color], i) => (
          <span key={i} className={colorMap[color]}>
            {text}
          </span>
        ))}
      </pre>
    </div>
  );
}

function Bullet({
  severity,
  title,
  body,
}: {
  severity: "high" | "mid";
  title: string;
  body: string;
}) {
  const dot = severity === "high" ? "bg-rose-500" : "bg-amber-500";
  return (
    <div className="flex gap-4">
      <span className={`mt-2.5 h-2.5 w-2.5 flex-shrink-0 rounded-full ${dot}`} />
      <div>
        <div className="text-lg font-semibold text-zinc-100">{title}</div>
        <p className="mt-1 text-zinc-400">{body}</p>
      </div>
    </div>
  );
}

function RuleCard({
  title,
  deny,
  review,
  policyName,
}: {
  title: string;
  deny: string[];
  review: string[];
  policyName: string;
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5">
      <div className="font-semibold text-zinc-100">{title}</div>
      {deny.length > 0 && (
        <div className="mt-3">
          <div className="font-mono text-xs uppercase tracking-widest text-rose-400">block if</div>
          <ul className="mt-1.5 space-y-1 text-sm text-zinc-400">
            {deny.map((d) => (
              <li key={d} className="flex gap-2">
                <span className="text-zinc-700">·</span>
                <span>{d}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {review.length > 0 && (
        <div className="mt-3">
          <div className="font-mono text-xs uppercase tracking-widest text-amber-400">needs approval if</div>
          <ul className="mt-1.5 space-y-1 text-sm text-zinc-400">
            {review.map((r) => (
              <li key={r} className="flex gap-2">
                <span className="text-zinc-700">·</span>
                <span>{r}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      <div className="mt-4 font-mono text-xs text-zinc-600">── {policyName} ──</div>
    </div>
  );
}

function ScannerList({
  header,
  color,
  items,
}: {
  header: string;
  color: "emerald" | "cyan" | "amber" | "zinc";
  items: string[];
}) {
  const map: Record<string, string> = {
    emerald: "text-emerald-400",
    cyan: "text-cyan-400",
    amber: "text-amber-400",
    zinc: "text-zinc-400",
  };
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5">
      <div className={`font-mono text-xs uppercase tracking-widest ${map[color]}`}># {header}</div>
      <ul className="mt-3 space-y-1.5 font-mono text-sm text-zinc-400">
        {items.map((it) => (
          <li key={it} className="flex gap-2">
            <span className="text-zinc-700">·</span>
            <span>{it}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Step({ num, title, command, result }: { num: string; title: string; command: string; result: string }) {
  return (
    <div className="flex gap-6">
      <div className="font-mono text-6xl font-bold text-zinc-800">{num}</div>
      <div className="flex-1">
        <div className="text-xl font-semibold text-zinc-100">{title}</div>
        <pre className="mt-3 overflow-auto rounded-lg border border-zinc-800 bg-zinc-900/80 p-4 font-mono text-sm leading-relaxed text-zinc-200">
          {command}
        </pre>
        <p className="mt-3 text-sm text-zinc-500">
          <span className="text-emerald-400">→</span> {result}
        </p>
      </div>
    </div>
  );
}

function Footer() {
  return (
    <footer className="border-t border-zinc-900 bg-black">
      <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-4 px-6 py-8 text-sm text-zinc-600">
        <div className="font-mono">
          <span className="text-emerald-400">$</span>{" "}
          <span className="text-zinc-400">vibefixing</span>{" "}
          <span className="text-zinc-600">// runtime-supervisor</span>{" "}
          <span className="text-zinc-700">— guardrails for agents that ship</span>
        </div>
        <div className="flex gap-6 font-mono">
          <Link href="/dashboard" className="hover:text-zinc-300">
            /dashboard
          </Link>
          <Link href="/review?status=pending" className="hover:text-zinc-300">
            /review
          </Link>
          <Link href="/policies" className="hover:text-zinc-300">
            /policies
          </Link>
          <Link href="https://github.com/ArielSanroj/runtime-supervisor" className="hover:text-zinc-300">
            /github
          </Link>
        </div>
      </div>
    </footer>
  );
}
