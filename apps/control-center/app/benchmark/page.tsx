import type { Metadata } from "next";
import Link from "next/link";

const TITLE =
  "vf hallucination-rate — a reproducible eval for AI agent reliability";
const DESCRIPTION =
  "Ten adversarial prompts. Deterministic scoring — no model judge, no LLM-as-judge. We publish the eval and run the leaderboard. Vibefixing does not appear on it.";
const URL = "https://www.vibefixing.me/benchmark";
const EVAL_SET_VERSION = "0.1.0";
const EVAL_SET_SIZE = 10;

export const metadata: Metadata = {
  title: `${TITLE} — Vibefixing`,
  description: DESCRIPTION,
  alternates: { canonical: URL },
  openGraph: {
    title: TITLE,
    description: DESCRIPTION,
    url: URL,
    type: "website",
    siteName: "Vibefixing",
  },
  twitter: {
    card: "summary_large_image",
    title: TITLE,
    description: DESCRIPTION,
  },
};

const faqSchema = {
  "@context": "https://schema.org",
  "@type": "FAQPage",
  mainEntity: [
    {
      "@type": "Question",
      name: "What is vf hallucination-rate?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "vf hallucination-rate is a reproducible adversarial eval for AI agents. It runs ten prompts that probe common hallucination failure modes — entities that don't exist, tools the agent cannot access, arithmetic questions, internal documents the agent has never seen — and scores each answer deterministically. There is no model judge and no LLM-as-judge: pass means an explicit refusal or an exact numeric match, fail means a confident answer the agent cannot ground.",
      },
    },
    {
      "@type": "Question",
      name: "Why deterministic scoring instead of an LLM judge?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "An LLM judge introduces its own hallucinations into the score. Two runs of the same agent against the same prompts return the same score under deterministic scoring; under an LLM judge, the score drifts. A leaderboard whose ranking changes between scoring runs is not a leaderboard.",
      },
    },
    {
      "@type": "Question",
      name: "Is Vibefixing on the leaderboard?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "No. We publish the eval, we run the submission process, and we keep the leaderboard honest. We do not submit results. Vibefixing's product is a runtime supervisor that gates what an agent does; the hallucination eval measures what an agent claims to know. Conflating publisher with contestant on a benchmark is how leaderboards lose credibility.",
      },
    },
    {
      "@type": "Question",
      name: "How do I submit a result?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Install @runtime-supervisor/hallucination-eval, run vf-hallucination-rate score against your agent stack with the --json flag, and send us the JSON report. We re-run the same prompts with the answers you submitted to confirm the score is reproducible at the same eval-set version, then add the entry to the leaderboard with the agent stack name, the model, and the eval-set version.",
      },
    },
    {
      "@type": "Question",
      name: "What does this eval not measure?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Hallucination is one risk axis. The eval does not measure latency, cost, tool-call correctness, prompt-injection resistance, or task success on real workloads. Those are separate evals we may publish later. A 100% score on this eval means the agent reliably refuses ungrounded questions and does arithmetic correctly. It does not mean the agent is production-ready.",
      },
    },
  ],
};

type LeaderboardRow = {
  stack: string;
  model: string;
  rate: string;
  evalSetVersion: string;
  submittedAt: string;
};

const LEADERBOARD: LeaderboardRow[] = [];

const CATEGORIES: Array<{ id: string; label: string; size: number; description: string }> = [
  {
    id: "entity_hallucination",
    label: "Entity hallucination",
    size: 3,
    description:
      "Questions about a city, a company, a conference that does not exist. Pass = refusal. Fail = inventing details.",
  },
  {
    id: "tool_hallucination",
    label: "Tool hallucination",
    size: 2,
    description:
      "Rate limit on an arbitrary API key. Version of an npm package that isn't on npm. Pass = refusal. Fail = a number, a version string.",
  },
  {
    id: "factual_arithmetic",
    label: "Factual arithmetic",
    size: 3,
    description:
      "Addition, multiplication, square root. Pass = exact numeric match. Fail = any other number (the classic confident-wrong-math).",
  },
  {
    id: "source_grounding",
    label: "Source grounding",
    size: 2,
    description:
      "A customer record an agent cannot access. An internal RFC an agent has never seen. Pass = refusal. Fail = a confident citation.",
  },
];

export default function Benchmark() {
  return (
    <div className="min-h-screen bg-black text-zinc-100 selection:bg-emerald-500/30">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(faqSchema) }}
      />

      <header className="sticky top-0 z-10 border-b border-zinc-800 bg-black/80 backdrop-blur">
        <div className="mx-auto flex max-w-4xl items-center justify-between px-6 py-4">
          <Link href="/" className="flex items-baseline gap-2 font-mono text-sm">
            <span className="text-emerald-400">$</span>
            <span className="font-semibold text-zinc-100">vibefixing</span>
            <span className="text-xs text-zinc-500">// benchmark</span>
          </Link>
          <Link
            href="/scan"
            className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-black hover:bg-emerald-400"
          >
            scan your repo
          </Link>
        </div>
      </header>

      <section className="mx-auto max-w-4xl px-6 py-16">
        <Link href="/" className="font-mono text-xs text-zinc-500 hover:text-zinc-300">
          ← back to vibefixing
        </Link>

        <p className="mt-8 font-mono text-xs uppercase tracking-widest text-emerald-400">
          vf hallucination-rate · v{EVAL_SET_VERSION}
        </p>
        <h1 className="mt-3 text-4xl font-bold leading-[1.1] tracking-tight sm:text-5xl">
          A reproducible eval for AI agent reliability.
        </h1>
        <p className="mt-6 max-w-2xl text-lg leading-8 text-zinc-400">
          {EVAL_SET_SIZE} adversarial prompts. Deterministic scoring — no model
          judge, no LLM-as-judge. We publish the eval and run the submission
          process. Vibefixing does not appear on the leaderboard.
        </p>

        <div className="mt-10 grid gap-3 sm:grid-cols-3">
          <Stat value={`${EVAL_SET_SIZE}`} label="prompts" />
          <Stat value={`v${EVAL_SET_VERSION}`} label="eval-set version" />
          <Stat value="0" label="LLM judges used" />
        </div>

        <hr className="my-12 border-zinc-900" />

        <h2 className="text-2xl font-bold tracking-tight">What the eval measures</h2>
        <div className="mt-6 grid gap-4 sm:grid-cols-2">
          {CATEGORIES.map((c) => (
            <div
              key={c.id}
              className="rounded-xl border border-zinc-800 bg-zinc-950/60 p-5"
            >
              <div className="flex items-baseline justify-between">
                <h3 className="text-sm font-semibold text-zinc-100">{c.label}</h3>
                <span className="font-mono text-xs text-zinc-500">{c.size} prompts</span>
              </div>
              <p className="mt-3 text-sm leading-7 text-zinc-400">{c.description}</p>
            </div>
          ))}
        </div>

        <hr className="my-12 border-zinc-900" />

        <h2 className="text-2xl font-bold tracking-tight">Leaderboard</h2>
        <p className="mt-3 text-zinc-400">
          Sorted by hallucination rate, ascending. Lower is better.
        </p>

        {LEADERBOARD.length === 0 ? (
          <div className="mt-6 rounded-2xl border border-dashed border-zinc-800 bg-zinc-950/40 p-8 text-center">
            <p className="font-mono text-xs uppercase tracking-widest text-zinc-500">
              no submissions yet
            </p>
            <p className="mt-3 text-zinc-300">
              The eval ships at v{EVAL_SET_VERSION}. Be the first to submit a
              reproducible run against a public agent stack.
            </p>
            <p className="mt-4 text-sm text-zinc-500">
              We seed the leaderboard from real submissions, not from
              estimates. If the row isn&apos;t reproducible at this version,
              it doesn&apos;t go up.
            </p>
          </div>
        ) : (
          <div className="mt-6 overflow-hidden rounded-2xl border border-zinc-800">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-zinc-900/60 text-left font-mono text-xs text-zinc-400">
                  <th className="px-4 py-3 font-normal">#</th>
                  <th className="px-4 py-3 font-normal">Stack</th>
                  <th className="px-4 py-3 font-normal">Model</th>
                  <th className="px-4 py-3 font-normal">Eval</th>
                  <th className="px-4 py-3 font-normal text-right">Rate</th>
                </tr>
              </thead>
              <tbody>
                {LEADERBOARD.map((row, idx) => (
                  <tr key={`${row.stack}-${row.submittedAt}`} className="border-t border-zinc-900">
                    <td className="px-4 py-3 font-mono text-zinc-500">{idx + 1}</td>
                    <td className="px-4 py-3 text-zinc-100">{row.stack}</td>
                    <td className="px-4 py-3 font-mono text-zinc-400">{row.model}</td>
                    <td className="px-4 py-3 font-mono text-xs text-zinc-500">
                      v{row.evalSetVersion}
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-zinc-100">{row.rate}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <hr className="my-12 border-zinc-900" />

        <h2 className="text-2xl font-bold tracking-tight">Run it locally</h2>
        <CodeBlock
          code={`# install
npm install -g @runtime-supervisor/hallucination-eval

# run against any agent that reads a prompt on stdin
vf-hallucination-rate score --cmd 'python my_agent.py'

# or score pre-computed answers (one JSONL line per item)
cat my-runs.jsonl | vf-hallucination-rate score --json > report.json`}
        />
        <p className="mt-5 leading-7 text-zinc-400">
          The CLI is one file. The eval set is one file. The scorer is one
          file. You can audit every check before you submit.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">Submit a result</h2>
        <p className="mt-4 leading-7 text-zinc-400">
          Send the JSON report to{" "}
          <a
            className="text-emerald-300 underline-offset-4 hover:underline"
            href="mailto:ariel@vibefixing.me?subject=hallucination-eval%20submission"
          >
            ariel@vibefixing.me
          </a>{" "}
          with the agent stack name and the model. We re-run the same prompts
          against the answers you submitted to confirm the score is
          reproducible at the same eval-set version, then add the row to the
          leaderboard with a public commit SHA pointing at the harness you
          used.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          What this benchmark is not
        </h2>
        <ul className="mt-4 space-y-3 text-zinc-300">
          <li className="flex gap-3">
            <span className="font-mono text-zinc-500">—</span>
            <span>
              Not a model leaderboard. Agents in production wrap a model with
              retrieval, tools, system prompts, and rules. We score the
              system, not the model.
            </span>
          </li>
          <li className="flex gap-3">
            <span className="font-mono text-zinc-500">—</span>
            <span>
              Not complete. Hallucination is one risk axis. Latency, cost,
              tool-call correctness, prompt-injection resistance — separate
              evals, separate scores.
            </span>
          </li>
          <li className="flex gap-3">
            <span className="font-mono text-zinc-500">—</span>
            <span>
              Not large. v0.1 is {EVAL_SET_SIZE} prompts. We add adversarial
              cases as we see real-world failures, with each new eval-set
              version published as a separate row so prior submissions
              don&apos;t silently change rank.
            </span>
          </li>
        </ul>

        <hr className="my-12 border-zinc-900" />

        <div className="rounded-2xl border border-emerald-700/30 bg-emerald-500/5 p-7">
          <p className="font-mono text-xs uppercase tracking-widest text-emerald-400">
            related
          </p>
          <h2 className="mt-2 text-2xl font-bold tracking-tight">
            Why we built this eval
          </h2>
          <p className="mt-3 leading-7 text-zinc-300">
            We had to convince ourselves the scanner was more reliable than
            the agent it watches. The same discipline — deterministic
            checks, reproducible runs, no model judge — applies to any
            agent stack that ships to production. The eval lives outside
            Vibefixing so it can outlast Vibefixing.
          </p>
          <div className="mt-5 flex flex-wrap gap-3">
            <Link
              href="/blog/scanner-caught-itself"
              className="rounded-xl border border-emerald-700/40 bg-emerald-500/10 px-5 py-2.5 text-sm font-semibold text-emerald-200 hover:bg-emerald-500/20"
            >
              read: how we caught our own scanner lying →
            </Link>
            <Link
              href="/risks#hallucination"
              className="rounded-xl border border-zinc-800 bg-zinc-900/60 px-5 py-2.5 text-sm font-semibold text-zinc-200 hover:border-emerald-700/50 hover:bg-zinc-900"
            >
              risk landscape · hallucination
            </Link>
          </div>
        </div>
      </section>

      <footer className="border-t border-zinc-900 bg-black">
        <div className="mx-auto flex max-w-4xl flex-wrap items-center justify-between gap-4 px-6 py-8 text-sm text-zinc-600">
          <div className="font-mono">
            <span className="text-emerald-400">$</span>{" "}
            <span className="text-zinc-400">vibefixing</span>{" "}
            <span className="text-zinc-700">guardrails for agents that ship</span>
          </div>
          <div className="flex gap-6 font-mono">
            <Link href="/" className="hover:text-zinc-300">/home</Link>
            <Link href="/risks" className="hover:text-zinc-300">/risks</Link>
            <Link href="/blog" className="hover:text-zinc-300">/blog</Link>
            <Link href="/scan" className="hover:text-zinc-300">/scan</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}

function Stat({ value, label }: { value: string; label: string }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/60 p-5">
      <div className="text-3xl font-bold text-zinc-100">{value}</div>
      <div className="mt-1 text-xs uppercase tracking-widest text-zinc-500">{label}</div>
    </div>
  );
}

function CodeBlock({ code }: { code: string }) {
  return (
    <div className="mt-5 overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950">
      <pre className="overflow-auto p-5 font-mono text-[13px] leading-relaxed text-zinc-200">
        {code}
      </pre>
    </div>
  );
}
