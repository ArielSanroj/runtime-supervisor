import type { Metadata } from "next";
import Link from "next/link";
import { threatsApi, type ThreatCatalogEntry } from "../../lib/threats";

export const dynamic = "force-dynamic";

const TITLE =
  "Audit trail for AI agents — what your auditor will actually ask";
const DESCRIPTION =
  "Three artifacts survive a quarterly review of an AI agent: a logged decision per action, the policy version at the time of the decision, and a tamper-evident chain so the log can't be rewritten. Here's what Vibefixing emits today and how it maps to the questions your auditor will ask.";
const URL = "https://www.vibefixing.me/compliance";

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
      name: "What does an auditor actually ask about an AI agent?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Three things, in order: 'show me every time the agent moved money in March', 'show me which policy was in effect when that happened', and 'show me that this log wasn't edited after the fact'. The right artifacts are a per-decision log with inputs and reasons, a policy version stamp on every decision, and a tamper-evident chain (hash-linked or signed). Everything else is documentation around these three primitives.",
      },
    },
    {
      "@type": "Question",
      name: "Is Vibefixing SOC 2 or NIST AI RMF certified?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "No. Vibefixing emits the artifacts an auditor asks for and ships a NIST AI RMF crosswalk that maps our outputs to GOVERN, MAP, MEASURE, and MANAGE functions. Mapping is not certification. If you need a SOC 2 Type II report on the supervisor itself, we don't have one to hand you today; the crosswalk lets you reuse Vibefixing artifacts inside your own audit instead of regenerating them.",
      },
    },
    {
      "@type": "Question",
      name: "How does Vibefixing record a decision so it can be replayed later?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Every supervisor decision writes an evidence event with the input fingerprint, the policy version, the reason strings, the threat signals that fired, and a deterministic risk score. The events are hash-linked so a tamper attempt breaks the chain at the next read. Replay is a dry-run of the same input against the current policy via /v1/actions/evaluate, which lets you see whether a fix shipped this week would have changed an outcome from last month.",
      },
    },
    {
      "@type": "Question",
      name: "What happens to the evidence log if I cancel my Vibefixing plan?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "You keep read-only access to historical scan artifacts and evidence events for 90 days after cancellation. We email a 30-day notice before that window closes with a one-click export bundle. No dark patterns and no silent retention beyond what your tier specified.",
      },
    },
    {
      "@type": "Question",
      name: "Can I run the supervisor on-prem to keep evidence inside my VPC?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Yes, on Enterprise. The supervisor is a FastAPI service with a SQL backend; the same container runs in your VPC against your own database, and the SDK clients point at your internal endpoint. The hash-linked chain and policy versioning work identically; the only difference is that we never see the events.",
      },
    },
  ],
};

async function loadCatalog(): Promise<{ items: ThreatCatalogEntry[]; live: boolean }> {
  try {
    const items = await threatsApi.catalog();
    return { items, live: true };
  } catch {
    return { items: [], live: false };
  }
}

export default async function Compliance() {
  const { items: threatCatalog, live } = await loadCatalog();

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
            <span className="text-xs text-zinc-500">// compliance</span>
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
          audit trail
        </p>
        <h1 className="mt-3 text-4xl font-bold leading-[1.1] tracking-tight sm:text-5xl">
          Audit trail for AI agents —
          <br />
          <span className="text-zinc-400">what your auditor will actually ask.</span>
        </h1>
        <p className="mt-6 max-w-2xl text-lg leading-8 text-zinc-400">
          Three artifacts survive a quarterly review of an AI agent. A
          per-decision log. A policy version stamp on every decision. A
          tamper-evident chain so the log can&apos;t be rewritten. Here&apos;s
          what Vibefixing emits today.
        </p>

        <hr className="my-12 border-zinc-900" />

        <h2 className="text-2xl font-bold tracking-tight">The three artifacts</h2>
        <div className="mt-6 grid gap-5 sm:grid-cols-3">
          <ArtifactCard
            chip="01 · decision log"
            title="Every action carries its rationale"
            body="For each supervised call, the evidence event records the input fingerprint, the reason strings, the threat signals that fired, the resulting decision (allow / deny / review), and a deterministic risk score."
          />
          <ArtifactCard
            chip="02 · policy version"
            title="Stamped at the moment of the decision"
            body="Policies are versioned YAML. The version that applied at the moment a decision was made is recorded with the decision — not 'whatever the current version says', so a fix shipped today doesn't rewrite history."
          />
          <ArtifactCard
            chip="03 · tamper evidence"
            title="Hash-linked chain"
            body="Events are hash-linked. A modification anywhere in the history breaks the chain on the next read, surfacing a verification failure rather than a silent edit."
          />
        </div>

        <hr className="my-12 border-zinc-900" />

        <h2 className="text-2xl font-bold tracking-tight">
          Threat catalog the supervisor knows about
        </h2>
        <p className="mt-3 max-w-2xl text-zinc-400">
          Each threat has an OWASP LLM Top 10 reference (or an internal id
          where no public reference applies). Auditors usually want this
          column populated; it&apos;s populated.
        </p>

        {threatCatalog.length === 0 ? (
          <div className="mt-6 rounded-2xl border border-dashed border-zinc-800 bg-zinc-950/40 p-6">
            <p className="font-mono text-xs uppercase tracking-widest text-zinc-500">
              catalog not reachable from this build
            </p>
            <p className="mt-3 text-zinc-300">
              The threat catalog is served by the supervisor API. When this
              page renders in production, the table below is sourced live
              from <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">/v1/threats/catalog</code>. The current build returned no
              entries — likely the API is offline or this is a preview
              snapshot.
            </p>
          </div>
        ) : (
          <div className="mt-6 overflow-hidden rounded-2xl border border-zinc-800">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-zinc-900/60 text-left font-mono text-xs text-zinc-400">
                  <th className="px-4 py-3 font-normal">Threat</th>
                  <th className="px-4 py-3 font-normal">OWASP ref</th>
                  <th className="px-4 py-3 font-normal">Severity</th>
                  <th className="px-4 py-3 font-normal">One-liner</th>
                </tr>
              </thead>
              <tbody>
                {threatCatalog.map((t) => (
                  <tr key={t.id} className="border-t border-zinc-900">
                    <td className="px-4 py-3 text-zinc-100">{t.title}</td>
                    <td className="px-4 py-3 font-mono text-xs text-zinc-400">{t.owasp_ref}</td>
                    <td className="px-4 py-3">
                      <SeverityChip level={t.severity} />
                    </td>
                    <td className="px-4 py-3 text-zinc-400">{t.one_liner}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="border-t border-zinc-900 bg-zinc-950/40 px-4 py-3 font-mono text-xs text-zinc-500">
              {threatCatalog.length} entries{" "}
              {live ? "· live from /v1/threats/catalog" : "· preview snapshot"}
            </div>
          </div>
        )}

        <hr className="my-12 border-zinc-900" />

        <h2 className="text-2xl font-bold tracking-tight">
          What we will not claim
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          Compliance language gets sloppy fast. Three lines we hold:
        </p>
        <ul className="mt-5 space-y-3 text-zinc-300">
          <li className="flex gap-3">
            <span className="font-mono text-rose-400">×</span>
            <span>
              We do not say <strong className="text-zinc-100">SOC 2 certified</strong>{" "}
              or <strong className="text-zinc-100">NIST AI RMF compliant</strong>.
              Vibefixing emits artifacts that map to those frameworks. Your
              compliance team writes the report; we don&apos;t.
            </span>
          </li>
          <li className="flex gap-3">
            <span className="font-mono text-rose-400">×</span>
            <span>
              We do not promise that installing Vibefixing makes your agent
              pass an audit. It makes the audit answerable. The difference
              matters.
            </span>
          </li>
          <li className="flex gap-3">
            <span className="font-mono text-rose-400">×</span>
            <span>
              We do not pretend the evidence chain is a court-admissible
              record by default. It is hash-linked and verifiable; whether
              that meets your jurisdiction&apos;s evidentiary bar is a legal
              question your counsel answers, not a marketing one.
            </span>
          </li>
        </ul>

        <hr className="my-12 border-zinc-900" />

        <div className="rounded-2xl border border-emerald-700/30 bg-emerald-500/5 p-7">
          <p className="font-mono text-xs uppercase tracking-widest text-emerald-400">
            for compliance buyers
          </p>
          <h2 className="mt-2 text-2xl font-bold tracking-tight">
            NIST AI RMF crosswalk
          </h2>
          <p className="mt-3 leading-7 text-zinc-300">
            Vibefixing artifacts mapped to GOVERN, MAP, MEASURE, and MANAGE.
            One page, no marketing, no promises beyond what the artifact
            actually contains. Built for the questionnaire response your
            security team has to fill in.
          </p>
          <div className="mt-5 flex flex-wrap gap-3">
            <Link
              href="/enterprise/nist-rmf"
              className="rounded-xl border border-emerald-700/40 bg-emerald-500/10 px-5 py-2.5 text-sm font-semibold text-emerald-200 hover:bg-emerald-500/20"
            >
              open the crosswalk →
            </Link>
            <a
              href="mailto:ariel@vibefixing.me?subject=Enterprise%20-%20Audit%20requirements"
              className="rounded-xl border border-zinc-800 bg-zinc-900/60 px-5 py-2.5 text-sm font-semibold text-zinc-200 hover:border-emerald-700/50 hover:bg-zinc-900"
            >
              email sales
            </a>
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
            <Link href="/benchmark" className="hover:text-zinc-300">/benchmark</Link>
            <Link href="/scan" className="hover:text-zinc-300">/scan</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}

function ArtifactCard({
  chip,
  title,
  body,
}: {
  chip: string;
  title: string;
  body: string;
}) {
  return (
    <div className="hover-glow flex h-full flex-col rounded-2xl border border-zinc-800 bg-zinc-950/60 p-6">
      <p className="font-mono text-xs uppercase tracking-widest text-emerald-400">
        {chip}
      </p>
      <h3 className="mt-3 text-lg font-semibold text-zinc-100">{title}</h3>
      <p className="mt-3 flex-1 text-sm leading-7 text-zinc-400">{body}</p>
    </div>
  );
}

function SeverityChip({ level }: { level: "info" | "warn" | "critical" }) {
  const palette = {
    info: "border-zinc-700/60 bg-zinc-500/10 text-zinc-300",
    warn: "border-amber-700/40 bg-amber-500/10 text-amber-300",
    critical: "border-rose-700/40 bg-rose-500/10 text-rose-300",
  }[level];
  return (
    <span
      className={`rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest ${palette}`}
    >
      {level}
    </span>
  );
}
