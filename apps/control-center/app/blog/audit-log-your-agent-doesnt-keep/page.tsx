import type { Metadata } from "next";
import Link from "next/link";

const TITLE =
  "The audit log your agent doesn't keep";
const DESCRIPTION =
  "Three months in, a regulator asks: show me every refund the agent issued in March. The application logs exist. The decision logs don't. Reconstruction is best-effort and the gap is the finding. Here's the evidence event your agent should be writing, the hash chain that keeps it honest, and the dry-run replay that closes the question.";
const URL = "https://www.vibefixing.me/blog/audit-log-your-agent-doesnt-keep";
const PUBLISHED = "2026-05-26";

export const metadata: Metadata = {
  title: `${TITLE} — Vibefixing`,
  description: DESCRIPTION,
  alternates: { canonical: URL },
  openGraph: {
    title: TITLE,
    description: DESCRIPTION,
    url: URL,
    type: "article",
    publishedTime: PUBLISHED,
    siteName: "Vibefixing",
  },
  twitter: {
    card: "summary_large_image",
    title: TITLE,
    description: DESCRIPTION,
  },
};

const articleSchema = {
  "@context": "https://schema.org",
  "@type": "TechArticle",
  headline: TITLE,
  description: DESCRIPTION,
  datePublished: PUBLISHED,
  dateModified: PUBLISHED,
  author: { "@type": "Organization", name: "Vibefixing" },
  publisher: {
    "@type": "Organization",
    name: "Vibefixing",
    url: "https://www.vibefixing.me",
  },
  mainEntityOfPage: { "@type": "WebPage", "@id": URL },
};

const breadcrumbSchema = {
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  itemListElement: [
    { "@type": "ListItem", position: 1, name: "Home", item: "https://www.vibefixing.me" },
    { "@type": "ListItem", position: 2, name: "Field notes", item: "https://www.vibefixing.me/blog" },
    { "@type": "ListItem", position: 3, name: TITLE, item: URL },
  ],
};

export default function Post() {
  return (
    <div className="min-h-screen bg-black text-zinc-100 selection:bg-emerald-500/30">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(articleSchema) }}
      />
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbSchema) }}
      />

      <header className="sticky top-0 z-10 border-b border-zinc-800 bg-black/80 backdrop-blur">
        <div className="mx-auto flex max-w-3xl items-center justify-between px-6 py-4">
          <Link href="/" className="flex items-baseline gap-2 font-mono text-sm">
            <span className="text-emerald-400">$</span>
            <span className="font-semibold text-zinc-100">vibefixing</span>
            <span className="text-xs text-zinc-500">// blog</span>
          </Link>
          <Link
            href="/scan"
            className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-black hover:bg-emerald-400"
          >
            scan your repo
          </Link>
        </div>
      </header>

      <article className="mx-auto max-w-3xl px-6 py-16">
        <Link href="/blog" className="font-mono text-xs text-zinc-500 hover:text-zinc-300">
          ← all field notes
        </Link>

        <p className="mt-8 font-mono text-xs uppercase tracking-widest text-zinc-500">
          Field note · May 26, 2026 · compliance
        </p>
        <h1 className="mt-3 text-4xl font-bold leading-[1.1] tracking-tight sm:text-5xl">
          The audit log your agent doesn&apos;t keep
        </h1>
        <p className="mt-6 text-lg leading-8 text-zinc-400">
          Three months into shipping the agent, the company gets the
          email every finance team eventually gets: <em>please share, for
          March of this year, every refund your AI agent issued — the
          customer, the amount, the reason, and the policy that
          authorized it.</em>
        </p>
        <p className="mt-4 text-lg leading-8 text-zinc-400">
          Application logs exist. Stripe records exist. What doesn&apos;t
          exist is a single record per agent decision saying <em>what
          fired and why</em>. The reconstruction takes a week, the
          answer is best-effort, and the next conversation with the
          regulator starts with apologies. The gap is the finding.
        </p>

        <hr className="my-10 border-zinc-900" />

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          What auditors actually ask for
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          A reviewer doesn&apos;t ask for &quot;explainable AI&quot;.
          They ask three questions and they want a CSV at the end of each:
        </p>
        <ol className="mt-5 list-decimal space-y-3 pl-6 leading-7 text-zinc-300">
          <li>
            <strong className="text-zinc-100">Show me every time the
            agent did this.</strong> A filterable record by action type,
            by date range, by customer or transaction id.
          </li>
          <li>
            <strong className="text-zinc-100">Show me which policy was
            in effect at the time.</strong> Not the current policy — the
            policy version stamped on the decision when it was made.
          </li>
          <li>
            <strong className="text-zinc-100">Show me that this log
            wasn&apos;t edited after the fact.</strong> A chain that
            breaks visibly if a row was modified.
          </li>
        </ol>
        <p className="mt-5 leading-7 text-zinc-300">
          Three primitives. If the agent doesn&apos;t emit them at the
          moment of the decision, you build them later from logs that
          weren&apos;t designed for the question.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          The evidence event, written at decision time
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          Every supervised action emits one record. The fields that
          matter for the regulator are{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            policy_version
          </code>
          ,{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            reasons
          </code>
          , and the link to the prior event:
        </p>
        <CodeBlock
          code={`{
  "event_id": "ev_2026-03-18T09:14:02Z_b1f9",
  "prev_event_hash": "sha256:7d…ae",          // hash chain
  "self_hash":       "sha256:91…02",          // verifiable
  "action_type": "refund",
  "actor": { "agent_id": "billing-agent-v3", "tenant_id": "t_842" },
  "input_fingerprint": "sha256:c8…44",        // not the raw payload
  "decision": "allow",
  "risk_score": 0.22,
  "reasons": [
    "refund_velocity_24h <= 3",
    "customer_age_days >= 30",
    "amount <= 500"
  ],
  "policy_version": "refund.base@v1.4",
  "policy_ref": "packages/policies/refund.base.v1.yaml#L42-L78",
  "enforcement_mode": "enforce",
  "occurred_at": "2026-03-18T09:14:02.314Z"
}`}
        />
        <p className="mt-4 leading-7 text-zinc-300">
          Three months later, the March CSV is one filter on{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            occurred_at
          </code>
          {" "}and{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            action_type
          </code>
          {" "}away. The policy column maps each row to the historical
          YAML file under{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            packages/policies/
          </code>{" "}
          at the version that fired. The hash chain is verifiable; a row
          edited later breaks the next read.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          The hash chain (why this isn&apos;t just append-only)
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          Append-only is necessary and not sufficient. A reviewer&apos;s
          standard question is <em>how do I know nobody quietly edited
          row 17 in row 23&apos;s favor?</em> Each evidence event stores
          a hash of the previous event alongside a hash of its own
          contents. Verification is a linear scan: at row N, recompute
          the hash of row N-1; if it doesn&apos;t match the stored
          pointer, the chain broke somewhere in between, and the
          mismatch tells you where.
        </p>
        <CodeBlock
          code={`# python check
def verify_chain(events: list[Event]) -> int | None:
    prev = None
    for i, ev in enumerate(events):
        if prev is not None and ev.prev_event_hash != prev.self_hash:
            return i  # first broken link
        if ev.self_hash != sha256(canonical_bytes(ev)):
            return i  # row itself was modified
        prev = ev
    return None  # chain intact`}
        />
        <p className="mt-4 leading-7 text-zinc-300">
          Vibefixing&apos;s evidence endpoint exposes the same
          verification. When the answer is <em>the chain is intact at
          row 47,294</em>, the reviewer accepts the rest of the
          conversation differently.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          Replay: would today&apos;s policy decide the same?
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          The next regulator question is usually <em>if you ran your
          policy on this case today, what would happen?</em> The
          supervisor exposes the same decision endpoint in dry-run mode,
          so any past decision can be re-evaluated against the current
          policy without committing to anything:
        </p>
        <CodeBlock
          code={`curl -X POST https://api.vibefixing.me/v1/actions/evaluate \\
  -H 'authorization: Bearer …' \\
  -d '{
    "action_type": "refund",
    "input": { /* original payload, retrieved by input_fingerprint */ },
    "dry_run": true
  }'

# response
{
  "decision": "allow",
  "risk_score": 0.22,
  "reasons": [
    "refund_velocity_24h <= 3",
    "customer_age_days >= 30",
    "amount <= 500"
  ],
  "policy_version": "refund.base@v1.7"
}`}
        />
        <p className="mt-4 leading-7 text-zinc-300">
          The dry-run isn&apos;t a do-over; the original decision still
          stands. It&apos;s the document the reviewer needs to see that
          you can answer the counterfactual the same way every time.

        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          What this is not
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          Not a SOC 2 report. Not a NIST AI RMF certification. We map
          the artifacts to those frameworks in the{" "}
          <Link
            href="/enterprise/nist-rmf"
            className="text-emerald-300 underline-offset-4 hover:underline"
          >
            crosswalk
          </Link>
          , but the report your auditor stamps still comes from your
          compliance team. The evidence chain gives them the
          underlying data; the binder is theirs to write.
        </p>
        <p className="mt-4 leading-7 text-zinc-300">
          Not a guarantee that the log is court-admissible by default.
          Hash chains are verifiable; whether your jurisdiction treats
          that as evidence is a question for your counsel, not for the
          supervisor.
        </p>

        <hr className="my-10 border-zinc-900" />

        <div className="mt-12 rounded-2xl border border-emerald-700/30 bg-emerald-500/5 p-6">
          <p className="font-mono text-xs uppercase tracking-widest text-emerald-400">
            related
          </p>
          <h3 className="mt-2 text-xl font-bold tracking-tight">
            The compliance overview and the NIST AI RMF crosswalk.
          </h3>
          <p className="mt-3 leading-7 text-zinc-300">
            The compliance page collects the three artifacts a reviewer
            actually asks for. The crosswalk maps each one to a NIST AI
            RMF sub-category so your security questionnaire response
            doesn&apos;t start from a blank page.
          </p>
          <div className="mt-5 flex flex-wrap gap-3">
            <Link
              href="/compliance"
              className="rounded-xl border border-emerald-700/40 bg-emerald-500/10 px-5 py-2.5 text-sm font-semibold text-emerald-200 hover:bg-emerald-500/20"
            >
              /compliance · audit trail
            </Link>
            <Link
              href="/enterprise/nist-rmf"
              className="rounded-xl border border-zinc-800 bg-zinc-900/60 px-5 py-2.5 text-sm font-semibold text-zinc-200 hover:border-emerald-700/50 hover:bg-zinc-900"
            >
              NIST AI RMF crosswalk
            </Link>
          </div>
        </div>
      </article>

      <footer className="border-t border-zinc-900 bg-black">
        <div className="mx-auto flex max-w-3xl flex-wrap items-center justify-between gap-4 px-6 py-8 text-sm text-zinc-600">
          <div className="font-mono">
            <span className="text-emerald-400">$</span>{" "}
            <span className="text-zinc-400">vibefixing</span>{" "}
            <span className="text-zinc-700">guardrails for agents that ship</span>
          </div>
          <div className="flex gap-6 font-mono">
            <Link href="/" className="hover:text-zinc-300">/home</Link>
            <Link href="/blog" className="hover:text-zinc-300">/blog</Link>
            <Link href="/scan" className="hover:text-zinc-300">/scan</Link>
          </div>
        </div>
      </footer>
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
