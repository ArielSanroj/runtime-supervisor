import type { Metadata } from "next";
import Link from "next/link";

const TITLE =
  "Why did the agent do that? Reconstructing a decision after the fact";
const DESCRIPTION =
  "A customer disputes a refund the agent denied three weeks ago. Without a logged decision, the answer is best guess. With one evidence event per supervised action — input fingerprint, policy version, reasons, threat signals — the answer is replay. Explainability is a logging discipline at the boundary, not a model property.";
const URL = "https://www.vibefixing.me/blog/why-did-the-agent-do-that";
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
          Field note · May 26, 2026 · explainability
        </p>
        <h1 className="mt-3 text-4xl font-bold leading-[1.1] tracking-tight sm:text-5xl">
          Why did the agent do that?
        </h1>
        <p className="mt-6 text-lg leading-8 text-zinc-400">
          A customer emails support: <em>three weeks ago your bot refused to
          refund my October order. My card was charged twice. I want to know
          why you said no.</em> Engineering opens the ticket. The application
          log shows the agent took an action. It does not show what the
          agent saw, which policy was live, or why the rule that fired
          fired. The answer to the customer&apos;s question is a best guess.
        </p>
        <p className="mt-4 text-lg leading-8 text-zinc-400">
          That is the explainability gap. It is not a property of the model.
          It is a logging discipline you applied — or didn&apos;t — at the
          boundary where the agent did something irreversible.
        </p>

        <hr className="my-10 border-zinc-900" />

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          The three things that need to live in one record
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          A decision the agent made three weeks ago is reconstructable if
          and only if you can answer three questions from a single log line:
        </p>
        <ol className="mt-5 list-decimal space-y-3 pl-6 leading-7 text-zinc-300">
          <li>
            <strong className="text-zinc-100">What did the agent see?</strong>{" "}
            The fingerprint of the input that reached the tool call. Not the
            entire payload — that often contains PII you don&apos;t want in
            an audit log forever — but enough to identify the case.
          </li>
          <li>
            <strong className="text-zinc-100">Which policy decided?</strong>{" "}
            The version of the policy file at the moment the decision was
            made. Not the current version; the historical one. A fix you
            shipped this week must not silently rewrite last month&apos;s
            history.
          </li>
          <li>
            <strong className="text-zinc-100">Why?</strong> The list of
            reasons that resolved to a denial or an approval, in
            human-readable strings, derived from the policy that ran.
          </li>
        </ol>

        <p className="mt-5 leading-7 text-zinc-300">
          Three fields. If any one is missing, the reconstruction is best
          guess.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          What the evidence event looks like
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          Each supervised action emits an evidence event the moment the
          decision is made. Below is the actual shape the supervisor writes,
          inlined from a denied refund:
        </p>
        <CodeBlock
          code={`{
  "event_id": "ev_2026-04-09T14:22:11Z_4f2a",
  "action_type": "refund",
  "input_fingerprint": "sha256:8c2e…",   // not the raw payload
  "decision": "deny",
  "risk_score": 0.82,
  "reasons": [
    "refund_velocity_24h > 3 (saw 5)",
    "customer_age_days < 30 (saw 11)",
    "amount > 500 (saw 729.00)"
  ],
  "threats": [
    { "detector_id": "refund-burst",
      "owasp_ref": "LLM06",
      "level": "warn",
      "message": "5 refunds in 24h for new account" }
  ],
  "policy_version": "refund.base@v1.4",
  "policy_ref": "packages/policies/refund.base.v1.yaml#L42-L78",
  "enforcement_mode": "enforce",
  "occurred_at": "2026-04-09T14:22:11.842Z"
}`}
        />
        <p className="mt-4 leading-7 text-zinc-300">
          Three weeks later you look this up by{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            customer_id
          </code>{" "}
          or by{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            occurred_at
          </code>
          . The reasons array tells you, in English, what the agent saw and
          what fired. The customer gets a real answer.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          Replay a past decision against today&apos;s policy
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          The customer&apos;s next question is usually <em>would it still
          deny if I tried again?</em> The supervisor exposes the same
          decision endpoint in dry-run mode, so you can re-evaluate the same
          input against the current policy without committing to anything:
        </p>
        <CodeBlock
          code={`curl -X POST https://api.vibefixing.me/v1/actions/evaluate \\
  -H 'authorization: Bearer …' \\
  -d '{
    "action_type": "refund",
    "input": { /* the original payload, retrieved by input_fingerprint */ },
    "dry_run": true
  }'

# response
{
  "decision": "review",                  # not 'deny' anymore
  "risk_score": 0.61,
  "reasons": [
    "refund_velocity_24h > 3 (saw 5)",
    # customer_age_days check removed in policy v1.6
  ],
  "policy_version": "refund.base@v1.6"
}`}
        />
        <p className="mt-4 leading-7 text-zinc-300">
          Now the engineer can answer the customer with precision: the
          policy in effect three weeks ago denied; today&apos;s policy would
          route the same case to a human reviewer. The policy diff between
          v1.4 and v1.6 is visible in source control. The ticket closes
          with a one-line explanation instead of a corporate paragraph that
          says nothing.

        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          The wrap
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          On the agent side, the discipline is one decorator at the
          chokepoint. The supervisor writes the evidence event whether the
          decision was allow, deny, or review — failures are recorded too:
        </p>
        <CodeBlock
          code={`from supervisor_guards import supervised

@supervised("refund")
def issue_refund(customer_id: str, amount: float, reason: str) -> Refund:
    return stripe.refunds.create(
        charge=resolve_charge(customer_id),
        amount=int(amount * 100),
        reason=reason,
    )`}
        />
        <p className="mt-4 leading-7 text-zinc-300">
          Every call to{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            issue_refund
          </code>{" "}
          now produces a record of what reached the supervisor and what the
          supervisor decided, before the Stripe call happens. There is no
          extra logging code in the function body. The agent code didn&apos;t
          change shape; it just became reconstructable.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          What I&apos;m not worried about
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          PII bloat in the log. The evidence event stores an{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            input_fingerprint
          </code>
          , not the raw payload. The raw input sits in the action store
          with whatever retention policy your data team already runs;
          evidence retention is configurable separately. Replay works
          because you can hand the original payload back to the dry-run
          endpoint when you need it, not because we kept a copy forever.
        </p>
        <p className="mt-4 leading-7 text-zinc-300">
          Your dashboards are also fine. The evidence chain is append-only
          and hash-linked; it sits next to the operational logs your team
          already grep. You don&apos;t move to a new logging stack. You add
          a column.
        </p>

        <hr className="my-10 border-zinc-900" />

        <div className="mt-12 rounded-2xl border border-emerald-700/30 bg-emerald-500/5 p-6">
          <p className="font-mono text-xs uppercase tracking-widest text-emerald-400">
            related
          </p>
          <h3 className="mt-2 text-xl font-bold tracking-tight">
            The explainability section of the risk hub.
          </h3>
          <p className="mt-3 leading-7 text-zinc-300">
            Same idea, framed for someone landing on the site for the first
            time: explainability isn&apos;t a model property, it&apos;s a
            logging discipline at the boundary.
          </p>
          <div className="mt-5 flex flex-wrap gap-3">
            <Link
              href="/risks#explainability"
              className="rounded-xl border border-emerald-700/40 bg-emerald-500/10 px-5 py-2.5 text-sm font-semibold text-emerald-200 hover:bg-emerald-500/20"
            >
              /risks · explainability →
            </Link>
            <Link
              href="/scan"
              className="rounded-xl bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-black hover:bg-emerald-400"
            >
              scan my repo
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
