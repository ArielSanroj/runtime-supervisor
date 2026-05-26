import type { Metadata } from "next";
import Link from "next/link";

const TITLE =
  "Your agent just emailed the wrong customer's invoice: PII fan-out in tool calls";
const DESCRIPTION =
  "An SDR agent generated SQL with a missing tenant filter and emailed customer A's invoice to customer B. One query, one missed WHERE clause, eleven recipients. The supervisor decision belongs at the data layer, not the email layer. Here's the failure, the wrap, and the policy that stops it.";
const URL = "https://www.vibefixing.me/blog/wrong-customer-invoice";
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
          Field note · May 26, 2026 · data privacy
        </p>
        <h1 className="mt-3 text-4xl font-bold leading-[1.1] tracking-tight sm:text-5xl">
          Your agent just emailed the wrong customer&apos;s invoice
        </h1>
        <p className="mt-6 text-lg leading-8 text-zinc-400">
          A B2B SaaS we know runs a billing agent that emails monthly
          invoices. On a Tuesday morning, eleven customers received an
          invoice belonging to a different customer. Different company
          names. Different amounts. Different line items. The agent
          didn&apos;t do anything dramatic — it ran the same template it
          had been running for six months. The change was three lines
          deeper in the stack, in a query the LLM had quietly refactored.
        </p>
        <p className="mt-4 text-lg leading-8 text-zinc-400">
          The fix isn&apos;t at the email layer. By the time the agent has
          a row in hand, the privacy bug has already happened. The fix is
          one wrap at the data layer.
        </p>

        <hr className="my-10 border-zinc-900" />

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          The query the agent shipped
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          The billing agent reads outstanding invoices and emails one per
          recipient. The original query was tenant-scoped:
        </p>
        <CodeBlock
          code={`# before
def outstanding_invoices(tenant_id: str) -> list[Invoice]:
    return (
        db.query(Invoice)
          .filter(Invoice.tenant_id == tenant_id)
          .filter(Invoice.status == "outstanding")
          .all()
    )`}
        />
        <p className="mt-4 leading-7 text-zinc-300">
          Then the engineer asked Cursor to <em>add a sort by due-date and
          a limit</em>. The model refactored the function, and the new
          version came back without the{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            tenant_id
          </code>{" "}
          filter:
        </p>
        <CodeBlock
          code={`# after — what shipped
def outstanding_invoices(tenant_id: str) -> list[Invoice]:
    return (
        db.query(Invoice)
          .filter(Invoice.status == "outstanding")
          .order_by(Invoice.due_date.desc())
          .limit(50)
          .all()
    )
# tenant_id parameter still there. WHERE clause gone.`}
        />
        <p className="mt-4 leading-7 text-zinc-300">
          The function signature still demanded a{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            tenant_id
          </code>
          , so every caller still passed one — code review didn&apos;t
          flag it because the call sites looked unchanged. Tests passed
          because the seeded test DB only had one tenant. Production has
          a hundred.

        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          Why the email-layer guard wouldn&apos;t have helped
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          The instinct after an incident like this is to put a check
          right before{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            send_invoice_email
          </code>{" "}
          — <em>verify the recipient&apos;s tenant matches the invoice&apos;s
          tenant</em>. That guard is fine. It doesn&apos;t solve the
          problem.
        </p>
        <p className="mt-4 leading-7 text-zinc-300">
          By the time you&apos;re at the email step, the cross-tenant
          read has already happened. The agent has the wrong row in
          memory. Now it&apos;s in the LLM&apos;s context. Now it&apos;s
          in whatever logging service captures function arguments. Now
          it might end up in a customer-support chat transcript when a
          human asks the agent what it did this morning. The bug
          fans out.
        </p>
        <p className="mt-4 leading-7 text-zinc-300">
          The right gate sits where the data leaves the database. If a
          row crosses a tenant boundary on read, the read itself is the
          policy violation.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          The wrap
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          Vibefixing&apos;s{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            data_access
          </code>{" "}
          action type intercepts four signals: <em>dataset</em>,{" "}
          <em>columns</em>, <em>actor</em>, <em>purpose</em>. The wrap
          lets the policy refuse a read where the actor doesn&apos;t
          belong to the row&apos;s tenant.
        </p>
        <CodeBlock
          code={`from supervisor_guards import supervised
from supervisor_guards.signals import data_access

@supervised(
    "data_access",
    signals=lambda tenant_id, **_: data_access(
        dataset="invoice",
        columns=["id", "tenant_id", "amount", "recipient_email"],
        actor={"tenant_id": tenant_id, "role": "billing-agent"},
        purpose="monthly_billing_run",
    ),
)
def outstanding_invoices(tenant_id: str) -> list[Invoice]:
    rows = (
        db.query(Invoice)
          .filter(Invoice.status == "outstanding")
          .order_by(Invoice.due_date.desc())
          .limit(50)
          .all()
    )
    # the supervisor refuses the read if any row's tenant_id
    # differs from actor.tenant_id — the missing WHERE clause
    # surfaces as a denial, not as a leaked invoice.
    return rows`}
        />
        <p className="mt-4 leading-7 text-zinc-300">
          The policy file that backs the wrap is plain YAML:
        </p>
        <CodeBlock
          code={`# packages/policies/data_access.tenant_isolation.v1.yaml
applies_to: action_type=data_access, dataset=invoice
require_evidence:
  - field: rows[*].tenant_id
    must_equal: actor.tenant_id
on_violation:
  decision: deny
  reason: "cross-tenant read attempted by billing-agent"
  emit_threat: { detector_id: "cross-tenant-read", level: "critical" }`}
        />
        <p className="mt-4 leading-7 text-zinc-300">
          When the LLM ships a query that loses the{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            tenant_id
          </code>{" "}
          filter, the policy denies the read. The agent gets back an
          empty list and a decision the operations team can replay. The
          eleven customers never see the wrong invoice.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          What shadow mode would have shown the team the morning before
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          With the wrap installed and{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            SUPERVISOR_ENFORCEMENT_MODE=shadow
          </code>{" "}
          set, nothing is blocked — but every would-block writes a
          decision to the supervisor&apos;s evidence chain. The morning
          digest the day before the incident:
        </p>
        <CodeBlock
          code={`Subject: 4 actions would have been blocked yesterday — vibefixing

  1. CROSS_TENANT_READ × 4 calls
     outstanding_invoices(tenant_id=t_842) returned rows for
     tenants {t_111, t_842, t_904}. The function lost its tenant
     WHERE clause in commit 1f4c2a.
     Open replay →

Flip to enforce when you trust shadow → vibefixing.me/dashboard`}
        />
        <p className="mt-4 leading-7 text-zinc-300">
          The fix is in source control. The four caught reads in shadow
          mode are the warning before the eleven uncaught reads in prod.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          What I&apos;m not worried about
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          Your DB is fine. Your ORM is fine. The wrap doesn&apos;t change
          the query, doesn&apos;t add indexes, doesn&apos;t need a
          migration. It reads what the function read, compares it to the
          actor&apos;s scope, and refuses the inconsistent case. Under
          fifteen minutes to install on the billing path, plus the
          parallel paths the scanner flags for you when you point it at
          the repo.
        </p>

        <hr className="my-10 border-zinc-900" />

        <div className="mt-12 rounded-2xl border border-emerald-700/30 bg-emerald-500/5 p-6">
          <p className="font-mono text-xs uppercase tracking-widest text-emerald-400">
            related
          </p>
          <h3 className="mt-2 text-xl font-bold tracking-tight">
            The data-privacy section of the risk hub.
          </h3>
          <p className="mt-3 leading-7 text-zinc-300">
            Same failure pattern, framed for first-time visitors and tied
            to the live{" "}
            <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
              data_access
            </code>{" "}
            action type in the registry.
          </p>
          <div className="mt-5 flex flex-wrap gap-3">
            <Link
              href="/risks#data-privacy"
              className="rounded-xl border border-emerald-700/40 bg-emerald-500/10 px-5 py-2.5 text-sm font-semibold text-emerald-200 hover:bg-emerald-500/20"
            >
              /risks · data privacy →
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
