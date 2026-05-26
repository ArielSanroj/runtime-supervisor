import type { Metadata } from "next";
import Link from "next/link";

const TITLE =
  "Your agent sent 621 emails overnight: the four wraps that would have stopped it";
const DESCRIPTION =
  "A real Series-A SaaS. Cron raced itself three ways. An override pointed at a deactivated template. A cancelled batch came back at 03:14. We didn't catch this with a pen-test report — we caught it because the four chokepoints were sitting in plain Python. Here's the timeline, the four wraps, and what shadow mode would have shown the founder at 00:01.";
const URL = "https://www.vibefixing.me/blog/621-emails-overnight";
const PUBLISHED = "2026-05-19";

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
          Field note · May 19, 2026
        </p>
        <h1 className="mt-3 text-4xl font-bold leading-[1.1] tracking-tight sm:text-5xl">
          Your agent sent 621 emails before you got out of bed
        </h1>
        <p className="mt-6 text-lg leading-8 text-zinc-400">
          A founder we know runs a Series-A SaaS with two agents in production
          &mdash; an SDR agent and a marketing agent. On the 16th she cancelled
          79 outreach drafts at 23:47 because something in the copy looked off.
          She went to sleep.
        </p>
        <p className="mt-4 text-lg leading-8 text-zinc-400">
          By the time she opened Slack the next morning, her agents had sent
          <strong className="text-zinc-100"> 621 emails</strong> to customers.
          The 79 she cancelled were back, plus 92 new ones the marketing agent
          had decided to add overnight. The SDR cron had fired three times
          between 00:00 and 13:00 because two schedulers and a GitHub Action
          all owned the same handler. And every email used a template that
          had been deprecated two weeks earlier &mdash; the rule resolver was
          reading from an override row that pointed at a deactivated row.
        </p>
        <p className="mt-4 text-lg leading-8 text-zinc-400">
          Four independent failures, one morning. None of them were exotic.
          All four would have been wraps the scanner emits today.
        </p>

        <hr className="my-10 border-zinc-900" />

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          The timeline
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          Reconstructed from her DB and her workers&apos; logs. UTC throughout.
        </p>
        <CodeBlock
          code={`23:47  user cancels 79 SDR drafts in the dashboard.
       cancel_pending_actions() flips status='pending' → 'cancelled'.

00:00  Celery beat fires sdr_scheduler.run_sdr_batch(). 150 new actions
       planned. SDR agent reads from agent_rule_overrides, resolves
       SDR-01..05 to template sdr_intro_custom_v1.
       (sdr_intro_custom_v1 was set is_active=false on May 3 when
       sdr_intro_gap_v3 replaced it. The override row was never updated.)
       150 emails sent.

03:14  marketing_agent.replan() wakes. It reads pending_actions without
       joining cancelled_intents. The 79 cancelled rows look fresh again.
       It also surfaces 92 new prospects from a Supabase view that ran
       overnight. 171 emails sent.

12:00  GitHub Actions fires the same run_sdr_batch via a cron: '0 12 * * *'
       in .github/workflows/sdr.yml. 150 more emails sent.

13:00  The prod crontab (forgotten from a 2024 migration) fires the same
       handler. 150 more emails sent.

       Total: 150 + 171 + 150 + 150 = 621 emails to real customers.`}
        />

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          Why none of this looked dangerous in code review
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          Each of the four failures is the kind of thing that passes review.
          The cron entries were each correct in isolation. The override table
          had been a tactical workaround for a copy A/B test six months earlier.
          The marketing agent&apos;s <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">replan()</code> was a feature, not a bug
          &mdash; it&apos;s how it adapts to new prospects appearing in the funnel.
          The rule resolver was three lines of SQLAlchemy.
        </p>
        <p className="mt-4 leading-7 text-zinc-300">
          The failure is the <em>combination</em>, and combinations don&apos;t
          live in any one file. They live at the chokepoints where the agent
          actually does something irreversible &mdash; the SMTP send, the cron
          dispatch, the template lookup, the batch insert. That&apos;s where the
          gate goes.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          The four wraps (this is the whole thing)
        </h2>

        <h3 className="mt-8 text-xl font-bold tracking-tight text-emerald-300">
          🔒 Wrap 1 · gate the email send, not the planner
        </h3>
        <p className="mt-3 leading-7 text-zinc-300">
          Two functions reach <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">resend.emails.send</code>: the cron path and the
          manual <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">run_agent()</code> path. Putting the gate on the planner means the
          manual path bypasses it. The gate belongs at the side effect.
        </p>
        <CodeBlock
          code={`from supervisor_guards import supervised

@supervised('email_send')
def send_outreach(recipient: str, body: str) -> None:
    resend.emails.send(...)`}
        />

        <h3 className="mt-8 text-xl font-bold tracking-tight text-emerald-300">
          🔒 Wrap 2 · dedup the cron at the chokepoint
        </h3>
        <p className="mt-3 leading-7 text-zinc-300">
          The fix isn&apos;t to delete the GitHub Action or the prod crontab
          &mdash; both were intentional, just both unaware of each other. The
          fix is one idempotency key keyed on the scheduled minute, so the
          second and third caller in the same minute are no-ops.
        </p>
        <CodeBlock
          code={`@supervised('cron_dispatch',
            idempotency_key=lambda ctx: f"sdr:{ctx.scheduled_at:%Y-%m-%dT%H:%M}")
def run_sdr_batch() -> None:
    ...`}
        />

        <h3 className="mt-8 text-xl font-bold tracking-tight text-emerald-300">
          🔒 Wrap 3 · refuse to resolve an override that points at a deactivated row
        </h3>
        <p className="mt-3 leading-7 text-zinc-300">
          Polite SQL is the bug here: the override join didn&apos;t carry an
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">is_active=true</code> filter, so the row outlived the thing it pointed at.
          Add a policy that blocks resolution when the destination is dead.
        </p>
        <CodeBlock
          code={`@supervised('rule_resolution')
def resolve(rule_id: str) -> Template:
    template = (
        db.query(Template)
          .join(RuleOverride, RuleOverride.template_id == Template.id)
          .filter(RuleOverride.rule_id == rule_id)
          .filter(Template.is_active == True)  # the missing line
          .one_or_none()
    )
    if template is None:
        raise RuleResolutionError('override points at deactivated template')
    return template`}
        />

        <h3 className="mt-8 text-xl font-bold tracking-tight text-emerald-300">
          🔒 Wrap 4 · refuse to re-send a batch that references a cancelled intent
        </h3>
        <p className="mt-3 leading-7 text-zinc-300">
          The marketing agent isn&apos;t wrong to replan. It&apos;s wrong to
          replan onto a recipient list a human just rejected. The policy
          consults a <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">cancelled_intents</code> ledger written
          by <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">cancel_pending_actions</code>:
        </p>
        <CodeBlock
          code={`# packages/policies/bulk_send_freeze.base.v1.yaml
applies_to: action_type=email_send, payload.batch_size >= 50
require_evidence:
  - field: batch.parent_intent_id
    must_not_be_in: cancelled_intents_last_24h
on_violation: block`}
        />

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          What shadow mode would have shown her at 00:01
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          With all four wraps installed and{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">SUPERVISOR_ENFORCEMENT_MODE=shadow</code>{" "}
          set, nothing is blocked &mdash; but every would-block writes a decision
          to the supervisor&apos;s evidence chain and surfaces it in the morning
          digest. Here&apos;s the email she would have read while coffee brewed:
        </p>
        <CodeBlock
          code={`Subject: 3 actions would have been blocked overnight — vibefixing

Hi,

Between 23:47 and 13:00 UTC, your supervisors saw 4 things they would
have blocked in enforce mode.

  1. RULE_TARGET_INACTIVE × 450 calls
     resolve('SDR-01') returned a template marked is_active=false.
     First seen: 00:00:01 UTC. Source: sdr_scheduler.run_sdr_batch.
     Open replay →

  2. DUPLICATE_DISPATCH × 2 calls
     Cron handler 'sdr' fired at the same scheduled minute by two
     different schedulers (Celery beat + GitHub Actions, then again
     by /etc/crontab).
     Open replay →

  3. BULK_SEND_REFERENCES_CANCELLED × 171 calls
     marketing_agent.replan re-issued a batch whose parent intent
     was cancelled at 23:47 by you.
     Open replay →

Flip to enforce when you trust shadow → vibefixing.me/dashboard`}
        />
        <p className="mt-4 leading-7 text-zinc-300">
          That&apos;s the difference between finding this at 09:00 in her inbox
          versus finding it at 14:30 when a customer replies asking who Ariel
          is and why she&apos;s getting cold outreach about a product she already
          uses.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          What I&apos;m not worried about
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          Her stack is fine. The agents are fine. The schedulers are fine. Nothing
          in this story requires rewriting any of them &mdash; just four
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">@supervised</code> decorators at the four chokepoints we
          already named, and a one-line env var to flip from shadow to enforce
          when the team trusts what they see. Total install: under fifteen
          minutes.
        </p>
        <p className="mt-4 leading-7 text-zinc-300">
          The wraps don&apos;t change what her agents do. They change what her
          agents <em>can&apos;t</em> do at 03:14.
        </p>

        <hr className="my-10 border-zinc-900" />

        <div className="mt-12 rounded-2xl border border-emerald-700/30 bg-emerald-500/5 p-6">
          <p className="font-mono text-xs uppercase tracking-widest text-emerald-400">
            scan your repo
          </p>
          <h3 className="mt-2 text-xl font-bold tracking-tight">
            Find your four wraps in 30 seconds.
          </h3>
          <p className="mt-3 leading-7 text-zinc-300">
            Paste a repo URL. We&apos;ll show you which call-sites reach the
            same SMTP / cron / DB chokepoints, and emit the stubs you copy in.
            Shadow mode by default. Free.
          </p>
          <Link
            href="/scan"
            className="mt-5 inline-flex rounded-xl bg-emerald-500 px-5 py-3 text-sm font-semibold text-black hover:bg-emerald-400"
          >
            scan my repo →
          </Link>
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

function CodeBlock({
  code,
  path,
  line,
}: {
  code: string;
  path?: string;
  line?: number;
}) {
  return (
    <div className="mt-5 overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950">
      {path ? (
        <div className="flex items-center gap-2 border-b border-zinc-800 bg-zinc-900/80 px-4 py-2 font-mono text-[11px] text-zinc-500">
          <span className="text-zinc-400">{path}</span>
          {line ? <span className="text-zinc-600">:{line}</span> : null}
        </div>
      ) : null}
      <pre className="overflow-auto p-5 font-mono text-[13px] leading-relaxed text-zinc-200">
        {code}
      </pre>
    </div>
  );
}
