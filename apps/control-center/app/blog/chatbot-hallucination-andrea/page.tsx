import type { Metadata } from "next";
import Link from "next/link";

const TITLE =
  "When the chatbot invents a person: the hallucination class your scanner missed";
const DESCRIPTION =
  "A real chat session: a manager asked her CRM bot about her team. The bot confidently analyzed five people who didn't exist in her data. Three hours, 35 messages, one lost user. Here's the failure mode, the wrap pattern, and the policy that stops it.";
const URL = "https://www.vibefixing.me/blog/chatbot-hallucination-andrea";
const PUBLISHED = "2026-04-30";

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
          Field note · April 30, 2026
        </p>
        <h1 className="mt-3 text-4xl font-bold leading-[1.1] tracking-tight sm:text-5xl">
          When the chatbot invents a person
        </h1>
        <p className="mt-6 text-lg leading-8 text-zinc-400">
          A people-analytics platform we&apos;d scanned three weeks earlier got a
          report from a manager. She&apos;d been chatting with the assistant about
          her team &mdash; eight people whose answers to a behavioral instrument
          live in the platform&apos;s database. She asked about a colleague from
          a sister team who isn&apos;t in her data. The assistant confidently
          analyzed him. Then her manager. Then three more directors. None of
          them had ever filled out the instrument.
        </p>
        <p className="mt-4 text-lg leading-8 text-zinc-400">
          Three hours and 35 messages into the chat, she wrote:{" "}
          <em>&quot;then what is this tool even for?&quot;</em>
        </p>

        <hr className="my-10 border-zinc-900" />

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          The shape of the chatbot
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          Express server, Anthropic SDK, Firestore as the source of truth.
          When a manager opens chat, the system prompt injects her team&apos;s
          archetype assignments and a few aggregated metrics. The user types
          a question. The model responds. The response goes back to the
          browser as JSON. There&apos;s no agent loop, no tool dispatcher,
          no LangChain &mdash; just <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">client.messages.create</code> and a return.
        </p>
        <p className="mt-4 leading-7 text-zinc-300">
          The author had already wrapped the LLM call when we showed up.
          Their wrapper checked prompt length and tracked latency, the kind
          of guardrail our base policy emits. None of it caught this.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          What actually happened in the chat
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          Message 10, the user asks about a director on a different team.
          The model pattern-matches against the names she <em>does</em> have
          access to, picks the closest archetype, and presents the answer
          with full confidence. She corrects: <em>that&apos;s not him, the
          director from commercial</em>. The model rolls with the correction
          and gives a fresh, equally confident analysis of the new name.
          There is no data on the new name.
        </p>
        <CodeBlock
          code={`User:    "I have doubts about Garbett showing up as Flexible Adapter,
          he's always at full speed, resolutive, doesn't soften
          his delivery..."

Bot:     "Luis, although he identifies as Flexible Adapter, his
          behavior suggests he may be acting more like a 'Resolutive
          Dominant'..."

User:    "not Luis, it's Garbett, the commercial director."

Bot:     "Garbett, with his fast pace and resolutive style, fits
          the profile of a Resolutive Dominant. He probably also
          shows..."

(Garbett is not in the manager's team_members. The bot has no data
on him. It generated the analysis from the name and the framework
labels in the system prompt.)`}
        />
        <p className="mt-4 leading-7 text-zinc-300">
          By message 28 the user asked the bot to analyze five people from
          the commercial leadership group. The bot complied. Five archetype
          assignments, five rationales, all hedged with the most dangerous
          chatbot phrasing on earth: <em>&quot;Pablo could be a Strategic
          Resolver if he focuses on solving problems...&quot;</em>. Authoritative
          tone. Systematic format. The user reads it as data.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          Why prompt rules don&apos;t catch this
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          The author had a clear system prompt. It listed the team members.
          It listed their archetypes. It said, in plain Spanish, <em>only
          discuss people in this list</em>. The model ignored it under the
          gentlest social pressure. <em>Can you tell me Pablo&apos;s
          archetype?</em> &mdash; that&apos;s all it took.
        </p>
        <p className="mt-4 leading-7 text-zinc-300">
          A prompt rule is advisory. It&apos;s a request, not a gate. Models
          violate prompt rules under pressure with a frequency we already
          accept for jailbreak research; we have to accept it for routine
          conversation too. The fix has to live <em>outside</em> the model.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          The fix &mdash; gate the response, not just the call
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          Today&apos;s scanner version flags this case as a new family:
          <code className="ml-1 rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">llm-output-without-validation</code>.
          A taint detector walks the function from the LLM call to the
          response, and if no entity-validation step runs in between, it
          fires.
        </p>
        <CodeBlock
          path="src/services/claude.service.js"
          line={314}
          code={`// before — ungated, the prompt was the only contract
async function respond(userMessage, allowed) {
  const r = await client.messages.create({
    model: 'claude-haiku',
    system: \`Only discuss \${allowed.join(', ')}\`,  // advisory only
    messages: [{ role: 'user', content: userMessage }],
  });
  return r.content[0].text;
}`}
        />
        <CodeBlock
          path="src/services/claude.service.js"
          line={314}
          code={`// after — the response is checked against the allowed set
import { assert_entities_in_scope, supervised } from 'supervisor_guards';

async function respond(userMessage, allowed) {
  const r = await client.messages.create({
    model: 'claude-haiku',
    system: \`Only discuss \${allowed.join(', ')}\`,
    messages: [{ role: 'user', content: userMessage }],
  });
  const reply = r.content[0].text;

  const check = assert_entities_in_scope(reply, allowed);
  if (!check.in_scope) {
    return \`I don't have data on \${check.unknown.join(', ')}.\` +
           \` Want to invite them to the test?\`;
  }
  return reply;
}`}
        />
        <p className="mt-4 leading-7 text-zinc-300">
          The helper extracts proper-noun candidates from the model output,
          folds case + accents, and compares against the caller&apos;s
          authorized list. The supervisor policy{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">scope_guard.base.v1</code>{" "}
          turns the comparison into an audited deny &mdash; the response never
          leaves the wrapper if it mentions someone the user can&apos;t see.
        </p>
        <CodeBlock
          path="runtime-supervisor/policies/scope_guard.base.v1.yaml"
          code={`when:   set(payload['entities_mentioned']) - set(payload['allowed_entities'])
        is non-empty
action: deny
reason: out-of-scope-entity-in-llm-response

when:   allowed_entities is empty AND entities_mentioned is non-empty
action: review
reason: scope-not-passed (likely a wiring bug — surface to a human)`}
        />
        <p className="mt-4 leading-7 text-zinc-300">
          The policy ships with every <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">repo_type=chatbot-rag</code>{" "}
          scan. The caller does the source-of-truth lookup once per request
          and feeds the two lists into the policy payload. The DSL stays
          synchronous; the domain knowledge lives in the caller.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          Why this is a class, not a one-off
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          Most agents ship in 2026 don&apos;t move money. They&apos;re chatbots
          and Q&amp;A surfaces over the customer&apos;s data. The dominant
          failure mode there isn&apos;t the agent <em>doing</em> the wrong
          thing &mdash; it&apos;s the model <em>saying</em> the wrong thing.
          A name that doesn&apos;t exist. A balance that&apos;s off by a
          decimal. A status that hasn&apos;t been true in two months.
        </p>
        <p className="mt-4 leading-7 text-zinc-300">
          Our threat model used to skip that whole surface. We modeled
          actions: payment, fs-delete, db-write. We didn&apos;t model
          assertions. Andrea&apos;s incident is the receipt for that gap.
          We&apos;ve closed it: chatbot-shaped repos now get a different
          report (LLM as the lead risk, not email), a different policy
          template (<code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">scope_guard</code> ships
          alongside the action policies), and a different stub in{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">stubs/py/chatbot_scope_guard_example.stub.py</code>.
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          The dashboard nudge that closes the loop
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          The author had the wrapper installed in shadow mode for six days
          when this happened. Six days of <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">would_block_in_shadow</code> data the
          dashboard never surfaced. The card we just added reads the same
          telemetry endpoint and tells the operator one of four things:
          keep soaking, tune your policies, flip to enforce, or you have
          a wiring gap. No interpretation of raw numbers required.
        </p>

        <hr className="my-12 border-zinc-900" />

        <div className="rounded-xl border border-emerald-700/40 bg-emerald-500/5 p-6">
          <p className="text-sm uppercase tracking-widest text-emerald-400">Try it</p>
          <p className="mt-3 text-lg font-semibold text-zinc-100">
            Scan your chatbot. Get the scope-guard policy.
          </p>
          <p className="mt-2 leading-7 text-zinc-300">
            Free public scan. If your repo classifies as{" "}
            <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">chatbot-rag</code>,{" "}
            the output ships with{" "}
            <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">policies/scope_guard.base.v1.yaml</code>{" "}
            and the wrap example. Drop the helper between your LLM call
            and the response, install the policy, deploy in shadow.
          </p>
          <div className="mt-4 flex flex-wrap items-center gap-3">
            <Link
              href="/scan"
              className="rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-black hover:bg-emerald-400"
            >
              scan your repo →
            </Link>
            <Link
              href="https://github.com/ArielSanroj/runtime-supervisor"
              className="font-mono text-sm text-zinc-400 hover:text-zinc-200"
            >
              github →
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
            <Link href="/scan" className="hover:text-zinc-300">/scan</Link>
            <Link
              href="https://github.com/ArielSanroj/runtime-supervisor"
              className="hover:text-zinc-300"
            >
              /github
            </Link>
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
