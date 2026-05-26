import type { Metadata } from "next";
import Link from "next/link";

const TITLE =
  "How we caught our own scanner lying: 5 layers so it can't lie that way again";
const DESCRIPTION =
  "In a live demo, the scanner reported plan_tool.py:8 as an agent chokepoint. Line 8 was a comment. main.py:813 came back as RCE-equivalent. Line 813 was warnings.filterwarnings. Two real bugs, eight false positives, one rule: the supervisor has to be more reliable than the agent it watches. Here are the five layers we shipped so the scanner can't lie that way again.";
const URL = "https://www.vibefixing.me/blog/scanner-caught-itself";
const PUBLISHED = "2026-05-22";

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
          Field note · May 22, 2026 · reliability
        </p>
        <h1 className="mt-3 text-4xl font-bold leading-[1.1] tracking-tight sm:text-5xl">
          How we caught our own scanner lying
        </h1>
        <p className="mt-6 text-lg leading-8 text-zinc-400">
          A scanner that sells trust has exactly one job: when it points at a
          line and says <em>this</em>, the line has to actually say that. If it
          ever doesn&apos;t, the demo dies, the conversion dies, and the
          founder reading the report stops trusting anything else we showed
          them.
        </p>
        <p className="mt-4 text-lg leading-8 text-zinc-400">
          On April 23 our scanner reported{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            plan_tool.py:8
          </code>{" "}
          in a public Hugging Face repo as an{" "}
          <em>agent chokepoint</em>. Line 8 was a comment. The same scan
          reported{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            main.py:813
          </code>{" "}
          as RCE-equivalent shell exec. Line 813 was{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            warnings.filterwarnings(&quot;ignore&quot;, …)
          </code>
          . Two flagrant false positives sampled at random, both in the same
          live scan.
        </p>
        <p className="mt-4 text-lg leading-8 text-zinc-400">
          The scanner doesn&apos;t use an LLM. It&apos;s 100% regex + Python
          AST. So neither false positive was a hallucination in the model
          sense — but the <em>effect</em> on the visitor reading the report
          was identical: confident output, plausible framing, technically
          false. That is unacceptable for a tool whose pitch is{" "}
          <em>we catch what your tests can&apos;t</em>.
        </p>
        <p className="mt-4 text-lg leading-8 text-zinc-400">
          Here are the two real bugs, the five layers we shipped so this class
          of failure can&apos;t recur silently, and what shipped to{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            main
          </code>{" "}
          across four commits over the next 27 hours.
        </p>

        <hr className="my-10 border-zinc-900" />

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          The two bugs
        </h2>

        <h3 className="mt-8 text-xl font-bold tracking-tight text-emerald-300">
          Bug 1 · AST line numbers on decorated functions
        </h3>
        <p className="mt-3 leading-7 text-zinc-300">
          The decorator-orchestrator detector walks the Python AST and emits
          a finding at{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            node.lineno
          </code>
          . On a decorated function,{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            node.lineno
          </code>{" "}
          in CPython is the line of the{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            def
          </code>
          , not the line of the decorator above it. The author wanted the
          decorator&apos;s line, so the finding pointed somewhere upstream of
          where the actual handler symbol lived. Sometimes that landed on
          imports, sometimes on docstrings, sometimes on comments.
        </p>
        <CodeBlock
          code={`# What the scanner emitted
plan_tool.py:8  AGENT CHOKEPOINT  Controller.handle() / Dispatcher.dispatch()

# What plan_tool.py:8 actually was
8:  # In-memory storage for the current plan
`}
        />

        <h3 className="mt-8 text-xl font-bold tracking-tight text-emerald-300">
          Bug 2 · optional alternation matching method names in prose
        </h3>
        <p className="mt-3 leading-7 text-zinc-300">
          The agent-orchestrator detector used a regex with an optional
          alternation:{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            (?:def|function)?\s*(plan|execute|dispatch|handle)
          </code>
          . The{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            ?
          </code>{" "}
          on the keyword made the keyword optional, so the regex matched the
          method name anywhere it appeared — including comments, docstrings,
          and call-sites that mentioned the word in prose. Any file with the
          word <em>plan</em> or <em>execute</em> in a code comment got
          flagged as an orchestrator.
        </p>
        <CodeBlock
          code={`# What the scanner emitted
session.py:142  AGENT CHOKEPOINT  orchestrator method 'execute'

# What session.py:142 actually was
142:  # We execute the steps in order, with retry on the inner loop.
`}
        />

        <p className="mt-4 leading-7 text-zinc-300">
          Two bugs, both in the same class: <em>the scanner&apos;s claim
          about a line did not match the bytes on that line</em>. We could
          have patched the two regexes and shipped. We didn&apos;t. The
          bigger question was: how do we keep this class of bug from sneaking
          back in next time someone adds a detector?
        </p>

        <hr className="my-10 border-zinc-900" />

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          The five layers
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          Each layer catches a different failure mode. The combination makes
          a silent regression cost more than just shipping the right code in
          the first place.
        </p>

        <h3 className="mt-8 text-xl font-bold tracking-tight text-emerald-300">
          🔒 Layer 1 · adversarial trap fixtures
        </h3>
        <p className="mt-3 leading-7 text-zinc-300">
          A test fixture directory whose entire purpose is to{" "}
          <em>look like</em> trouble at the surface and{" "}
          <em>be inert</em> on inspection. Comments that say{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            # subprocess.Popen
          </code>
          . F-strings that interpolate the literal word{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            execute
          </code>
          . Docstrings that name a chokepoint we don&apos;t actually have.
          The whole detector suite has to assert <em>zero findings</em>{" "}
          across these files. Any new detector that lights up here is a
          regex-leaks-into-comments bug before it ever hits production.
        </p>
        <CodeBlock
          code={`tests/fixtures/adversarial_trap/
  no_shell_exec.py        # mentions subprocess.Popen in a docstring
  no_orchestrator.py      # 'execute' and 'plan' in comments only
  no_payment_call.py      # 'stripe.refunds.create' as a string literal
  README.md               # explains the trap to the next developer

def test_traps_emit_zero_findings():
    for path in TRAP_FIXTURES:
        findings = scan(path)
        assert findings == [], (
            f"{path} fired {len(findings)} findings — "
            "regex is leaking into comments or strings"
        )`}
        />

        <h3 className="mt-8 text-xl font-bold tracking-tight text-emerald-300">
          🔒 Layer 2 · runtime self-check
        </h3>
        <p className="mt-3 leading-7 text-zinc-300">
          The scanner walks files and emits findings. Before any finding is
          returned, the self-check re-opens the file at the reported line and
          asserts the snippet the finding claims is actually on that line. If
          it isn&apos;t, the finding is dropped and a counter ticks. This is
          the layer that would have caught both bugs above on the first scan
          of <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">ml-intern</code> — the line said{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            warnings.filterwarnings
          </code>
          , the finding said{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            subprocess.Popen
          </code>
          , the assertion would have failed, the finding never ships.
        </p>
        <CodeBlock
          code={`# packages/supervisor-discover/scanners/__init__.py

def _self_check(finding: Finding, source: str) -> bool:
    """Return True iff the reported snippet appears on the reported line."""
    lines = source.splitlines()
    if finding.line < 1 or finding.line > len(lines):
        return False
    actual = lines[finding.line - 1]
    needle = finding.snippet.strip()
    return needle in actual

def emit(detector, source, raw_findings):
    kept = []
    for f in raw_findings:
        if _self_check(f, source):
            kept.append(f)
        else:
            METRICS.dropped_by_self_check += 1
            log.warning("self_check_drop", detector=detector, line=f.line)
    return kept`}
        />
        <p className="mt-4 leading-7 text-zinc-300">
          Twenty lines. It assumes every detector emits a snippet alongside
          the line number, which we enforce at the type level. It is the
          single most important layer.
        </p>

        <h3 className="mt-8 text-xl font-bold tracking-tight text-emerald-300">
          🔒 Layer 3 · AST-first for Python
        </h3>
        <p className="mt-3 leading-7 text-zinc-300">
          Regex on raw text leaks into comments, docstrings, and f-string
          contents. The fix isn&apos;t cleverer regex — it&apos;s walking
          the AST and asserting that the match is on a real expression node,
          not a token inside a{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            Comment
          </code>{" "}
          or a{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            Constant(str)
          </code>
          . The orchestrator detector now resolves a dotted name through{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            ast.walk
          </code>{" "}
          and a helper that knows{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            Controller.handle
          </code>{" "}
          is the same symbol as{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            self.handle
          </code>{" "}
          on a method of{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            Controller
          </code>
          . It can no longer match the word in a comment.
        </p>

        <h3 className="mt-8 text-xl font-bold tracking-tight text-emerald-300">
          🔒 Layer 4 · golden-repo snapshots
        </h3>
        <p className="mt-3 leading-7 text-zinc-300">
          A handful of real-world repositories — pinned by commit SHA — are
          scanned in CI. The output is committed to{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            tests/golden_repos/
          </code>{" "}
          and diffed on every PR. If a detector change adds or removes
          findings on a golden repo, the test fails loudly. Intentional
          changes update the snapshot with a one-line command; accidental
          drift gets caught at review.
        </p>
        <CodeBlock
          code={`tests/golden_repos/
  ml-intern@a3f9c1.findings.json       # 47 findings — pinned
  fastapi-quickstart@b2e480.findings.json
  langchain-tutorial@de1109.findings.json

# Updating intentionally
$ pytest tests/golden_repos/ --update-snapshots
# Reviewer sees the diff in the PR alongside the detector change`}
        />

        <h3 className="mt-8 text-xl font-bold tracking-tight text-emerald-300">
          🔒 Layer 5 · confidence gate on the public UI
        </h3>
        <p className="mt-3 leading-7 text-zinc-300">
          The first four layers protect the scanner&apos;s correctness in
          CI. The fifth protects what an anonymous visitor sees on the
          landing. Findings carry a confidence tier — <em>high</em>,
          <em> medium</em>, <em>low</em> — derived from how many independent
          signals fired and whether the AST resolution was unambiguous. The
          public scan only renders <em>high</em> confidence priority
          findings. Medium and low sit behind a sign-in. If a future detector
          regresses to a noisier baseline, the noise stays in the dashboard,
          not on the homepage.
        </p>

        <hr className="my-10 border-zinc-900" />

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          What this means for a repo you scan today
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          A re-scan of the same Hugging Face repo went from 55 findings to 47
          — eight false positives eliminated, with the remaining 47 cross-
          checked line-by-line against the real source. Every finding the
          scanner emits now has been validated against the bytes on the
          reported line before it leaves the process. The decorator detector
          resolves through the AST. New detectors run against the trap
          fixtures the first time they&apos;re imported. Golden snapshots
          fail CI before a regression ships.
        </p>
        <p className="mt-4 leading-7 text-zinc-300">
          The supervisor we&apos;re asking you to put in front of your agent
          had to clear a bar first: it had to be more reliable than the
          agent. These five layers are how we got there, and the tests stay
          green at 94/94 on every commit to{" "}
          <code className="rounded bg-zinc-900 px-1.5 py-0.5 text-sm text-emerald-300">
            main
          </code>
          .
        </p>

        <h2 className="mt-12 text-2xl font-bold tracking-tight">
          What I&apos;m not worried about
        </h2>
        <p className="mt-4 leading-7 text-zinc-300">
          The next class of bug. There will be one — every detector has a
          blind spot until someone scans a repo that exercises it. The
          layers don&apos;t prevent the next bug; they make sure the next
          bug fails noisily in CI instead of quietly in a customer demo.
          That&apos;s the only contract a scanner can honestly offer.
        </p>

        <hr className="my-10 border-zinc-900" />

        <div className="mt-12 rounded-2xl border border-emerald-700/30 bg-emerald-500/5 p-6">
          <p className="font-mono text-xs uppercase tracking-widest text-emerald-400">
            scan your repo
          </p>
          <h3 className="mt-2 text-xl font-bold tracking-tight">
            Paste a repo URL. Every finding is line-checked.
          </h3>
          <p className="mt-3 leading-7 text-zinc-300">
            Public repos free. No login, no API key, no instrumentation.
            You get the high-confidence findings, the snippet that lives on
            the reported line, and a copy-paste wrap for each one.
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
