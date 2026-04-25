import type { Metadata } from "next";
import Link from "next/link";

const TITLE = "Field notes — Vibefixing";
const DESCRIPTION =
  "Real combos we've found in real AI agents. What the LLM can do, why it matters, and the gate that stops it.";
const URL = "https://www.vibefixing.me/blog";

export const metadata: Metadata = {
  title: TITLE,
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

type Post = {
  slug: string;
  date: string;
  badge: { label: string; tone: "danger" | "warn" };
  title: string;
  dek: string;
};

const POSTS: Post[] = [
  {
    slug: "voice-phishing-langchain-agent",
    date: "April 25, 2026",
    badge: { label: "combo · voice-clone + outbound-call", tone: "danger" },
    title:
      "The vishing recipe hiding in your LangChain agent: ElevenLabs + Twilio + one prompt injection",
    dek: "We scanned a real parenting assistant. Three innocent features — TTS, outbound calls, an ungated LLM — compose into a working voice-phishing weapon under one calendar-event injection. The exploit, the code, and the gate.",
  },
];

export default function BlogIndex() {
  return (
    <div className="min-h-screen bg-black text-zinc-100 selection:bg-emerald-500/30">
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

      <section className="mx-auto max-w-3xl px-6 py-16">
        <Link
          href="/"
          className="font-mono text-xs text-zinc-500 hover:text-zinc-300"
        >
          &larr; back to vibefixing
        </Link>
        <h1 className="mt-8 text-4xl font-bold leading-[1.1] tracking-tight sm:text-5xl">
          Field notes
        </h1>
        <p className="mt-6 max-w-2xl text-lg leading-8 text-zinc-400">
          Real combos we&apos;ve found in real AI agents. What the LLM can do, why
          it matters, and the gate that stops it.
        </p>

        <ul className="mt-12 space-y-6">
          {POSTS.map((post) => (
            <li key={post.slug}>
              <Link
                href={`/blog/${post.slug}`}
                className="group block overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950 p-6 transition-colors hover:border-emerald-700/50 md:p-8"
              >
                <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
                  <span
                    className={
                      post.badge.tone === "danger"
                        ? "rounded-full border border-rose-700/40 bg-rose-500/10 px-2.5 py-0.5 text-rose-300"
                        : "rounded-full border border-amber-700/40 bg-amber-500/10 px-2.5 py-0.5 text-amber-300"
                    }
                  >
                    {post.badge.label}
                  </span>
                  <span className="text-zinc-500">{post.date}</span>
                </div>
                <h2 className="mt-4 text-xl font-bold leading-snug tracking-tight text-zinc-100 group-hover:text-emerald-300 sm:text-2xl">
                  {post.title}
                </h2>
                <p className="mt-3 leading-7 text-zinc-400">{post.dek}</p>
                <span className="mt-5 inline-flex items-center gap-1 font-mono text-sm text-emerald-400 group-hover:text-emerald-300">
                  read field note &rarr;
                </span>
              </Link>
            </li>
          ))}
        </ul>
      </section>

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
