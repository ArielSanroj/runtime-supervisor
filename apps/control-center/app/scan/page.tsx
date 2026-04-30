import Link from "next/link";
import ScanForm from "./ScanForm";

export const dynamic = "force-dynamic";

export default function ScanPage() {
  return (
    <div className="min-h-screen bg-black text-zinc-100 selection:bg-emerald-500/30">
      <header className="sticky top-0 z-10 border-b border-zinc-800 bg-black/70 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
          <Link href="/" className="flex items-baseline gap-2 font-mono text-sm">
            <span className="text-emerald-400">$</span>
            <span className="font-semibold text-zinc-100">vibefixing</span>
            <span className="text-xs text-zinc-500">// scan</span>
          </Link>
          <div className="flex items-center gap-3 text-sm">
            <Link
              href="/"
              className="font-mono text-xs text-zinc-500 hover:text-zinc-300"
            >
              ← home
            </Link>
            <Link href="/dashboard" className="font-mono text-xs text-zinc-500 hover:text-zinc-300">
              /dashboard
            </Link>
          </div>
        </div>
      </header>

      <section className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(52,211,153,0.10),transparent_60%)]" />
        <div className="relative mx-auto grid max-w-5xl gap-10 px-6 pt-20 pb-10 lg:grid-cols-[1fr_320px]">
          <div className="animate-fade-in">
            <div className="inline-flex items-center gap-2 rounded-full border border-emerald-700/40 bg-emerald-500/10 px-3.5 py-1.5 text-xs font-mono text-emerald-300">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-float" />
              free public repo scan
            </div>
            <h1 className="mt-7 text-4xl font-bold leading-[1.05] tracking-tight sm:text-5xl">
              Paste a repo URL.
              <br />
              <span className="bg-gradient-to-r from-emerald-300 via-emerald-400 to-emerald-200 bg-clip-text text-transparent">
                See the actions your agent should not run unchecked.
              </span>
            </h1>
            <p className="mt-5 max-w-2xl text-lg leading-8 text-zinc-400">
              Shallow clone, run the scanners, and get a risk-ranked preview in seconds.
              Public repos are free. Then connect the GitHub App and get a comment
              on every PR with the new ungated call-sites — diffed against your
              last scan. Builder unlocks private repos, history, and CI integration.
            </p>
          </div>
          <aside className="hover-glow rounded-2xl border border-emerald-900/50 bg-emerald-500/5 p-6">
            <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">Builder unlock</div>
            <div className="mt-3 text-3xl font-bold">$29/mo</div>
            <ul className="mt-4 space-y-2 text-sm text-zinc-400">
              <li className="flex gap-2"><span className="text-emerald-400">✓</span><span>Full <code className="text-zinc-200">runtime-supervisor/</code> export</span></li>
              <li className="flex gap-2"><span className="text-emerald-400">✓</span><span>Private GitHub repo scans</span></li>
              <li className="flex gap-2"><span className="text-emerald-400">✓</span><span>Scan history and diffs</span></li>
              <li className="flex gap-2"><span className="text-emerald-400">✓</span><span>CI and PR comments</span></li>
            </ul>
            <p className="mt-4 text-xs leading-5 text-zinc-500">
              Pro ($99/workspace/mo) adds team workflows, org controls, SSO, and shared review queues.
            </p>
          </aside>
        </div>
      </section>

      <section className="mx-auto max-w-4xl px-6 pb-24">
        <div className="hover-glow rounded-2xl border border-zinc-800 bg-zinc-950/60 p-6 sm:p-8">
          <ScanForm />
        </div>
      </section>
    </div>
  );
}
