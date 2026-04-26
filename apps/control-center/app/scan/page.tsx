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

      <section className="mx-auto grid max-w-5xl gap-10 px-6 pt-20 pb-10 lg:grid-cols-[1fr_320px]">
        <div>
        <div className="inline-flex items-center gap-2 rounded-full border border-zinc-800 bg-zinc-900/50 px-3 py-1 text-xs font-mono text-zinc-400">
          <span className="text-pink-400">#</span> free public repo scan
        </div>
        <h1 className="mt-6 text-4xl font-bold leading-[1.1] tracking-tight sm:text-5xl">
          Paste a repo URL.
          <br />
          <span className="text-emerald-400">See the actions your agent should not run unchecked.</span>
        </h1>
        <p className="mt-5 max-w-2xl text-lg text-zinc-400">
          Shallow clone, run the scanners, and get a risk-ranked preview in seconds.
          Public repos are free. Builder unlocks private repos and full exports. Pro adds team workflows and org controls.
        </p>
        </div>
        <aside className="rounded-xl border border-emerald-900/50 bg-emerald-500/5 p-5">
          <div className="font-mono text-xs uppercase tracking-widest text-emerald-400">Builder unlock</div>
          <div className="mt-3 text-3xl font-bold">$29/mo</div>
          <ul className="mt-4 space-y-2 text-sm text-zinc-400">
            <li>Full <code className="text-zinc-200">runtime-supervisor/</code> export</li>
            <li>Private GitHub repo scans</li>
            <li>Scan history and diffs</li>
            <li>CI and PR comments</li>
          </ul>
          <p className="mt-4 text-xs leading-5 text-zinc-500">
            Pro ($99/workspace/mo) adds team workflows, org controls, SSO, and shared review queues.
          </p>
        </aside>
      </section>

      <section className="mx-auto max-w-4xl px-6 pb-24">
        <ScanForm />
      </section>
    </div>
  );
}
