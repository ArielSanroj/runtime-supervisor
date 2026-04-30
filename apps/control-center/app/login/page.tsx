import Link from "next/link";
import LoginForm from "./LoginForm";

export const dynamic = "force-dynamic";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string }>;
}) {
  const sp = await searchParams;
  const next = sp.next ?? "/dashboard";
  return (
    <div className="min-h-screen bg-black text-zinc-100 selection:bg-emerald-500/30">
      <header className="border-b border-zinc-900 bg-black/80 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
          <Link href="/" className="flex items-baseline gap-2 font-mono text-sm hover:opacity-80">
            <span className="text-emerald-400">$</span>
            <span className="font-semibold text-zinc-100">vibefixing</span>
            <span className="hidden text-xs text-zinc-500 sm:inline">// runtime-supervisor</span>
          </Link>
          <Link href="/" className="font-mono text-xs text-zinc-500 hover:text-zinc-300">
            ← back to home
          </Link>
        </div>
      </header>

      <main className="ops-shell relative overflow-hidden">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(52,211,153,0.10),transparent_55%)]" />
        <div className="relative mx-auto flex min-h-[calc(100vh-65px)] max-w-md items-center px-6 py-16">
          <div className="hover-glow w-full animate-fade-in rounded-2xl border border-zinc-800 bg-zinc-950/80 p-8">
            <h1 className="text-2xl font-bold tracking-tight text-zinc-100">Sign in</h1>
            <p className="mt-2 text-sm text-zinc-400">
              Sign in to manage your scans, review queue, and policies.
            </p>
            <div className="mt-6">
              <LoginForm next={next} />
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
