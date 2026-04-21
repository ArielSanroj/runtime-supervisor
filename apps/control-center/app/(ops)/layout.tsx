import Link from "next/link";
import LogoutButton from "./LogoutButton";

const NAV = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/review", label: "Review" },
  { href: "/threats", label: "Threats" },
  { href: "/findings", label: "Findings" },
  { href: "/policies", label: "Policies" },
  { href: "/integrations", label: "Integrations" },
] as const;

export default function OpsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="ops-shell min-h-screen bg-black text-zinc-100">
      <header className="sticky top-0 z-10 border-b border-zinc-800 bg-black/70 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-6 px-6 py-3">
          <Link
            href="/"
            className="flex items-baseline gap-2 font-mono text-sm hover:opacity-80"
          >
            <span className="text-emerald-400">$</span>
            <span className="font-semibold text-zinc-100">vibefixing</span>
            <span className="text-xs text-zinc-500">// runtime-supervisor</span>
          </Link>
          <nav className="flex items-center gap-5 font-mono text-sm text-zinc-400">
            {NAV.map((l) => (
              <Link
                key={l.href}
                href={l.href}
                className="transition-colors hover:text-emerald-400"
              >
                {l.label}
              </Link>
            ))}
          </nav>
          <LogoutButton />
        </div>
      </header>
      <main className="ops-main">{children}</main>
    </div>
  );
}
