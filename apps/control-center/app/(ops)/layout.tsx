import Link from "next/link";

const NAV = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/review", label: "Review queue" },
  { href: "/threats", label: "Threats" },
  { href: "/policies", label: "Policies" },
  { href: "/integrations", label: "Integrations" },
] as const;

export default function OpsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="ops-shell">
      <header className="ops-header">
        <nav>
          {NAV.map((l) => (
            <Link key={l.href} href={l.href}>{l.label}</Link>
          ))}
        </nav>
      </header>
      <main className="ops-main">{children}</main>
    </div>
  );
}
