import Link from "next/link";
import { getSession, canAccess } from "@/lib/session";
import LogoutButton from "./LogoutButton";

const NAV = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/review", label: "Review queue" },
  { href: "/threats", label: "Threats" },
  { href: "/policies", label: "Policies" },
  { href: "/integrations", label: "Integrations" },
] as const;

export default async function OpsLayout({ children }: { children: React.ReactNode }) {
  const session = await getSession();
  // In dev (no session) we still render ops chrome so the UI is usable without login.
  const role = session?.user.role ?? "admin";

  return (
    <div className="ops-shell">
      <header className="ops-header">
        <div className="brand">
          <strong>Agentic Internal Controls</strong>
          <span className="env">ops · {role}</span>
        </div>
        <nav>
          {NAV.filter((l) => canAccess(role, l.href)).map((l) => (
            <Link key={l.href} href={l.href}>{l.label}</Link>
          ))}
          <Link href="/">← Site</Link>
          {session && (
            <span className="muted" style={{ marginLeft: 12, fontSize: 13 }}>
              {session.user.email}
            </span>
          )}
          {session && <LogoutButton />}
        </nav>
      </header>
      <main className="ops-main">{children}</main>
    </div>
  );
}
