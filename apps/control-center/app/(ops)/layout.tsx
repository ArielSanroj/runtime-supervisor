import Link from "next/link";

export default function OpsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="ops-shell">
      <header className="ops-header">
        <div className="brand">
          <strong>Agentic Internal Controls</strong>
          <span className="env">ops · phase 1</span>
        </div>
        <nav>
          <Link href="/dashboard">Dashboard</Link>
          <Link href="/review">Review queue</Link>
          <Link href="/">← Site</Link>
        </nav>
      </header>
      <main className="ops-main">{children}</main>
    </div>
  );
}
