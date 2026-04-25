import Link from "next/link";
import { getRepo } from "@/lib/repos";
import { buildEnglishBanner, type RepoSummary } from "@/lib/scans";
import RescanButton from "./RescanButton";

export const dynamic = "force-dynamic";

type Tab = { slug: string; label: string; comingSoon?: boolean };

const TABS: Tab[] = [
  { slug: "", label: "Overview" },
  { slug: "findings", label: "Findings" },
  { slug: "combos", label: "Combos" },
  { slug: "history", label: "History" },
  { slug: "rollout", label: "Rollout", comingSoon: true },
  { slug: "runtime", label: "Runtime", comingSoon: true },
];

export default async function RepoDetailLayout({
  params,
  children,
}: {
  params: Promise<{ repo_id: string }>;
  children: React.ReactNode;
}) {
  const { repo_id } = await params;
  const overview = await getRepo(repo_id).catch(() => null);

  if (!overview) {
    return (
      <div className="card" style={{ padding: 24, margin: 24, maxWidth: 640 }}>
        <h2 style={{ marginTop: 0 }}>Repo not found</h2>
        <p className="muted">
          No scans found for this repo_id. Run a scan to start tracking.
        </p>
        <Link href="/scan" className="button">run a scan →</Link>
      </div>
    );
  }

  const banner = overview.repo_summary
    ? buildEnglishBanner(overview.repo_summary as unknown as RepoSummary)
    : null;
  const repoPath = overview.github_url.replace(/^https?:\/\/(www\.)?github\.com\//, "");

  return (
    <div style={{ padding: 24 }}>
      <div className="row" style={{ alignItems: "flex-start", justifyContent: "space-between", gap: 16, marginBottom: 8 }}>
        <div>
          <div className="muted mono" style={{ fontSize: 12 }}>
            <Link href="/repos" style={{ color: "#71717a" }}>repos</Link> / {repoPath}
          </div>
          <h1 style={{ margin: "6px 0 4px" }}>{repoPath}</h1>
          {banner && <p className="muted" style={{ marginTop: 4 }}>Scanned <strong style={{ color: "#a7f3d0" }}>{banner}</strong>.</p>}
        </div>
        <div className="row" style={{ gap: 8 }}>
          <RescanButton githubUrl={overview.github_url} />
          <BuilderButton label="export bundle" />
          <BuilderButton label="create PR" />
        </div>
      </div>

      <div className="row" style={{ gap: 16, marginTop: 12, marginBottom: 4, flexWrap: "wrap" }}>
        <Stat label="high findings" value={overview.high_findings} tone={overview.high_findings > 0 ? "danger" : "muted"} />
        <Stat label="critical combos" value={overview.critical_combos} tone={overview.critical_combos > 0 ? "warning" : "muted"} />
        <Stat label="priority call-sites" value={overview.priority_count} />
        <Stat label="scans" value={overview.scan_count} />
        <Stat label="mode" value={overview.mode ?? "—"} />
      </div>

      <nav className="row" style={{ gap: 20, borderBottom: "1px solid #27272a", padding: "12px 0 10px", marginTop: 16, fontFamily: "ui-monospace, monospace", fontSize: 14 }}>
        {TABS.map((tab) => {
          const href = tab.slug ? `/repos/${repo_id}/${tab.slug}` : `/repos/${repo_id}`;
          return (
            <Link
              key={tab.label}
              href={tab.comingSoon ? "#" : href}
              style={{
                color: tab.comingSoon ? "#52525b" : "#a1a1aa",
                textDecoration: "none",
                cursor: tab.comingSoon ? "not-allowed" : "pointer",
              }}
              aria-disabled={tab.comingSoon}
              title={tab.comingSoon ? "Coming soon" : undefined}
            >
              {tab.label}
              {tab.comingSoon && <span style={{ marginLeft: 6, fontSize: 10, color: "#3f3f46" }}>soon</span>}
            </Link>
          );
        })}
      </nav>

      <div style={{ marginTop: 20 }}>{children}</div>
    </div>
  );
}

function Stat({ label, value, tone = "default" }: { label: string; value: string | number; tone?: "default" | "danger" | "warning" | "muted" }) {
  const color = tone === "danger" ? "#fb7185" : tone === "warning" ? "#fbbf24" : tone === "muted" ? "#71717a" : "#e4e4e7";
  return (
    <div>
      <div className="mono" style={{ fontSize: 18, fontWeight: 600, color }}>{value}</div>
      <div className="muted mono" style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: "0.1em" }}>{label}</div>
    </div>
  );
}

function BuilderButton({ label }: { label: string }) {
  return (
    <button
      type="button"
      disabled
      title="Builder unlocks — $29/mo"
      className="button-secondary"
      style={{ opacity: 0.5, cursor: "not-allowed" }}
    >
      {label}
    </button>
  );
}
