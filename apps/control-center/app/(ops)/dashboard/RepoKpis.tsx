"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { getHistory, type RepoHistoryEntry } from "@/lib/repo-history";
import type { RepoOverview } from "@/lib/repos";

/**
 * Top-of-dashboard KPI strip + recent-scans sidebar.
 *
 * Repos live in localStorage until auth; the KPIs are the aggregate over those
 * repos' latest scans, fetched on mount via /api/repos/by-url.
 */
type Agg = {
  repos: number;
  highFindings: number;
  criticalCombos: number;
  enforceMode: number;
  recent: Array<RepoHistoryEntry & { overview: RepoOverview | null }>;
};

export default function RepoKpis() {
  const [agg, setAgg] = useState<Agg | null>(null);

  useEffect(() => {
    const entries = getHistory();
    if (entries.length === 0) {
      setAgg({ repos: 0, highFindings: 0, criticalCombos: 0, enforceMode: 0, recent: [] });
      return;
    }
    let cancelled = false;
    Promise.all(
      entries.map(async (entry) => {
        try {
          const res = await fetch(`/api/repos/by-url?github_url=${encodeURIComponent(entry.github_url)}`, {
            cache: "no-store",
          });
          if (!res.ok) return { ...entry, overview: null };
          const overview = (await res.json()) as RepoOverview;
          return { ...entry, overview };
        } catch {
          return { ...entry, overview: null };
        }
      }),
    ).then((all) => {
      if (cancelled) return;
      const withOverview = all.filter((r) => r.overview !== null) as Array<RepoHistoryEntry & { overview: RepoOverview }>;
      const highFindings = withOverview.reduce((acc, r) => acc + r.overview.high_findings, 0);
      const criticalCombos = withOverview.reduce((acc, r) => acc + r.overview.critical_combos, 0);
      const enforceMode = withOverview.filter((r) => r.overview.mode === "enforce").length;
      setAgg({
        repos: entries.length,
        highFindings,
        criticalCombos,
        enforceMode,
        recent: all.slice(0, 5),
      });
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (agg === null) {
    return (
      <section className="grid cols-4" style={{ marginTop: 16, marginBottom: 20 }}>
        <Kpi value="…" label="Repos connected" tone="muted" />
        <Kpi value="…" label="High-risk findings" tone="muted" />
        <Kpi value="…" label="Critical combos" tone="muted" />
        <Kpi value="…" label="In enforce mode" tone="muted" />
      </section>
    );
  }

  if (agg.repos === 0) {
    return (
      <section className="card" style={{ marginTop: 16, marginBottom: 20, padding: 16 }}>
        <div className="row" style={{ justifyContent: "space-between", alignItems: "center", gap: 12 }}>
          <div>
            <strong>No repos tracked yet.</strong>{" "}
            <span className="muted">Run your first scan to start the dashboard.</span>
          </div>
          <Link href="/scan" className="badge approved">scan a repo →</Link>
        </div>
      </section>
    );
  }

  return (
    <>
      <section className="grid cols-4" style={{ marginTop: 16, marginBottom: 20 }}>
        <Kpi value={agg.repos} label="Repos connected" tone="muted" href="/repos" />
        <Kpi value={agg.highFindings} label="High-risk findings" tone={agg.highFindings > 0 ? "danger" : "good"} />
        <Kpi value={agg.criticalCombos} label="Critical combos" tone={agg.criticalCombos > 0 ? "warn" : "good"} />
        <Kpi value={agg.enforceMode} label="In enforce mode" tone={agg.enforceMode > 0 ? "good" : "muted"} />
      </section>

      {agg.recent.length > 0 && (
        <aside className="card" style={{ marginBottom: 20, padding: 0 }}>
          <h3 style={{ margin: 0, padding: "14px 18px 6px" }}>Recent scans</h3>
          <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
            {agg.recent.map((r) => {
              const path = r.github_url.replace(/^https?:\/\/(www\.)?github\.com\//, "");
              return (
                <li key={r.github_url} style={{ borderTop: "1px solid var(--border)" }}>
                  <Link
                    href={r.overview ? `/repos/${r.overview.repo_id}` : "/repos"}
                    className="row"
                    style={{
                      justifyContent: "space-between",
                      padding: "10px 18px",
                      color: "inherit",
                      textDecoration: "none",
                    }}
                  >
                    <span className="mono" style={{ fontSize: 13 }}>{path}</span>
                    <span className="row" style={{ gap: 12, alignItems: "baseline" }}>
                      <span className="muted mono" style={{ fontSize: 11 }}>{formatAge(r.ran_at)}</span>
                      {r.overview?.high_findings ? (
                        <span className="mono" style={{ fontSize: 12, color: "var(--danger)" }}>
                          {r.overview.high_findings} high
                        </span>
                      ) : null}
                      {r.overview?.critical_combos ? (
                        <span className="mono" style={{ fontSize: 12, color: "var(--warn)" }}>
                          {r.overview.critical_combos} combo
                        </span>
                      ) : null}
                    </span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </aside>
      )}
    </>
  );
}

function Kpi({
  value,
  label,
  tone,
  href,
}: {
  value: number | string;
  label: string;
  tone: "danger" | "warn" | "good" | "muted";
  href?: string;
}) {
  const color = tone === "danger" ? "var(--danger)" : tone === "warn" ? "var(--warn)" : tone === "good" ? "var(--ok)" : "var(--text)";
  const body = (
    <div className="card kpi" style={{ borderColor: tone === "muted" ? "var(--border)" : color }}>
      <span style={{ color }}>{value}</span>
      <span className="label">{label}</span>
    </div>
  );
  return href ? <Link href={href} style={{ color: "inherit", textDecoration: "none" }}>{body}</Link> : body;
}

function formatAge(iso: string): string {
  const then = new Date(iso).getTime();
  if (!then) return iso;
  const delta = Math.max(0, Date.now() - then);
  const mins = Math.floor(delta / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
