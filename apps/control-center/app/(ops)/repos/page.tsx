"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { getHistory, type RepoHistoryEntry } from "@/lib/repo-history";
import type { RepoOverview } from "@/lib/repos";

/**
 * Repo listing — hydrates from localStorage (the only source of "which repos
 * has this user scanned?" until auth lands), then fans out to
 * /api/repos/by-url for the latest aggregated state per repo.
 */
type Row = { entry: RepoHistoryEntry; overview: RepoOverview | null; error: string | null };

export default function ReposPage() {
  const [rows, setRows] = useState<Row[] | null>(null);

  useEffect(() => {
    const entries = getHistory();
    if (entries.length === 0) {
      setRows([]);
      return;
    }
    let cancelled = false;
    Promise.all(
      entries.map(async (entry) => {
        try {
          const res = await fetch(`/api/repos/by-url?github_url=${encodeURIComponent(entry.github_url)}`, {
            cache: "no-store",
          });
          if (!res.ok) {
            const data = (await res.json().catch(() => ({}))) as { error?: string };
            return { entry, overview: null, error: data.error ?? `${res.status}` } satisfies Row;
          }
          const overview = (await res.json()) as RepoOverview;
          return { entry, overview, error: null } satisfies Row;
        } catch (e) {
          return { entry, overview: null, error: (e as Error).message } satisfies Row;
        }
      }),
    ).then((all) => {
      if (!cancelled) setRows(all);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (rows === null) {
    return <div className="muted" style={{ padding: 24 }}>Loading your repos…</div>;
  }

  if (rows.length === 0) {
    return (
      <div className="card" style={{ padding: 24, margin: 24, maxWidth: 640 }}>
        <h2 style={{ marginTop: 0 }}>No repos yet</h2>
        <p className="muted">
          Run a scan to start tracking a repo. The dashboard keeps your scan history locally and
          shows the latest findings + critical combos per repo.
        </p>
        <Link href="/scan" className="button">run a scan →</Link>
      </div>
    );
  }

  return (
    <div style={{ padding: 24 }}>
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 16 }}>
        <div>
          <h1 style={{ margin: 0 }}>Repos</h1>
          <p className="muted" style={{ marginTop: 4 }}>
            {rows.length} repo{rows.length === 1 ? "" : "s"} scanned from this browser
          </p>
        </div>
        <Link href="/scan" className="button">scan a new repo →</Link>
      </div>

      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <Th>Repo</Th>
              <Th>Latest scan</Th>
              <Th align="right">High findings</Th>
              <Th align="right">Critical combos</Th>
              <Th align="right">Scans</Th>
              <Th></Th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <RepoRow key={row.entry.github_url} row={row} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RepoRow({ row }: { row: Row }) {
  const { entry, overview, error } = row;
  const urlShort = entry.github_url.replace(/^https?:\/\/(www\.)?github\.com\//, "");
  return (
    <tr>
      <Td>
        <div className="mono" style={{ fontSize: 13, color: "#e4e4e7" }}>{urlShort}</div>
        <div className="muted mono" style={{ fontSize: 11 }}>{entry.github_url}</div>
      </Td>
      <Td>
        {overview?.latest_scan_at ? (
          <time dateTime={overview.latest_scan_at} title={overview.latest_scan_at}>
            {formatAge(overview.latest_scan_at)}
          </time>
        ) : (
          <span className="muted">—</span>
        )}
      </Td>
      <Td align="right">
        {error ? <span className="muted">—</span> : overview ? <Badge count={overview.high_findings} tone="danger" /> : <Loading />}
      </Td>
      <Td align="right">
        {error ? <span className="muted">—</span> : overview ? <Badge count={overview.critical_combos} tone="warning" /> : <Loading />}
      </Td>
      <Td align="right">
        {overview ? overview.scan_count : <span className="muted">—</span>}
      </Td>
      <Td align="right">
        {overview?.repo_id ? (
          <Link href={`/repos/${overview.repo_id}`}>open →</Link>
        ) : (
          <span className="muted" title={error ?? ""}>{error ? "error" : "…"}</span>
        )}
      </Td>
    </tr>
  );
}

function Th({ children, align = "left" }: { children?: React.ReactNode; align?: "left" | "right" }) {
  return (
    <th style={{ padding: "10px 14px", textAlign: align, fontSize: 12, textTransform: "uppercase", letterSpacing: "0.1em", color: "#71717a", borderBottom: "1px solid #27272a" }}>
      {children}
    </th>
  );
}

function Td({ children, align = "left" }: { children?: React.ReactNode; align?: "left" | "right" }) {
  return (
    <td style={{ padding: "12px 14px", textAlign: align, fontSize: 14, borderBottom: "1px solid #27272a" }}>
      {children}
    </td>
  );
}

function Badge({ count, tone }: { count: number; tone: "danger" | "warning" }) {
  if (count === 0) return <span className="muted mono">0</span>;
  const color = tone === "danger" ? "#fb7185" : "#fbbf24";
  return <span className="mono" style={{ color, fontWeight: 600 }}>{count}</span>;
}

function Loading() {
  return <span className="muted mono" style={{ fontSize: 12 }}>…</span>;
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
