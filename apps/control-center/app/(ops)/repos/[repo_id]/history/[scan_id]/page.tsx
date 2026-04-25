import Link from "next/link";
import { getRepoHistory } from "@/lib/repos";
import { getScan, type ScanFinding } from "@/lib/scans";

export const dynamic = "force-dynamic";

type FindingKey = string;

function keyOf(f: ScanFinding): FindingKey {
  // (file:line:scanner:family) is stable enough — moving a call inside a file
  // changes the key but adding a new identical-shape call elsewhere is correctly
  // counted as new. Good trade-off for an MVP diff view.
  const family = (f.extra as Record<string, unknown> | undefined)?.family ?? "";
  return `${f.file}:${f.line}:${f.scanner}:${family}`;
}

export default async function ScanDiffPage({
  params,
}: {
  params: Promise<{ repo_id: string; scan_id: string }>;
}) {
  const { repo_id, scan_id } = await params;

  const [history, current] = await Promise.all([
    getRepoHistory(repo_id),
    getScan(scan_id),
  ]);

  const ix = history.findIndex((h) => h.scan_id === scan_id);
  const previous = ix >= 0 && ix < history.length - 1 ? history[ix + 1] : null;

  if (!previous) {
    return (
      <div className="card" style={{ padding: 24 }}>
        <h2 style={{ marginTop: 0 }}>First scan for this repo</h2>
        <p className="muted">
          No previous scan to diff against. Run another scan after pushing changes
          to see what was added or fixed.
        </p>
        <Link href={`/findings/${scan_id}`} className="button-secondary" style={{ marginTop: 12 }}>
          open full findings →
        </Link>
      </div>
    );
  }

  const previousScan = await getScan(previous.scan_id);

  const previousByKey = new Map<FindingKey, ScanFinding>();
  for (const f of previousScan.findings ?? []) previousByKey.set(keyOf(f), f);

  const currentByKey = new Map<FindingKey, ScanFinding>();
  for (const f of current.findings ?? []) currentByKey.set(keyOf(f), f);

  const added: ScanFinding[] = [];
  const fixed: ScanFinding[] = [];

  for (const [k, f] of currentByKey) {
    if (!previousByKey.has(k)) added.push(f);
  }
  for (const [k, f] of previousByKey) {
    if (!currentByKey.has(k)) fixed.push(f);
  }

  // Surface high-confidence first within each set — those are the ones the dev
  // most likely cares about reviewing.
  const byConfidence = (a: ScanFinding, b: ScanFinding) => {
    const rank = { high: 0, medium: 1, low: 2 } as const;
    return (rank[a.confidence] ?? 9) - (rank[b.confidence] ?? 9);
  };
  added.sort(byConfidence);
  fixed.sort(byConfidence);

  return (
    <div>
      <div className="card" style={{ padding: 16, marginBottom: 16 }}>
        <div className="row" style={{ justifyContent: "space-between", alignItems: "baseline", flexWrap: "wrap", gap: 12 }}>
          <div>
            <div className="muted mono" style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: "0.1em" }}>
              diff
            </div>
            <h2 style={{ margin: "4px 0 0" }}>
              {fmtDate(previousScan.created_at)}
              {" → "}
              {fmtDate(current.created_at)}
            </h2>
          </div>
          <div className="row" style={{ gap: 16, fontSize: 14 }}>
            <span className="mono" style={{ color: "var(--warn)" }}>+{added.length} new</span>
            <span className="mono" style={{ color: "var(--ok)" }}>−{fixed.length} fixed</span>
          </div>
        </div>
      </div>

      <div className="grid cols-2" style={{ gap: 16 }}>
        <DiffColumn
          title="New since last scan"
          tone="warn"
          empty="Nothing new — the surface is stable."
          items={added}
        />
        <DiffColumn
          title="Fixed since last scan"
          tone="good"
          empty="No findings disappeared."
          items={fixed}
        />
      </div>

      <div className="row" style={{ gap: 12, marginTop: 24 }}>
        <Link href={`/findings/${scan_id}`} className="button-secondary">
          full findings of this scan →
        </Link>
        <Link href={`/repos/${repo_id}/history`} className="button-secondary">
          ← back to history
        </Link>
      </div>
    </div>
  );
}

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString();
}

function DiffColumn({
  title,
  tone,
  empty,
  items,
}: {
  title: string;
  tone: "warn" | "good";
  empty: string;
  items: ScanFinding[];
}) {
  const color = tone === "warn" ? "var(--warn)" : "var(--ok)";
  return (
    <div className="card" style={{ padding: 0, overflow: "hidden" }}>
      <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)", color, fontWeight: 600, fontSize: 13 }}>
        {title} ({items.length})
      </div>
      {items.length === 0 ? (
        <p className="muted" style={{ padding: 16, margin: 0 }}>{empty}</p>
      ) : (
        <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
          {items.map((f, i) => (
            <li
              key={`${f.file}:${f.line}:${i}`}
              style={{ padding: "10px 16px", borderBottom: "1px solid var(--border)" }}
            >
              <div className="mono" style={{ fontSize: 13 }}>
                <span style={{ color: "#e4e4e7" }}>{f.file}</span>
                <span className="muted">:{f.line}</span>
              </div>
              <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>
                {f.scanner} · {f.suggested_action_type} · <span className="mono">{f.confidence}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
