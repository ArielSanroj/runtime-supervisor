import Link from "next/link";
import { getRepoHistory } from "@/lib/repos";

export const dynamic = "force-dynamic";

export default async function RepoHistoryPage({
  params,
}: {
  params: Promise<{ repo_id: string }>;
}) {
  const { repo_id } = await params;
  const history = await getRepoHistory(repo_id);

  if (history.length === 0) {
    return (
      <div className="card" style={{ padding: 20 }}>
        <p className="muted">No scans recorded for this repo yet.</p>
      </div>
    );
  }

  return (
    <div className="card" style={{ padding: 0, overflow: "hidden" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr>
            <Th>Scanned</Th>
            <Th>Ref</Th>
            <Th align="right">Total</Th>
            <Th align="right">High</Th>
            <Th align="right">+ new high</Th>
            <Th align="right">– fixed</Th>
            <Th></Th>
          </tr>
        </thead>
        <tbody>
          {history.map((row) => (
            <tr key={row.scan_id}>
              <Td>
                <time dateTime={row.completed_at} title={row.completed_at}>
                  {new Date(row.completed_at).toLocaleString()}
                </time>
              </Td>
              <Td>
                <span className="mono muted" style={{ fontSize: 12 }}>{row.ref ?? "default"}</span>
              </Td>
              <Td align="right">{row.total_findings}</Td>
              <Td align="right">
                <span className="mono" style={{ color: row.high_findings > 0 ? "var(--danger)" : "var(--muted)" }}>
                  {row.high_findings}
                </span>
              </Td>
              <Td align="right">
                <Delta value={row.new_high} sign="+" tone="warn" />
              </Td>
              <Td align="right">
                <Delta value={row.fixed} sign="-" tone="good" />
              </Td>
              <Td align="right">
                <Link href={`/findings/${row.scan_id}`}>open →</Link>
              </Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Delta({ value, sign, tone }: { value: number | null; sign: "+" | "-"; tone: "warn" | "good" }) {
  if (value === null) return <span className="muted">—</span>;
  if (value === 0) return <span className="muted mono">0</span>;
  const color = tone === "warn" ? "var(--warn)" : "var(--ok)";
  return <span className="mono" style={{ color }}>{sign}{value}</span>;
}

function Th({ children, align = "left" }: { children?: React.ReactNode; align?: "left" | "right" }) {
  return (
    <th style={{ padding: "10px 14px", textAlign: align, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.1em", color: "#71717a", borderBottom: "1px solid #27272a" }}>
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
