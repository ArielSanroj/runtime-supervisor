import Link from "next/link";
import { threatsApi } from "@/lib/threats";

export const dynamic = "force-dynamic";

export default async function ThreatDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const row = await threatsApi.get(Number(id));

  return (
    <div>
      <h1>Threat {row.id} · <span className={`badge ${row.level === "critical" ? "rejected" : row.level === "warn" ? "pending" : "approved"}`}>{row.level}</span></h1>
      <div className="row" style={{ marginBottom: 12, gap: 12 }}>
        <span className="muted mono">OWASP {row.owasp_ref}</span>
        <span className="muted mono">detector {row.detector_id}</span>
        <span className="muted mono">at {new Date(row.created_at).toLocaleString()}</span>
      </div>

      <div className="grid cols-2">
        <div className="card">
          <h2>Signal</h2>
          {row.signals.map((s, i) => (
            <div key={i} style={{ marginBottom: 12 }}>
              <p>{s.message}</p>
              <pre>{JSON.stringify(s.evidence, null, 2)}</pre>
            </div>
          ))}
        </div>
        <div className="card">
          <h2>Context</h2>
          <p className="muted mono">integration_id</p>
          <p className="mono">{row.integration_id ?? "—"}</p>
          <p className="muted mono" style={{ marginTop: 12 }}>action_id</p>
          <p className="mono">
            {row.action_id ? (
              <Link href={`#`} style={{ pointerEvents: "none" }}>{row.action_id}</Link>
            ) : "—"}
          </p>
          {row.action_id && (
            <p style={{ marginTop: 16 }}>
              <Link href={`/review`}>→ see in review queue</Link>
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
