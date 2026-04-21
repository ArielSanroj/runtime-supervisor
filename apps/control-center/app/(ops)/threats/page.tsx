import Link from "next/link";
import { threatsApi, type ThreatAssessmentRow, type ThreatLevel } from "@/lib/threats";
import InfoTip from "../InfoTip";

export const dynamic = "force-dynamic";
export const revalidate = 5;

function levelClass(level: ThreatLevel): string {
  if (level === "critical") return "badge rejected";
  if (level === "warn") return "badge pending";
  return "badge approved";
}

export default async function ThreatsPage({
  searchParams,
}: {
  searchParams: Promise<{ level?: string }>;
}) {
  const sp = await searchParams;
  const level = (sp.level as ThreatLevel | undefined) ?? undefined;

  let rows: ThreatAssessmentRow[] = [];
  let err: string | null = null;
  try {
    rows = await threatsApi.list(100, level);
  } catch (e) {
    err = (e as Error).message;
  }

  const counts = {
    critical: rows.filter((r) => r.level === "critical").length,
    warn: rows.filter((r) => r.level === "warn").length,
    info: rows.filter((r) => r.level === "info").length,
  };

  return (
    <div>
      <h1 style={{ display: "flex", alignItems: "center" }}>
        Threat feed
        <InfoTip>
          <strong>Qué:</strong> stream en vivo de detecciones del threat pipeline, independientes de tus policies. Cada evento apunta a una regla del <strong>OWASP LLM Top 10</strong>: <code>LLM01</code> prompt injection, <code>LLM02</code> PII disclosure, <code>LLM06</code> jailbreak, <code>LLM10</code> unbounded consumption, etc.<br /><br />
          <strong>Quién:</strong> security / CISO — <em>¿qué ataques está recibiendo el agente?</em>.<br /><br />
          <strong>Acción:</strong> click en un threat para ver el payload completo + detector. Si un detector genera muchos falsos positivos, calibrá sensibilidad o agregá excepciones.<br /><br />
          <strong>Niveles:</strong> <span style={{ color: "var(--danger)" }}>critical</span> = ataque probable · <span style={{ color: "var(--warn)" }}>warn</span> = señal débil · <span style={{ color: "var(--ok)" }}>info</span> = log informativo.
        </InfoTip>
      </h1>
      <p className="muted" style={{ marginBottom: 16 }}>
        Live stream of detections raised by the threat pipeline. Mapped to OWASP LLM Top 10.
      </p>

      <div className="grid cols-3" style={{ marginBottom: 16 }}>
        <div className="card kpi"><span className="chain-bad">{counts.critical}</span> <span className="label">Critical</span></div>
        <div className="card kpi" style={{ color: "var(--warn)" }}>{counts.warn} <span className="label" style={{ color: "var(--muted)" }}>Warn</span></div>
        <div className="card kpi">{counts.info} <span className="label">Info</span></div>
      </div>

      <div className="row" style={{ marginBottom: 16 }}>
        <Link href="/threats" className={`badge ${!level ? "approved" : ""}`} style={!level ? { outline: "2px solid var(--accent)" } : undefined}>All</Link>
        <Link href="/threats?level=critical" className="badge rejected" style={level === "critical" ? { outline: "2px solid var(--accent)" } : undefined}>Critical</Link>
        <Link href="/threats?level=warn" className="badge pending" style={level === "warn" ? { outline: "2px solid var(--accent)" } : undefined}>Warn</Link>
        <Link href="/threats?level=info" className="badge approved" style={level === "info" ? { outline: "2px solid var(--accent)" } : undefined}>Info</Link>
      </div>

      {err && <div className="card" style={{ borderColor: "var(--danger)", color: "var(--danger)" }}>{err}</div>}

      {!err && rows.length === 0 && (
        <p className="muted">No threats recorded yet. Try <Link href="/">the simulator on the landing page</Link> to see a blocked prompt injection.</p>
      )}

      {rows.length > 0 && (
        <div className="card" style={{ padding: 0 }}>
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Level</th>
                <th>Detector</th>
                <th>OWASP</th>
                <th>Integration</th>
                <th>Action</th>
                <th>Message</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="mono muted">{new Date(r.created_at).toLocaleString()}</td>
                  <td><span className={levelClass(r.level)}>{r.level}</span></td>
                  <td className="mono">{r.detector_id}</td>
                  <td className="mono">{r.owasp_ref}</td>
                  <td className="mono">{r.integration_id ? r.integration_id.slice(0, 8) + "…" : "—"}</td>
                  <td className="mono">{r.action_id ? r.action_id.slice(0, 8) + "…" : "—"}</td>
                  <td>{r.signals[0]?.message ?? ""}</td>
                  <td><Link href={`/threats/${r.id}`}>open →</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
