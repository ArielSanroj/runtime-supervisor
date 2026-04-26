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
        Live attacks
        <InfoTip>
          <strong>What:</strong> attacks the supervisor caught against your agent in real time. Different from policy denies — these are detected behaviors (prompt injections, jailbreaks, PII exfiltration attempts, runaway loops) regardless of which action_type fired them.<br /><br />
          <strong>When:</strong> something here means the supervisor blocked or escalated an attempted attack <em>before</em> your agent ran the action. Quiet feed = nobody is poking your agent yet.<br /><br />
          <strong>Action:</strong> click an attack to see the full payload + which detector caught it. If a detector flags too many false positives, tune sensitivity or add an exception.<br /><br />
          <strong>Levels:</strong> <span style={{ color: "var(--danger)" }}>critical</span> = likely attack · <span style={{ color: "var(--warn)" }}>warn</span> = soft signal · <span style={{ color: "var(--ok)" }}>info</span> = informational only.<br /><br />
          <span className="muted">Footnote: detectors are mapped to the OWASP LLM Top 10 (LLM01 prompt injection, LLM02 PII, LLM06 jailbreak, LLM10 unbounded consumption) — visible in each row for compliance reporting.</span>
        </InfoTip>
      </h1>
      <p className="muted" style={{ marginBottom: 16 }}>
        Attacks the supervisor caught against your agent in real time — prompt injection, jailbreak,
        PII exfiltration, runaway loops, and more.
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
