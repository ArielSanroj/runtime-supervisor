import Link from "next/link";
import { getMetrics, type MetricsSummary } from "@/lib/metrics";
import { api, type RecentAction, type ReviewCase } from "@/lib/api";
import { threatsApi, type ThreatAssessmentRow } from "@/lib/threats";
import { AutoRefresh } from "../review/AutoRefresh";
import InfoTip from "../InfoTip";

export const dynamic = "force-dynamic";

function age(iso: string): string {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  return h < 24 ? `${h}h` : `${Math.floor(h / 24)}d`;
}

function payloadOneLiner(c: ReviewCase): string {
  const amt = c.action_payload["amount"];
  const cur = c.action_payload["currency"] ?? "USD";
  const cust = c.action_payload["customer_id"];
  const reason = c.action_payload["reason"];
  const bits: string[] = [c.action_type];
  if (typeof amt === "number") bits.push(`${amt.toLocaleString()} ${cur}`);
  if (cust) bits.push(`to ${cust}`);
  if (reason) bits.push(`· ${String(reason).slice(0, 40)}`);
  return bits.join(" ");
}

type Window = "24h" | "7d" | "30d";

function pct(num: number, total: number): string {
  if (!total) return "0%";
  return `${Math.round((num / total) * 100)}%`;
}

function fmtAge(minutes: number | null): string {
  if (minutes === null) return "—";
  if (minutes < 60) return `${minutes}m`;
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  if (h < 24) return `${h}h ${m}m`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h`;
}

function DecisionBar({ m }: { m: MetricsSummary }) {
  const t = m.decisions.allow + m.decisions.deny + m.decisions.review;
  if (t === 0) return <p className="muted">No decisions yet in this window.</p>;
  const allow = (m.decisions.allow / t) * 100;
  const deny = (m.decisions.deny / t) * 100;
  const review = (m.decisions.review / t) * 100;
  return (
    <div>
      <div style={{ display: "flex", height: 24, borderRadius: 6, overflow: "hidden", border: "1px solid var(--border)" }}>
        <div style={{ width: `${allow}%`, background: "rgba(52,211,153,0.9)", color: "#0b0d12", fontSize: 11, fontWeight: 600, textAlign: "center", lineHeight: "24px" }}>
          {allow >= 8 ? "allow" : ""}
        </div>
        <div style={{ width: `${review}%`, background: "rgba(245,182,66,0.9)", color: "#0b0d12", fontSize: 11, fontWeight: 600, textAlign: "center", lineHeight: "24px" }}>
          {review >= 8 ? "review" : ""}
        </div>
        <div style={{ width: `${deny}%`, background: "rgba(239,79,90,0.9)", color: "#0b0d12", fontSize: 11, fontWeight: 600, textAlign: "center", lineHeight: "24px" }}>
          {deny >= 8 ? "deny" : ""}
        </div>
      </div>
      <div className="row" style={{ gap: 16, marginTop: 8, fontSize: 13 }}>
        <span><span className="chain-ok">●</span> allow {m.decisions.allow} · {pct(m.decisions.allow, t)}</span>
        <span style={{ color: "var(--warn)" }}>● review {m.decisions.review} · {pct(m.decisions.review, t)}</span>
        <span style={{ color: "var(--danger)" }}>● deny {m.decisions.deny} · {pct(m.decisions.deny, t)}</span>
      </div>
    </div>
  );
}

export default async function Dashboard({
  searchParams,
}: {
  searchParams: Promise<{ window?: string }>;
}) {
  const sp = await searchParams;
  const win = (sp.window as Window) ?? "24h";
  let m: MetricsSummary | null = null;
  let err: string | null = null;
  let blocks: RecentAction[] = [];
  let pending: ReviewCase[] = [];
  let threats: ThreatAssessmentRow[] = [];
  try {
    [m, blocks, pending, threats] = await Promise.all([
      getMetrics(win),
      api.listRecentActions({ decision: "deny", limit: 10 }).catch(() => []),
      api.listReviews("pending").catch(() => []),
      threatsApi.list(10).catch(() => []),
    ]);
  } catch (e) {
    err = (e as Error).message;
  }

  if (err || !m) {
    return (
      <div>
        <h1>Dashboard</h1>
        <div className="card" style={{ borderColor: "var(--danger)", color: "var(--danger)" }}>
          Supervisor API unreachable: {err}
        </div>
      </div>
    );
  }

  const threatRate = m.actions_total ? Math.round((m.threats.total / m.actions_total) * 100) : 0;

  return (
    <div>
      <AutoRefresh intervalMs={5000} />
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center" }}>
          <h1 style={{ margin: 0 }}>Dashboard</h1>
          <InfoTip>
            <strong>Para qué:</strong> ver el estado de salud del supervisor de un vistazo. Si el agente está siendo atacado o si tu policy está frenando pedidos legítimos, acá lo ves primero.<br /><br />
            <strong>Quién:</strong> dev/founder (diario durante el rollout), compliance (semanal).<br /><br />
            <strong>Refresh:</strong> auto cada 5s. Elegí ventana <code>24h</code>, <code>7d</code> o <code>30d</code> arriba a la derecha.
          </InfoTip>
        </div>
        <div className="row" style={{ gap: 6 }}>
          {(["24h", "7d", "30d"] as Window[]).map((w) => (
            <Link key={w} href={`/dashboard?window=${w}`} className={`badge ${win === w ? "approved" : ""}`}>
              {w}
            </Link>
          ))}
        </div>
      </div>

      <h2>Qué está pasando ahora<InfoTip>Los 3 feeds en vivo: acciones frenadas, casos que esperan decisión humana, y amenazas detectadas por el pipeline OWASP.</InfoTip></h2>
      <div className="grid cols-3">
        {/* Card 1 — Recent blocks */}
        <div className="card">
          <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
            <h3 style={{ margin: 0, display: "flex", alignItems: "center" }}>
              Bloqueos recientes
              <InfoTip>
                <strong>Qué:</strong> las últimas acciones que el supervisor frenó (decisión <code>deny</code>) según la policy. Ej.: un refund sobre el hard-cap, un DELETE sin <code>WHERE</code>, un pago a país sancionado.<br /><br />
                <strong>Quién:</strong> dev/founder — <em>¿rompió algo anoche?</em>.<br /><br />
                <strong>Acción:</strong> si un bloqueo es falso positivo, ajustá la regla en <code>/policies</code> y promové nueva versión.
              </InfoTip>
            </h3>
            <span className="muted mono">{blocks.length}</span>
          </div>
          {blocks.length === 0 ? (
            <p className="muted" style={{ marginTop: 8 }}>
              Sin bloqueos todavía. Cuando el supervisor frene una acción real, aparece acá con razón + latencia.
            </p>
          ) : (
            <table style={{ marginTop: 8 }}>
              <tbody>
                {blocks.slice(0, 8).map((b) => (
                  <tr key={b.action_id}>
                    <td className="muted mono" style={{ width: 52 }}>{age(b.created_at)}</td>
                    <td><span className="mono">{b.action_type}</span></td>
                    <td className="muted">{b.reasons.slice(0, 2).join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Card 2 — Pending reviews */}
        <div className="card">
          <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
            <h3 style={{ margin: 0, display: "flex", alignItems: "center" }}>
              Esperan humano
              <InfoTip>
                <strong>Qué:</strong> casos que superaron el umbral de risk score (≥50 por defecto) y la policy los mandó a review en vez de aprobar/bloquear automático.<br /><br />
                <strong>Quién:</strong> operador on-call (dev de guardia o compliance). Uno por turno abre y decide.<br /><br />
                <strong>Acción:</strong> click en el caso → ver payload + historial del cliente → <code>approve</code> o <code>reject</code>. El agente queda esperando (o timeout según policy).
              </InfoTip>
            </h3>
            <Link href="/review?status=pending" className="muted mono">{pending.length} →</Link>
          </div>
          {pending.length === 0 ? (
            <p className="muted" style={{ marginTop: 8 }}>
              Nada en review. Cuando el supervisor escale a humano, aparece acá con resumen + botón para abrir.
            </p>
          ) : (
            <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 8 }}>
              {pending.slice(0, 5).map((c) => (
                <Link key={c.id} href={`/review/${c.id}`} style={{ textDecoration: "none", color: "inherit" }}>
                  <div className="row" style={{ justifyContent: "space-between", gap: 8, padding: "6px 0", borderBottom: "1px solid var(--border)" }}>
                    <div>
                      <div>{payloadOneLiner(c)}</div>
                      <div className="muted mono" style={{ fontSize: 11 }}>
                        {age(c.created_at)} · {c.policy_hits[0]?.reason ?? "—"}
                        {c.priority !== "normal" && ` · priority: ${c.priority}`}
                      </div>
                    </div>
                    <span className="muted">open →</span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>

        {/* Card 3 — Recent threats */}
        <div className="card">
          <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
            <h3 style={{ margin: 0, display: "flex", alignItems: "center" }}>
              Threats detectados
              <InfoTip>
                <strong>Qué:</strong> detecciones del threat pipeline (prompt-injection, jailbreak, PII exfil, excessive agency, etc.) mapeadas al <strong>OWASP LLM Top 10</strong>. Son señales independientes de la policy.<br /><br />
                <strong>Quién:</strong> security / CISO — <em>¿nos están atacando?</em>.<br /><br />
                <strong>Acción:</strong> si hay un patrón (mismo detector disparando seguido), revisá el ángulo de ataque en <code>/threats</code>. Si son falsos positivos recurrentes, ajustá la sensibilidad del detector.
              </InfoTip>
            </h3>
            <Link href="/threats" className="muted mono">{threats.length} →</Link>
          </div>
          {threats.length === 0 ? (
            <p className="muted" style={{ marginTop: 8 }}>
              Pipeline OWASP LLM Top 10 corriendo, sin hits. Si el agente recibe un prompt-injection, jailbreak o PII exfil, aparece acá.
            </p>
          ) : (
            <table style={{ marginTop: 8 }}>
              <tbody>
                {threats.slice(0, 8).map((t) => (
                  <tr key={t.id}>
                    <td className="muted mono" style={{ width: 52 }}>{age(t.created_at)}</td>
                    <td>
                      <span className={`badge ${t.level === "critical" ? "" : ""}`} style={{ background: t.level === "critical" ? "var(--danger)" : t.level === "warn" ? "var(--warn, #b48a00)" : "var(--border)", color: "white" }}>
                        {t.level}
                      </span>
                    </td>
                    <td className="mono">{t.owasp_ref}</td>
                    <td className="muted">{t.detector_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <h2>Volume<InfoTip>Totales agregados para la ventana elegida. Útil para ver tendencia (hoy vs. ayer) y detectar spikes. Si <code>Actions</code> cae a cero, el supervisor dejó de recibir tráfico — probable problema de conectividad del guard, no del agente.</InfoTip></h2>
      <div className="grid cols-3">
        <div className="card kpi">
          {m.actions_total}
          <span className="label">Actions ({m.window})</span>
        </div>
        <div className="card kpi">
          {m.threats.total}
          <span className="label">Threats detected · {threatRate}% rate</span>
        </div>
        <div className="card kpi">
          {m.reviews.pending}
          <span className="label">Pending review · oldest {fmtAge(m.reviews.oldest_pending_age_minutes)}</span>
        </div>
      </div>

      <h2>Decisions<InfoTip><strong>Allow</strong> (verde) = la policy dejó pasar.<br /><strong>Review</strong> (amarillo) = el caso fue escalado a humano.<br /><strong>Deny</strong> (rojo) = la acción fue bloqueada.<br /><br /><strong>Señal:</strong> si deny&gt;20% sostenido, tu policy está demasiado estricta o estás bajo ataque. Si allow=100%, el supervisor no está haciendo nada — revisá que las reglas estén promovidas.</InfoTip></h2>
      <div className="card">
        <DecisionBar m={m} />
      </div>

      {m.threats.top_detectors.length > 0 && (
        <>
          <h2>Top threat detectors<InfoTip>Ranking de qué detector del pipeline OWASP se disparó más. Te dice <strong>qué vector de ataque estás recibiendo</strong>: <code>LLM01</code> (prompt injection), <code>LLM02</code> (PII disclosure), <code>LLM06</code> (jailbreak), <code>LLM10</code> (unbounded consumption). Si uno domina, ajustá la policy para ese detector específico.</InfoTip></h2>
          <div className="card" style={{ padding: 0 }}>
            <table>
              <thead><tr><th>Detector</th><th>Hits</th></tr></thead>
              <tbody>
                {m.threats.top_detectors.map((t) => (
                  <tr key={t.detector_id}>
                    <td className="mono">{t.detector_id}</td>
                    <td>{t.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <h2>Executions (action_proxy)<InfoTip>Solo aplica si usás <strong>action_proxy mode</strong> (el supervisor ejecuta la acción en tu nombre tras aprobarla, no solo te devuelve un <code>allow</code>). Acá ves si esas ejecuciones salieron OK o fallaron después del permit. En el modo normal (<code>guard</code>) estos números quedan en 0.</InfoTip></h2>
      <div className="grid cols-3">
        <div className="card kpi">
          {m.executions.success}
          <span className="label">Success</span>
        </div>
        <div className="card kpi">
          {m.executions.failed}
          <span className="label">Failed</span>
        </div>
        <div className="card kpi">
          {m.executions.success_rate === null ? "—" : `${Math.round(m.executions.success_rate * 100)}%`}
          <span className="label">Success rate</span>
        </div>
      </div>

      <h2>Volume by action_type</h2>
      <div className="card" style={{ padding: 0 }}>
        <table>
          <thead><tr><th>action_type</th><th>Count</th><th>Active policy</th></tr></thead>
          <tbody>
            {Object.keys(m.volume_by_action_type).length === 0 ? (
              <tr><td className="muted" colSpan={3} style={{ padding: 16 }}>No actions in this window.</td></tr>
            ) : (
              Object.entries(m.volume_by_action_type).map(([at, n]) => (
                <tr key={at}>
                  <td className="mono">{at}</td>
                  <td>{n}</td>
                  <td className="mono muted">
                    {m.active_policies_by_type[at] ? `DB v${m.active_policies_by_type[at]}` : "YAML (disk)"}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <h2>System</h2>
      <div className="grid cols-3">
        <div className="card kpi">{m.active_integrations}<span className="label">Active integrations</span></div>
        <div className="card kpi">{Object.keys(m.active_policies_by_type).length}<span className="label">DB policies active</span></div>
        <div className="card">
          <h3 style={{ margin: 0 }}>Next step</h3>
          <p className="muted" style={{ marginTop: 8 }}>
            {m.reviews.pending > 0 ? (
              <>Open <Link href="/review">review queue</Link> to resolve {m.reviews.pending} pending.</>
            ) : m.threats.critical > 0 ? (
              <>See <Link href="/threats?level=critical">{m.threats.critical} critical threat(s)</Link>.</>
            ) : (
              <>System quiet. Inspect the <Link href="/threats">threat feed</Link> or <Link href="/policies">policies</Link>.</>
            )}
          </p>
        </div>
      </div>
    </div>
  );
}
