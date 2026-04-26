import { api, type CustomerContext, type EvidenceBundle, type ReviewCase } from "@/lib/api";
import ResolveForm from "./ResolveForm";

export const dynamic = "force-dynamic";

function formatAmount(payload: Record<string, unknown>): string | null {
  const amt = payload["amount"];
  const cur = (payload["currency"] as string | undefined) ?? "USD";
  if (typeof amt !== "number") return null;
  return `${amt.toLocaleString()} ${cur}`;
}

function buildSummary(item: ReviewCase): string {
  const amt = formatAmount(item.action_payload);
  const customer = item.action_payload["customer_id"];
  const reason = item.action_payload["reason"];
  const pieces: string[] = [];
  pieces.push(`Agente ${item.assigned_to ? `(${item.assigned_to})` : ""} quiere hacer un`);
  pieces.push(`**${item.action_type}**`);
  if (amt) pieces.push(`de **${amt}**`);
  if (customer) pieces.push(`al cliente \`${String(customer)}\``);
  if (reason) pieces.push(`con motivo "${String(reason)}"`);
  return pieces.join(" ").replace(/\s+/g, " ");
}

function consequenceOf(actionType: string): { approve: string; reject: string } {
  switch (actionType) {
    case "refund":
      return {
        approve: "Aprobás → se ejecuta `stripe.Refund.create` con este monto.",
        reject: "Rechazás → la acción se cancela, el agente recibe `deny`.",
      };
    case "payment":
      return {
        approve: "Aprobás → se ejecuta la llamada de pago downstream.",
        reject: "Rechazás → la llamada de pago se cancela.",
      };
    case "account_change":
      return {
        approve: "Aprobás → el cambio al perfil/cuenta se persiste.",
        reject: "Rechazás → el perfil/cuenta queda como estaba.",
      };
    case "tool_use":
      return {
        approve: "Aprobás → el agente ejecuta la tool-call al LLM/API externa.",
        reject: "Rechazás → la tool-call se cancela, el agente no invoca al modelo.",
      };
    default:
      return {
        approve: `Aprobás → el agente ejecuta la acción \`${actionType}\`.`,
        reject: "Rechazás → la acción se cancela, el agente recibe `deny`.",
      };
  }
}

type Trigger = { kind: "threat" | "policy" | "risk"; label: string; color: string };

function computeTrigger(item: ReviewCase, evidence: EvidenceBundle): Trigger {
  const threatEvent = evidence.events.find((e) => e.event_type === "threat.detected");
  if (threatEvent) {
    const level = (threatEvent.event_payload as { level?: string })?.level ?? "warn";
    return { kind: "threat", label: `threat · ${level}`, color: "var(--danger)" };
  }
  if (item.policy_hits.length > 0) {
    return { kind: "policy", label: "policy rule", color: "var(--accent)" };
  }
  return { kind: "risk", label: `risk score ${item.risk_score}`, color: "var(--warn, #b48a00)" };
}

function agentContextOf(evidence: EvidenceBundle): Record<string, unknown> | null {
  // Emitted by the guard when the agent opens an observing(...) block.
  // Null when the agent didn't ship context — common case for legacy calls.
  const ev = evidence.events.find((e) => e.event_type === "agent.context");
  return ev ? (ev.event_payload as Record<string, unknown>) : null;
}

function pendingFor(createdAt: string): string {
  const diff = Date.now() - new Date(createdAt).getTime();
  const min = Math.floor(diff / 60000);
  if (min < 1) return "<1min";
  if (min < 60) return `${min}min`;
  const h = Math.floor(min / 60);
  const rem = min % 60;
  return rem === 0 ? `${h}h` : `${h}h ${rem}m`;
}

const PAYLOAD_LABELS: Record<string, string> = {
  amount: "Monto",
  currency: "Moneda",
  customer_id: "Cliente",
  customer_age_days: "Antigüedad (días)",
  refund_velocity_24h: "Refunds 24h",
  reason: "Motivo",
  vendor_id: "Proveedor",
  bank_account_changed: "Cuenta bancaria cambió",
};

export default async function ReviewDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const item = await api.getReview(id);
  const evidence = await api.getEvidence(item.action_id);
  const customerId = item.action_payload["customer_id"] as string | undefined;
  const customerContext = customerId ? await api.customerContext(customerId) : null;

  const summary = buildSummary(item);
  const consequence = consequenceOf(item.action_type);
  const trigger = computeTrigger(item, evidence);
  const agentContext = agentContextOf(evidence);
  const pending = item.status === "pending";

  return (
    <div>
      <div className="row" style={{ gap: 12, marginBottom: 6, alignItems: "center" }}>
        <span className={`badge ${item.status}`}>{item.status}</span>
        <span className="badge" style={{ background: trigger.color, color: "white" }}>
          {trigger.label}
        </span>
        {item.priority !== "normal" && (
          <span className="badge" style={{ background: "var(--danger)", color: "white" }}>
            priority: {item.priority}
          </span>
        )}
        {pending && (
          <span className="muted">pending for {pendingFor(item.created_at)}</span>
        )}
      </div>
      <h1 style={{ margin: "0 0 8px" }}>Review {item.id.slice(0, 8)}…</h1>
      <p style={{ fontSize: "1.05rem", marginTop: 0 }} dangerouslySetInnerHTML={{ __html: mdBold(summary) }} />

      {agentContext && <AgentContextCard ctx={agentContext} />}

      <div className="grid cols-2">
        <div className="card">
          <h2>Action details</h2>
          <PayloadTable payload={item.action_payload} />
          <h2 style={{ marginTop: 24 }}>Why this is in review</h2>
          {item.policy_hits.length > 0 ? (
            <ul style={{ paddingLeft: 18 }}>
              {item.policy_hits.map((h) => (
                <li key={h.rule_id} style={{ marginBottom: 10 }}>
                  <strong>{h.action.toUpperCase()}</strong>
                  {" · "}
                  <span className="mono muted">{h.rule_id}</span>
                  {h.explanation ? (
                    <div style={{ marginTop: 4 }}>{h.explanation}</div>
                  ) : (
                    <div className="muted" style={{ marginTop: 4 }}>
                      reason: <span className="mono">{h.reason}</span>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          ) : trigger.kind === "threat" ? (
            <p>
              An attack signal was detected ({trigger.label}). Check the{" "}
              <span className="mono">threat.detected</span> event in the audit trail below.
            </p>
          ) : (
            <p>No policy hits — escalated by risk score ({item.risk_score}).</p>
          )}
          <h2 style={{ marginTop: 24 }}>Risk score</h2>
          <p className="kpi">{item.risk_score}</p>
        </div>

        <div className="card">
          <h2>Resolve</h2>
          {pending ? (
            <>
              <div style={{ marginBottom: 12, fontSize: "0.95rem", lineHeight: 1.5 }}>
                <div>
                  <strong style={{ color: "#0a7a2e" }}>Approve:</strong> {consequence.approve}
                </div>
                <div style={{ marginTop: 6 }}>
                  <strong style={{ color: "var(--danger)" }}>Reject:</strong> {consequence.reject}
                </div>
              </div>
              <ResolveForm
                id={item.id}
                canEscalate={item.priority !== "high"}
                approverEmail=""
              />
            </>
          ) : (
            <>
              <p>
                Resolved {item.resolved_at ? new Date(item.resolved_at).toLocaleString() : ""} by{" "}
                <span className="mono">{item.approver ?? "—"}</span>
              </p>
              {item.approver_notes && (
                <>
                  <h2>Notes</h2>
                  <p>{item.approver_notes}</p>
                </>
              )}
            </>
          )}
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h2 style={{ marginTop: 0 }}>Customer context</h2>
        {customerContext ? (
          <CustomerContextView ctx={customerContext} />
        ) : (
          <p className="muted">
            Conectá tu CRM seteando <span className="mono">SUPERVISOR_CUSTOMER_CONTEXT_URL</span> en
            el control-center. El UI hará GET a <span className="mono">${"{URL}"}/{"{customer_id}"}</span>{" "}
            y renderizará lo que devuelva (historial, tier, tickets). Sin eso, el reviewer tiene que flipear
            al CRM a mano.
          </p>
        )}
      </div>

      <details style={{ marginTop: 16 }} className="card">
        <summary style={{ cursor: "pointer", fontWeight: 600 }}>
          Audit trail ({evidence.events.length} eventos · chain {evidence.chain_ok ? "OK" : "BROKEN"})
        </summary>
        <div style={{ marginTop: 12 }}>
          <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
            <span className={evidence.chain_ok ? "chain-ok" : "chain-bad"}>
              chain_ok: {String(evidence.chain_ok)}
              {evidence.broken_at_seq != null && ` · broken at seq ${evidence.broken_at_seq}`}
            </span>
            <span className="muted mono">bundle {evidence.bundle_hash.slice(0, 16)}…</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>seq</th>
                <th>type</th>
                <th>hash</th>
                <th>when</th>
              </tr>
            </thead>
            <tbody>
              {evidence.events.map((e) => (
                <tr key={e.seq}>
                  <td>{e.seq}</td>
                  <td className="mono">{e.event_type}</td>
                  <td className="mono">{e.hash.slice(0, 16)}…</td>
                  <td className="muted mono">{new Date(e.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}

function PayloadTable({ payload }: { payload: Record<string, unknown> }) {
  const entries = Object.entries(payload);
  if (entries.length === 0) return <p className="muted">(empty)</p>;
  return (
    <table>
      <tbody>
        {entries.map(([k, v]) => (
          <tr key={k}>
            <td style={{ width: "40%" }}>{PAYLOAD_LABELS[k] ?? k}</td>
            <td className="mono">{formatValue(v)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function formatValue(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v);
}

function AgentContextCard({ ctx }: { ctx: Record<string, unknown> }) {
  // Renders the known-shape keys (session_id, user_id, role, goal, etc) as
  // a labeled card; anything else falls into a collapsible "Other fields".
  const known: Array<[string, string, unknown]> = [
    ["session_id", "Sesión", ctx.session_id],
    ["agent_id", "Agent", ctx.agent_id],
    ["user_id", "Usuario", ctx.user_id],
    ["role", "Rol", ctx.role],
    ["goal", "Objetivo", ctx.goal],
    ["tenant_id", "Tenant", ctx.tenant_id],
  ].filter(([, , v]) => v !== undefined && v !== null && v !== "") as Array<[string, string, unknown]>;

  const tools = Array.isArray(ctx.available_tools) ? ctx.available_tools : null;
  const sources = Array.isArray(ctx.sources) ? ctx.sources : null;
  const otherKeys = Object.keys(ctx).filter(
    (k) => !["session_id", "agent_id", "user_id", "role", "goal", "tenant_id", "available_tools", "sources"].includes(k),
  );

  return (
    <div className="card" style={{ marginBottom: 16, borderLeft: "3px solid var(--accent)" }}>
      <h3 style={{ margin: 0, marginBottom: 8 }}>Agent context</h3>
      <p className="muted" style={{ marginTop: 0, marginBottom: 12, fontSize: "0.9rem" }}>
        Lo que el agente dijo de sí mismo al abrir el `observing(...)` block.
      </p>
      {known.length > 0 && (
        <table>
          <tbody>
            {known.map(([k, label, v]) => (
              <tr key={k}>
                <td style={{ width: "30%" }}>{label}</td>
                <td className="mono">{String(v)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {tools && tools.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <span className="muted">Tools disponibles: </span>
          {tools.map((t, i) => (
            <span key={i} className="mono" style={{ marginRight: 6 }}>
              {String(t)}
            </span>
          ))}
        </div>
      )}
      {sources && sources.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <span className="muted">Fuentes consultadas: </span>
          {sources.map((s, i) => (
            <span key={i} className="mono" style={{ marginRight: 6 }}>
              {String(s)}
            </span>
          ))}
        </div>
      )}
      {otherKeys.length > 0 && (
        <details style={{ marginTop: 8 }}>
          <summary className="muted" style={{ cursor: "pointer" }}>Otros campos ({otherKeys.length})</summary>
          <table style={{ marginTop: 6 }}>
            <tbody>
              {otherKeys.map((k) => (
                <tr key={k}>
                  <td style={{ width: "30%" }}>{k}</td>
                  <td className="mono">{JSON.stringify(ctx[k])}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </div>
  );
}

function CustomerContextView({ ctx }: { ctx: CustomerContext }) {
  const rows: [string, string][] = [];
  if (ctx.display_name) rows.push(["Nombre", ctx.display_name]);
  if (ctx.tier) rows.push(["Tier", ctx.tier]);
  if (typeof ctx.lifetime_value === "number") rows.push(["LTV", `${ctx.lifetime_value.toLocaleString()} USD`]);
  if (typeof ctx.open_tickets === "number") rows.push(["Tickets abiertos", String(ctx.open_tickets)]);
  if (typeof ctx.recent_refunds_30d === "number") rows.push(["Refunds últimos 30d", String(ctx.recent_refunds_30d)]);
  if (ctx.signup_date) rows.push(["Signup", new Date(ctx.signup_date).toLocaleDateString()]);
  return (
    <>
      <table>
        <tbody>
          {rows.map(([k, v]) => (
            <tr key={k}>
              <td style={{ width: "40%" }}>{k}</td>
              <td>{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {ctx.notes && <p style={{ marginTop: 12 }}>{ctx.notes}</p>}
    </>
  );
}

// Bare-bones markdown: only `**bold**` + backticks, which is all buildSummary uses.
function mdBold(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, '<code>$1</code>');
}
