import { api } from "@/lib/api";
import ResolveForm from "./ResolveForm";

export const dynamic = "force-dynamic";

export default async function ReviewDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const item = await api.getReview(id);
  const evidence = await api.getEvidence(item.action_id);

  return (
    <div>
      <h1>Review {item.id.slice(0, 8)}…</h1>
      <div className="row" style={{ gap: 12, marginBottom: 12 }}>
        <span className={`badge ${item.status}`}>{item.status}</span>
        <span className="muted mono">action_id {item.action_id}</span>
      </div>

      <div className="grid cols-2">
        <div className="card">
          <h2>Action payload</h2>
          <pre>{JSON.stringify(item.action_payload, null, 2)}</pre>
          <h2>Policy hits</h2>
          {item.policy_hits.length === 0 ? (
            <p className="muted">No explicit policy hits — elevated by risk score.</p>
          ) : (
            <ul>
              {item.policy_hits.map((h) => (
                <li key={h.rule_id}>
                  <span className="mono">{h.rule_id}</span> → <strong>{h.action}</strong> · {h.reason}
                </li>
              ))}
            </ul>
          )}
          <h2>Risk score</h2>
          <p className="kpi">{item.risk_score}</p>
        </div>

        <div className="card">
          <h2>Resolve</h2>
          {item.status === "pending" ? (
            <ResolveForm id={item.id} />
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

      <h2>Evidence</h2>
      <div className="card">
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
    </div>
  );
}
