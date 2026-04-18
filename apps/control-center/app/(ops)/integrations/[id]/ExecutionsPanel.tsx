import type { ActionExecution } from "@/lib/integrations";

function stateBadge(state: string): string {
  if (state === "success") return "approved";
  if (state === "failed") return "rejected";
  return "pending";
}

export default function ExecutionsPanel({ rows }: { rows: ActionExecution[] }) {
  if (rows.length === 0) {
    return (
      <p className="muted">
        No downstream executions yet. Configure <code>execute_url</code> above and an <code>allow</code>/approved
        review will POST here automatically.
      </p>
    );
  }
  return (
    <div className="card" style={{ padding: 0 }}>
      <table>
        <thead>
          <tr>
            <th>When</th>
            <th>State</th>
            <th>Triggered by</th>
            <th>action_id</th>
            <th>HTTP</th>
            <th>Attempts</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((e) => (
            <tr key={e.id}>
              <td className="muted mono">{new Date(e.queued_at).toLocaleString()}</td>
              <td><span className={`badge ${stateBadge(e.state)}`}>{e.state}</span></td>
              <td className="mono">{e.triggered_by}</td>
              <td className="mono muted">{e.action_id.slice(0, 8)}…</td>
              <td className="mono">{e.status_code ?? "—"}</td>
              <td className="mono">{e.attempts}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
