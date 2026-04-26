import Link from "next/link";
import { adminTokenConfigured, integrationsApi, type Integration } from "@/lib/integrations";
import InfoTip from "../InfoTip";

export const dynamic = "force-dynamic";

export default async function IntegrationsPage() {
  if (!adminTokenConfigured()) {
    return (
      <div>
        <h1>Integrations</h1>
        <div className="card" style={{ borderColor: "var(--danger)", color: "var(--danger)" }}>
          <strong>SUPERVISOR_ADMIN_TOKEN is not configured.</strong>
          <p className="muted" style={{ marginTop: 8 }}>
            Add it to <code>apps/control-center/.env.local</code> (same value as the supervisor's{" "}
            <code>ADMIN_BOOTSTRAP_TOKEN</code>).
          </p>
        </div>
      </div>
    );
  }

  let rows: Integration[] = [];
  let err: string | null = null;
  try {
    rows = await integrationsApi.list();
  } catch (e) {
    err = (e as Error).message;
  }

  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h1 style={{ margin: 0, display: "flex", alignItems: "center" }}>
          Integrations
          <InfoTip>
            <strong>What:</strong> apps that talk to the supervisor. Each integration has its own <code>APP_ID</code> + <code>SHARED_SECRET</code> for signing JWTs. Scopes define which <code>action_type</code> it can evaluate.<br /><br />
            <strong>When:</strong> add a new one when you wire up a new agent or service. Rotate when a secret leaks or a teammate leaves.<br /><br />
            <strong>Action:</strong> <code>+ New integration</code> issues a secret. <em>Copy it now — it won&apos;t be shown again.</em> To rotate, click an existing integration → <code>rotate secret</code>.
          </InfoTip>
        </h1>
        <Link href="/integrations/new" className="badge approved" style={{ padding: "8px 14px" }}>+ New integration</Link>
      </div>

      {err && <div className="card" style={{ borderColor: "var(--danger)", color: "var(--danger)", marginTop: 16 }}>{err}</div>}

      {!err && rows.length === 0 && (
        <p className="muted" style={{ marginTop: 24 }}>
          No integrations registered. Create one to issue JWT credentials for an external agent.
        </p>
      )}

      {rows.length > 0 && (
        <div className="card" style={{ padding: 0, marginTop: 16 }}>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Tenant</th>
                <th>Scopes</th>
                <th>Execute URL</th>
                <th>Status</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((i) => (
                <tr key={i.id}>
                  <td className="mono">{i.name}</td>
                  <td className="mono muted" style={{ fontSize: 12 }}>
                    {i.tenant_id ? i.tenant_id.slice(0, 8) : "—"}
                  </td>
                  <td className="mono">{(i.scopes || []).join(", ")}</td>
                  <td className="mono muted" style={{ maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {i.execute_url ?? "—"}
                  </td>
                  <td>
                    {i.active ? (
                      <span className="badge approved">active</span>
                    ) : (
                      <span className="badge rejected">revoked</span>
                    )}
                  </td>
                  <td className="muted mono">{new Date(i.created_at).toLocaleString()}</td>
                  <td><Link href={`/integrations/${i.id}`}>open →</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
