import Link from "next/link";
import { adminTokenConfigured, policiesApi, type Policy } from "@/lib/policies";
import InfoTip from "../InfoTip";

export const dynamic = "force-dynamic";

export default async function PoliciesPage({
  searchParams,
}: {
  searchParams: Promise<{ action_type?: string }>;
}) {
  const sp = await searchParams;
  const actionType = sp.action_type;

  if (!adminTokenConfigured()) {
    return (
      <div>
        <h1>Policies</h1>
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

  let rows: Policy[] = [];
  let err: string | null = null;
  try {
    rows = await policiesApi.list(actionType);
  } catch (e) {
    err = (e as Error).message;
  }

  const grouped = rows.reduce<Record<string, Policy[]>>((acc, p) => {
    (acc[p.action_type] ??= []).push(p);
    return acc;
  }, {});
  const actionTypes = Object.keys(grouped).sort();

  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h1 style={{ margin: 0, display: "flex", alignItems: "center" }}>
          Policies
          <InfoTip>
            <strong>Qué:</strong> las reglas YAML que el supervisor evalúa en cada llamada del agente. Agrupadas por <code>action_type</code> (refund, payment, account_change, tool_use, data_access, compliance). Cada policy tiene reglas <code>when</code> que deciden <code>allow / deny / review</code>.<br /><br />
            <strong>Quién:</strong> security lead + dev que entiende el negocio. Compliance las revisa para auditar.<br /><br />
            <strong>Acción:</strong> click en una policy → editá el YAML → <code>promote</code> nueva versión. El cambio aplica en la próxima llamada — <em>sin redeploy</em>. Para volver atrás, promové la versión anterior.
          </InfoTip>
        </h1>
        <Link href="/policies/new" className="badge approved" style={{ padding: "8px 14px" }}>+ New policy</Link>
      </div>

      {err && <div className="card" style={{ borderColor: "var(--danger)", color: "var(--danger)", marginTop: 16 }}>{err}</div>}

      {!err && rows.length === 0 && (
        <p className="muted" style={{ marginTop: 24 }}>
          No policies in the DB yet — the supervisor is running off the checked-in YAML files under <code>packages/policies/</code>.
          Create one here to edit rules without a deploy.
        </p>
      )}

      {actionTypes.map((at) => (
        <div key={at} style={{ marginTop: 24 }}>
          <h2>{at}</h2>
          <div className="card" style={{ padding: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>Version</th>
                  <th>Name</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {grouped[at].map((p) => (
                  <tr key={p.id}>
                    <td className="mono">v{p.version}</td>
                    <td className="mono">{p.name}</td>
                    <td>
                      {p.is_active ? (
                        <span className="badge approved">active</span>
                      ) : p.deactivated_at ? (
                        <span className="badge rejected">deactivated</span>
                      ) : (
                        <span className="badge pending">draft</span>
                      )}
                    </td>
                    <td className="muted mono">{new Date(p.created_at).toLocaleString()}</td>
                    <td><Link href={`/policies/${p.id}`}>open →</Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
    </div>
  );
}
