import { getSession } from "@/lib/session";
import { buildToken } from "@runtime-supervisor/client";
import InviteForm from "./InviteForm";

export const dynamic = "force-dynamic";

const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8099";
const APP_ID = process.env.SUPERVISOR_APP_ID;
const SECRET = process.env.SUPERVISOR_SECRET;

type Member = {
  id: string;
  email: string;
  role: string;
  tenant_id: string | null;
  active: boolean;
  created_at: string;
};

async function fetchMembers(tenantId: string): Promise<Member[]> {
  const headers: Record<string, string> = {};
  if (APP_ID && SECRET) {
    const token = await buildToken(APP_ID, ["*"], SECRET, 300);
    headers.authorization = `Bearer ${token}`;
  }
  try {
    const r = await fetch(
      `${API}/v1/team/members?tenant_id=${encodeURIComponent(tenantId)}`,
      { headers, cache: "no-store" },
    );
    if (!r.ok) return [];
    return (await r.json()) as Member[];
  } catch {
    return [];
  }
}

export default async function TeamPage() {
  const session = await getSession();
  if (!session) {
    return (
      <div style={{ padding: 24 }}>
        <h1>Team</h1>
        <p className="muted">Sign in to manage team members.</p>
      </div>
    );
  }
  const tenantId = session.user.tenant_id;
  if (!tenantId) {
    return (
      <div style={{ padding: 24 }}>
        <h1>Team</h1>
        <p className="muted">Your account isn&apos;t linked to a workspace.</p>
      </div>
    );
  }
  const members = await fetchMembers(tenantId);

  return (
    <div style={{ padding: 24 }}>
      <div className="row" style={{ alignItems: "baseline", gap: 12 }}>
        <h1 style={{ margin: 0 }}>Team</h1>
        <span className="muted mono" style={{ fontSize: 12 }}>
          {members.length} member{members.length === 1 ? "" : "s"}
        </span>
      </div>
      <p className="muted" style={{ marginTop: 8 }}>
        Everyone on your workspace sees the same fix queue, review queue, and dashboard.
      </p>

      <section style={{ marginTop: 24 }}>
        <InviteForm />
      </section>

      <section style={{ marginTop: 32 }}>
        <h2 style={{ marginTop: 0, fontSize: 18 }}>Members</h2>
        {members.length === 0 ? (
          <p className="muted">No members yet — invite someone above.</p>
        ) : (
          <div className="card" style={{ padding: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Joined</th>
                </tr>
              </thead>
              <tbody>
                {members.map((m) => (
                  <tr key={m.id}>
                    <td className="mono">{m.email}</td>
                    <td className="mono muted">{m.role}</td>
                    <td>
                      <span className={`badge ${m.active ? "approved" : "pending"}`}>
                        {m.active ? "active" : "inactive"}
                      </span>
                    </td>
                    <td className="muted mono" style={{ fontSize: 12 }}>
                      {new Date(m.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <details className="muted" style={{ marginTop: 32, fontSize: 13 }}>
        <summary className="cursor-pointer">how invites work</summary>
        <div style={{ marginTop: 8, paddingLeft: 16 }}>
          <p>1. You enter their email + role.</p>
          <p>2. We email them a one-time magic link.</p>
          <p>3. They click → land in this dashboard, sharing your fix queue + reviews + scans.</p>
          <p>4. No passwords. Sessions last 8h, then they re-magic-link.</p>
        </div>
      </details>
    </div>
  );
}
