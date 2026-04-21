import Link from "next/link";
import { api, type ReviewCase } from "@/lib/api";
import { AutoRefresh } from "./AutoRefresh";

export const dynamic = "force-dynamic";

function amount(payload: Record<string, unknown>) {
  const amt = payload["amount"];
  const cur = payload["currency"] ?? "";
  return typeof amt === "number" ? `${amt} ${cur}` : "—";
}

export default async function ReviewQueue({
  searchParams,
}: {
  searchParams: Promise<{ status?: string }>;
}) {
  const sp = await searchParams;
  const status = (sp.status ?? "pending") as "pending" | "approved" | "rejected";
  let cases: ReviewCase[] = [];
  let err: string | null = null;
  try {
    cases = await api.listReviews(status);
  } catch (e) {
    err = (e as Error).message;
  }

  return (
    <div>
      {/* Only poll the pending list — approved/rejected don't change often
          and operators browsing history don't need auto-refresh. */}
      <AutoRefresh intervalMs={5000} enabled={status === "pending"} />
      <h1>Review queue</h1>
      <div className="row" style={{ marginBottom: 16 }}>
        {(["pending", "approved", "rejected"] as const).map((s) => (
          <Link
            key={s}
            href={`/review?status=${s}`}
            className={`badge ${s}`}
            style={status === s ? { outline: "2px solid var(--accent)" } : undefined}
          >
            {s}
          </Link>
        ))}
      </div>
      {err && (
        <div className="card" style={{ borderColor: "var(--danger)", color: "var(--danger)" }}>
          {err}
        </div>
      )}
      {!err && cases.length === 0 && (
        <p className="muted">No {status} cases.</p>
      )}
      {cases.length > 0 && (
        <div className="card" style={{ padding: 0 }}>
          <table>
            <thead>
              <tr>
                <th>Created</th>
                <th>Action</th>
                <th>Amount</th>
                <th>Customer</th>
                <th>Risk</th>
                <th>Hits</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {cases.map((c) => (
                <tr key={c.id}>
                  <td className="mono muted">{new Date(c.created_at).toLocaleString()}</td>
                  <td>{c.action_type}</td>
                  <td>{amount(c.action_payload)}</td>
                  <td className="mono">{String(c.action_payload["customer_id"] ?? "—")}</td>
                  <td>{c.risk_score}</td>
                  <td className="mono">{c.policy_hits.map((h) => h.reason).join(", ") || "—"}</td>
                  <td><span className={`badge ${c.status}`}>{c.status}</span></td>
                  <td><Link href={`/review/${c.id}`}>open →</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
