import Link from "next/link";
import { api } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function Dashboard() {
  let pending = 0;
  let approved = 0;
  let rejected = 0;
  let err: string | null = null;
  try {
    const [p, a, r] = await Promise.all([
      api.listReviews("pending"),
      api.listReviews("approved"),
      api.listReviews("rejected"),
    ]);
    pending = p.length;
    approved = a.length;
    rejected = r.length;
  } catch (e) {
    err = (e as Error).message;
  }
  return (
    <div>
      <h1>Dashboard</h1>
      {err && (
        <div className="card" style={{ borderColor: "var(--danger)", color: "var(--danger)", marginBottom: 16 }}>
          Supervisor API unreachable: {err}
        </div>
      )}
      <div className="grid cols-3">
        <div className="card kpi">
          {pending} <span className="label">Pending review</span>
        </div>
        <div className="card kpi">
          {approved} <span className="label">Approved</span>
        </div>
        <div className="card kpi">
          {rejected} <span className="label">Rejected</span>
        </div>
      </div>
      <h2>Next step</h2>
      <p className="muted">
        Open the <Link href="/review">review queue</Link> to resolve pending cases.
      </p>
    </div>
  );
}
