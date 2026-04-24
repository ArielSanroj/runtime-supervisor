import Link from "next/link";
import { policiesApi } from "@/lib/policies";
import DiffPanel from "./DiffPanel";
import PolicyActions from "./PolicyActions";
import PolicyHumanView from "./PolicyHumanView";
import ReplayPanel from "./ReplayPanel";
import TestPanel from "./TestPanel";

export const dynamic = "force-dynamic";

const SAMPLE_PAYLOADS: Record<string, string> = {
  refund: JSON.stringify(
    { amount: 50, currency: "USD", customer_id: "c_test", customer_age_days: 400, refund_velocity_24h: 0, reason: "defective" },
    null,
    2,
  ),
  payment: JSON.stringify(
    { amount: 500, currency: "USD", vendor_id: "v_test", vendor_first_seen_days: 400, approval_chain: ["cfo"], bank_account_changed: false, beneficiary_country: "US" },
    null,
    2,
  ),
};

export default async function PolicyDetail({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ tested?: string }>;
}) {
  const { id } = await params;
  const sp = await searchParams;
  const policy = await policiesApi.get(id);
  const allSameType = await policiesApi.list(policy.action_type).catch(() => []);
  const siblings = allSameType
    .filter((p) => p.id !== policy.id)
    .sort((a, b) => b.version - a.version)
    .map((p) => ({ id: p.id, version: p.version, name: p.name, is_active: p.is_active }));

  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
        <h1 style={{ margin: 0 }}>
          {policy.name} <span className="muted mono" style={{ fontSize: 14 }}>v{policy.version}</span>
        </h1>
        <div className="row" style={{ gap: 8 }}>
          {policy.is_active ? (
            <span className="badge approved">active</span>
          ) : policy.deactivated_at ? (
            <span className="badge rejected">deactivated</span>
          ) : (
            <span className="badge pending">draft</span>
          )}
        </div>
      </div>

      <div className="row" style={{ gap: 12, marginBottom: 16 }}>
        <span className="muted mono">{policy.action_type}</span>
        <span className="muted mono">id {policy.id}</span>
        <span className="muted mono">created {new Date(policy.created_at).toLocaleString()}</span>
      </div>

      {sp.tested === "1" && (
        <div className="card" style={{ marginBottom: 16 }}>
          <strong>Draft created and tested.</strong>
          <p className="muted" style={{ marginTop: 4 }}>
            If the result looks correct, press <em>Promote</em> to make this the active policy for <code>{policy.action_type}</code>.
          </p>
        </div>
      )}

      <PolicyHumanView yamlSource={policy.yaml_source} />

      <div className="grid cols-2">
        <div className="card">
          <h2>YAML source</h2>
          <pre style={{ maxHeight: 500 }}>{policy.yaml_source}</pre>
          <div style={{ marginTop: 12 }}>
            <Link href="/policies/new">+ Clone as new version</Link>
          </div>
        </div>

        <div className="card">
          <h2>Actions</h2>
          <PolicyActions id={policy.id} isActive={policy.is_active} deactivated={Boolean(policy.deactivated_at)} />

          <h2 style={{ marginTop: 24 }}>Test against payload</h2>
          <TestPanel id={policy.id} samplePayload={SAMPLE_PAYLOADS[policy.action_type] ?? "{}"} />
        </div>
      </div>

      <h2>Diff against another version</h2>
      <div className="card">
        <DiffPanel id={policy.id} siblings={siblings} />
      </div>

      <h2>Replay against recent actions</h2>
      <div className="card">
        <ReplayPanel id={policy.id} />
      </div>
    </div>
  );
}
