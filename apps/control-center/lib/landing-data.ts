import { api, type ActionTypeSpec, type DecisionOut } from "./api";
import type { ThreatCatalogEntry } from "./threats";
import { threatsApi } from "./threats";

const FALLBACK: ActionTypeSpec[] = [
  {
    id: "refund",
    title: "Refund supervision",
    one_liner: "Stop risky refunds before money leaves the system.",
    status: "live",
    intercepted_signals: ["amount", "customer_age_days", "refund_velocity_24h", "reason"],
    sample_payload: null,
    policy_ref: "refund.base@v1",
  },
  {
    id: "payment",
    title: "Payment approvals",
    one_liner: "Enforce thresholds, approval chains, and anomaly detection on outgoing payments.",
    status: "planned",
    intercepted_signals: ["amount", "vendor_id", "bank_account", "approval_chain"],
    sample_payload: null,
    policy_ref: null,
  },
  {
    id: "account_change",
    title: "Account changes",
    one_liner: "Prevent unsafe updates to customer identity and profile data.",
    status: "planned",
    intercepted_signals: ["field_changed", "new_value_fingerprint", "actor_role"],
    sample_payload: null,
    policy_ref: null,
  },
  {
    id: "data_access",
    title: "Restricted data access",
    one_liner: "Block unauthorized use of sensitive data by agents and the tools they call.",
    status: "planned",
    intercepted_signals: ["dataset", "columns", "actor", "purpose"],
    sample_payload: null,
    policy_ref: null,
  },
];

export type LandingData = {
  actionTypes: ActionTypeSpec[];
  threatCatalog: ThreatCatalogEntry[];
  liveDemo: { spec: ActionTypeSpec; decision: DecisionOut } | null;
  sourcedFromApi: boolean;
};

export async function getLandingData(): Promise<LandingData> {
  try {
    const [{ action_types }, threatCatalog] = await Promise.all([
      api.listActionTypes(),
      threatsApi.catalog(),
    ]);
    const liveSpec = action_types.find((a) => a.status === "live" && a.sample_payload);
    let liveDemo = null;
    if (liveSpec && liveSpec.sample_payload) {
      try {
        const decision = await api.evaluateDryRun(liveSpec.id, liveSpec.sample_payload);
        liveDemo = { spec: liveSpec, decision };
      } catch {
        liveDemo = null;
      }
    }
    return { actionTypes: action_types, threatCatalog, liveDemo, sourcedFromApi: true };
  } catch {
    return { actionTypes: FALLBACK, threatCatalog: [], liveDemo: null, sourcedFromApi: false };
  }
}
