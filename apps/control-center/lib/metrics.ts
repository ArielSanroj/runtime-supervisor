const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8000";
const APP_ID = process.env.SUPERVISOR_APP_ID;
const SECRET = process.env.SUPERVISOR_SECRET;

export type MetricsSummary = {
  window: string;
  since: string;
  actions_total: number;
  decisions: { allow: number; deny: number; review: number };
  threats: {
    total: number;
    critical: number;
    warn: number;
    info: number;
    top_detectors: Array<{ detector_id: string; count: number }>;
  };
  reviews: { pending: number; approved: number; rejected: number; oldest_pending_age_minutes: number | null };
  executions: { success: number; failed: number; pending: number; success_rate: number | null; total: number };
  active_integrations: number;
  active_policies_by_type: Record<string, number>;
  volume_by_action_type: Record<string, number>;
};

export async function getMetrics(window: "24h" | "7d" | "30d" = "24h"): Promise<MetricsSummary> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (APP_ID && SECRET) {
    const { buildToken } = await import("@runtime-supervisor/client");
    headers.authorization = `Bearer ${await buildToken(APP_ID, ["*"], SECRET, 300)}`;
  }
  const r = await fetch(`${API}/v1/metrics/summary?window=${window}`, { headers, cache: "no-store" });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}: ${await r.text()}`);
  return r.json();
}

export type EnforcementReadiness = {
  window: string;
  since: string; // ISO timestamp — start of the window
  total_evaluations: number;
  shadow_evaluations: number;
  enforced_evaluations: number;
  would_block_in_shadow: number;
  actually_blocked: number;
  reviews: { pending: number; approved: number; rejected: number };
  blocks_later_approved_by_reviewer: number;
  // null when no review outcomes resolved yet — UI must guard against it
  // and treat the readiness as "needs more data" instead of computing 0%.
  estimated_false_positive_rate: number | null;
  latency_ms: { p50: number; p95: number; p99: number; samples: number };
};

/**
 * Pull shadow-vs-enforce telemetry for the rollout nudge. Used by the
 * dashboard's <EnforcementReadiness> component to decide whether to
 * recommend flipping `SUPERVISOR_ENFORCEMENT_MODE` from shadow to enforce.
 *
 * The endpoint is tenant-scoped (the BFF authenticates via APP_ID/SECRET).
 * For a per-app readout the caller would extend the route, but right now
 * one tenant === one app for the cliocsbot deployment.
 */
export async function getEnforcementReadiness(
  window: "24h" | "7d" | "30d" = "7d",
): Promise<EnforcementReadiness> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (APP_ID && SECRET) {
    const { buildToken } = await import("@runtime-supervisor/client");
    headers.authorization = `Bearer ${await buildToken(APP_ID, ["*"], SECRET, 300)}`;
  }
  const r = await fetch(`${API}/v1/metrics/enforcement?window=${window}`, {
    headers,
    cache: "no-store",
  });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}: ${await r.text()}`);
  return r.json();
}
