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
