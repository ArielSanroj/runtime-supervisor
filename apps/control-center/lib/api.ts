const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8000";

export type ReviewStatus = "pending" | "approved" | "rejected";

export type PolicyHit = { rule_id: string; action: string; reason: string };

export type ReviewCase = {
  id: string;
  action_id: string;
  status: ReviewStatus;
  action_type: string;
  action_payload: Record<string, unknown>;
  risk_score: number;
  policy_hits: PolicyHit[];
  created_at: string;
  resolved_at: string | null;
  approver: string | null;
  approver_notes: string | null;
};

export type EvidenceEvent = {
  seq: number;
  event_type: string;
  event_payload: Record<string, unknown>;
  prev_hash: string;
  hash: string;
  created_at: string;
};

export type EvidenceBundle = {
  action_id: string;
  action_type: string;
  status: string;
  events: EvidenceEvent[];
  chain_ok: boolean;
  broken_at_seq: number | null;
  bundle_hash: string;
  bundle_signature: string;
  exported_at: string;
};

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}: ${await res.text()}`);
  return res.json() as Promise<T>;
}

export type ActionTypeSpec = {
  id: string;
  title: string;
  one_liner: string;
  status: "live" | "planned";
  intercepted_signals: string[];
  sample_payload: Record<string, unknown> | null;
  policy_ref: string | null;
};

export type DecisionOut = {
  action_id: string;
  decision: "allow" | "deny" | "review";
  reasons: string[];
  risk_score: number;
  policy_version: string;
};

export const api = {
  listReviews: (status?: ReviewStatus) =>
    req<ReviewCase[]>(`/v1/review-cases${status ? `?status=${status}` : ""}`),
  getReview: (id: string) => req<ReviewCase>(`/v1/review-cases/${id}`),
  resolveReview: (id: string, body: { decision: "approved" | "rejected"; notes?: string }, approver: string) =>
    req<ReviewCase>(`/v1/review-cases/${id}/resolve`, {
      method: "POST",
      headers: { "X-Approver": approver },
      body: JSON.stringify(body),
    }),
  getEvidence: (actionId: string) => req<EvidenceBundle>(`/v1/decisions/${actionId}/evidence`),
  listActionTypes: () => req<{ action_types: ActionTypeSpec[] }>(`/v1/action-types`),
  evaluateDryRun: (action_type: string, payload: Record<string, unknown>) =>
    req<DecisionOut>(`/v1/actions/evaluate?dry_run=true`, {
      method: "POST",
      body: JSON.stringify({ action_type, payload }),
    }),
};
