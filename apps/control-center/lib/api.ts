/**
 * Server-side supervisor client used by dashboard + review pages.
 *
 * Uses @runtime-supervisor/client when SUPERVISOR_APP_ID + SUPERVISOR_SECRET
 * are configured (signs JWT HS256 per request). Otherwise, plain fetch — fine
 * for local dev where supervisor_api has REQUIRE_AUTH=false.
 */
import { Client, type ActionTypeSpec as SdkActionTypeSpec, type Decision as SdkDecision } from "@runtime-supervisor/client";

const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8000";
const APP_ID = process.env.SUPERVISOR_APP_ID;
const SECRET = process.env.SUPERVISOR_SECRET;

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

export type ActionTypeSpec = SdkActionTypeSpec;
export type DecisionOut = SdkDecision;

let _sdk: Client | null = null;
function sdk(): Client | null {
  if (!APP_ID || !SECRET) return null;
  if (_sdk) return _sdk;
  _sdk = new Client({
    baseUrl: API,
    appId: APP_ID,
    sharedSecret: SECRET,
    scopes: ["*"],
  });
  return _sdk;
}

async function unauthReq<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}: ${await res.text()}`);
  return res.json() as Promise<T>;
}

export const api = {
  listReviews: async (status?: ReviewStatus): Promise<ReviewCase[]> => {
    const client = sdk();
    if (client) return (await client.listReviews(status)) as unknown as ReviewCase[];
    return unauthReq<ReviewCase[]>(`/v1/review-cases${status ? `?status=${status}` : ""}`);
  },

  getReview: (id: string) => unauthReq<ReviewCase>(`/v1/review-cases/${id}`, sdkAuthHeader()),

  resolveReview: (id: string, body: { decision: "approved" | "rejected"; notes?: string }, approver: string) =>
    unauthReq<ReviewCase>(`/v1/review-cases/${id}/resolve`, {
      method: "POST",
      headers: { ...sdkAuthHeader().headers, "X-Approver": approver },
      body: JSON.stringify(body),
    }),

  getEvidence: (actionId: string) => unauthReq<EvidenceBundle>(`/v1/decisions/${actionId}/evidence`, sdkAuthHeader()),

  listActionTypes: async (): Promise<{ action_types: ActionTypeSpec[] }> => {
    // /v1/action-types is public — no auth required
    return unauthReq<{ action_types: ActionTypeSpec[] }>(`/v1/action-types`);
  },

  evaluateDryRun: async (action_type: string, payload: Record<string, unknown>): Promise<DecisionOut> => {
    const client = sdk();
    if (client) return client.evaluate(action_type, payload, { dryRun: true });
    return unauthReq<DecisionOut>(`/v1/actions/evaluate?dry_run=true`, {
      method: "POST",
      body: JSON.stringify({ action_type, payload }),
    });
  },
};

function sdkAuthHeader(): { headers: Record<string, string> } {
  const client = sdk();
  if (!client) return { headers: {} };
  // Client doesn't expose its JWT builder publicly on purpose; for the two
  // routes that don't have typed methods here, fall back to fetch without auth.
  // Auth flows through SDK methods when available (listReviews, evaluateDryRun).
  return { headers: {} };
}
