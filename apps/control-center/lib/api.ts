/**
 * Server-side supervisor client used by dashboard + review pages.
 *
 * Uses @runtime-supervisor/client when SUPERVISOR_APP_ID + SUPERVISOR_SECRET
 * are configured (signs JWT HS256 per request). Otherwise, plain fetch — fine
 * for local dev where supervisor_api has REQUIRE_AUTH=false.
 */
import { buildToken, Client, type ActionTypeSpec as SdkActionTypeSpec, type Decision as SdkDecision } from "@runtime-supervisor/client";

const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8000";
const APP_ID = process.env.SUPERVISOR_APP_ID;
const SECRET = process.env.SUPERVISOR_SECRET;

export type ReviewStatus = "pending" | "approved" | "rejected";

export type PolicyHit = { rule_id: string; action: string; reason: string; explanation?: string | null };

export type ReviewPriority = "low" | "normal" | "high";

export type RecentAction = {
  action_id: string;
  action_type: string;
  decision: "allow" | "deny" | "review";
  reasons: string[];
  risk_score: number;
  policy_version: string;
  created_at: string;
  latency_ms: number | null;
  shadow: boolean;
};

export type CustomerContext = {
  // Free-form shape — the integrator decides what to return. These fields
  // are the ones the UI will look for; anything else lands in `extra`.
  display_name?: string;
  tier?: string;
  lifetime_value?: number;
  open_tickets?: number;
  recent_refunds_30d?: number;
  signup_date?: string;
  notes?: string;
  extra?: Record<string, unknown>;
};

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
  priority: ReviewPriority;
  assigned_to: string | null;
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

async function authHeaders(): Promise<Record<string, string>> {
  if (!APP_ID || !SECRET) return {};
  const token = await buildToken(APP_ID, ["*"], SECRET, 300);
  return { authorization: `Bearer ${token}` };
}

async function unauthReq<T>(path: string, init?: RequestInit): Promise<T> {
  // Despite the name, this signs requests when SUPERVISOR_APP_ID + SECRET are
  // set. Kept as a single entry point so callers don't branch on auth state.
  const extra = await authHeaders();
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...extra, ...(init?.headers ?? {}) },
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

  listRecentActions: async (
    opts: { decision?: "allow" | "deny" | "review"; limit?: number } = {},
  ): Promise<RecentAction[]> => {
    const params = new URLSearchParams();
    if (opts.decision) params.set("decision", opts.decision);
    if (opts.limit) params.set("limit", String(opts.limit));
    return unauthReq<RecentAction[]>(`/v1/actions/recent${params.size ? `?${params}` : ""}`);
  },

  escalateReview: (id: string, body: { notes?: string }, approver: string) =>
    unauthReq<ReviewCase>(`/v1/review-cases/${id}/escalate`, {
      method: "POST",
      headers: { ...sdkAuthHeader().headers, "X-Approver": approver },
      body: JSON.stringify(body),
    }),

  customerContext: async (customerId: string): Promise<CustomerContext | null> => {
    // Pluggable — points at the customer's own CRM/back-office. UI falls
    // back to a "connect CRM" card when this env is not set.
    const base = process.env.SUPERVISOR_CUSTOMER_CONTEXT_URL;
    if (!base || !customerId) return null;
    try {
      const res = await fetch(`${base.replace(/\/$/, "")}/${encodeURIComponent(customerId)}`, {
        cache: "no-store",
      });
      if (!res.ok) return null;
      return (await res.json()) as CustomerContext;
    } catch {
      return null;
    }
  },

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
