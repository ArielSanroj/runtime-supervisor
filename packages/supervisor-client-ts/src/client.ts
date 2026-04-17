import { buildToken } from "./jwt.js";

export type DecisionKind = "allow" | "deny" | "review";

export interface Decision {
  action_id: string;
  decision: DecisionKind;
  reasons: string[];
  risk_score: number;
  policy_version: string;
}

export interface ActionTypeSpec {
  id: string;
  title: string;
  one_liner: string;
  status: "live" | "planned";
  intercepted_signals: string[];
  sample_payload: Record<string, unknown> | null;
  policy_ref: string | null;
}

export class SupervisorError extends Error {
  constructor(public statusCode: number, public detail: string) {
    super(`${statusCode}: ${detail}`);
  }
}

export interface ClientOptions {
  baseUrl: string;
  appId: string;
  sharedSecret: string;
  scopes?: string[];
  tokenTtlSeconds?: number;
  fetchImpl?: typeof fetch;
}

export class Client {
  private baseUrl: string;
  private appId: string;
  private secret: string;
  private scopes: string[];
  private ttl: number;
  private fetchImpl: typeof fetch;

  constructor(opts: ClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.appId = opts.appId;
    this.secret = opts.sharedSecret;
    this.scopes = opts.scopes ?? ["*"];
    this.ttl = opts.tokenTtlSeconds ?? 300;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  private async headers(): Promise<Record<string, string>> {
    const token = await buildToken(this.appId, this.scopes, this.secret, this.ttl);
    return {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    };
  }

  private async req<T>(method: string, path: string, body?: unknown, extraHeaders: Record<string, string> = {}): Promise<T> {
    const r = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers: { ...(await this.headers()), ...extraHeaders },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!r.ok) {
      let detail = r.statusText;
      try {
        const j = (await r.json()) as { detail?: string };
        detail = j.detail ?? detail;
      } catch {
        /* ignore */
      }
      throw new SupervisorError(r.status, detail);
    }
    return (await r.json()) as T;
  }

  evaluate(actionType: string, payload: Record<string, unknown>, opts: { dryRun?: boolean } = {}): Promise<Decision> {
    const path = "/v1/actions/evaluate" + (opts.dryRun ? "?dry_run=true" : "");
    return this.req<Decision>("POST", path, { action_type: actionType, payload });
  }

  async listActionTypes(): Promise<ActionTypeSpec[]> {
    const data = await this.req<{ action_types: ActionTypeSpec[] }>("GET", "/v1/action-types");
    return data.action_types;
  }

  listReviews(status?: "pending" | "approved" | "rejected") {
    const q = status ? `?status=${status}` : "";
    return this.req<
      Array<{
        id: string;
        action_id: string;
        status: string;
        action_type: string;
        risk_score: number;
        created_at: string;
      }>
    >("GET", `/v1/review-cases${q}`);
  }

  resolveReview(
    id: string,
    body: { decision: "approved" | "rejected"; notes?: string },
    approver?: string,
  ) {
    const extra: Record<string, string> = approver ? { "x-approver": approver } : {};
    return this.req("POST", `/v1/review-cases/${id}/resolve`, body, extra);
  }

  getEvidence(actionId: string) {
    return this.req("GET", `/v1/decisions/${actionId}/evidence`);
  }
}
