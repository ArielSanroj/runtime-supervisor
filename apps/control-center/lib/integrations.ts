const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8000";
const ADMIN_TOKEN = process.env.SUPERVISOR_ADMIN_TOKEN ?? "";

export type Integration = {
  id: string;
  name: string;
  scopes: string[];
  active: boolean;
  created_at: string;
  revoked_at: string | null;
  execute_url: string | null;
  execute_method: string;
  tenant_id: string | null;
};

export type IntegrationCreated = Integration & { shared_secret: string };

export type WebhookSubscription = {
  id: string;
  integration_id: string;
  url: string;
  events: string[];
  active: boolean;
  created_at: string;
};

export type WebhookDelivery = {
  id: number;
  subscription_id: string;
  event_type: string;
  status_code: number | null;
  error: string | null;
  attempts: number;
  delivered_at: string | null;
  created_at: string;
};

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      "x-admin-token": ADMIN_TOKEN,
      ...(init?.headers ?? {}),
    },
    cache: "no-store",
  });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}: ${await r.text()}`);
  if (r.status === 204) return undefined as T;
  return r.json() as Promise<T>;
}

export type ActionExecution = {
  id: number;
  action_id: string;
  integration_id: string | null;
  url: string;
  method: string;
  status_code: number | null;
  error: string | null;
  attempts: number;
  state: "pending" | "success" | "failed";
  triggered_by: "allow" | "review";
  queued_at: string;
  executed_at: string | null;
};

export const integrationsApi = {
  listExecutions: (id: string, limit = 50) =>
    req<ActionExecution[]>(`/v1/integrations/${id}/executions?limit=${limit}`),
  list: () => req<Integration[]>("/v1/integrations"),
  get: (id: string) => req<Integration>(`/v1/integrations/${id}`),
  create: (body: { name: string; scopes: string[] }) =>
    req<IntegrationCreated>("/v1/integrations", { method: "POST", body: JSON.stringify(body) }),
  rotate: (id: string) => req<IntegrationCreated>(`/v1/integrations/${id}/rotate-secret`, { method: "POST" }),
  revoke: (id: string) => req<Integration>(`/v1/integrations/${id}/revoke`, { method: "POST" }),
  setExecuteConfig: (id: string, body: { url: string | null; method: "POST" | "PUT" | "PATCH" }) =>
    req<Integration>(`/v1/integrations/${id}/execute-config`, { method: "PUT", body: JSON.stringify(body) }),
  listWebhooks: (id: string) => req<WebhookSubscription[]>(`/v1/integrations/${id}/webhooks`),
  addWebhook: (id: string, body: { url: string; events: string[] }) =>
    req<WebhookSubscription>(`/v1/integrations/${id}/webhooks`, { method: "POST", body: JSON.stringify(body) }),
  deleteWebhook: (id: string, subId: string) =>
    req<void>(`/v1/integrations/${id}/webhooks/${subId}`, { method: "DELETE" }),
};

export function adminTokenConfigured(): boolean {
  return Boolean(ADMIN_TOKEN);
}
