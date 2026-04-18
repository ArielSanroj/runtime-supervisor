const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8000";
const ADMIN_TOKEN = process.env.SUPERVISOR_ADMIN_TOKEN ?? "";

export type Policy = {
  id: string;
  action_type: string;
  name: string;
  version: number;
  yaml_source: string;
  is_active: boolean;
  created_by: string | null;
  created_at: string;
  deactivated_at: string | null;
};

export type PolicyTestResult = {
  decision: "allow" | "deny" | "review";
  hits: Array<{ rule_id: string; action: string; reason: string }>;
  reasons: string[];
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
  return r.json() as Promise<T>;
}

export const policiesApi = {
  list: (actionType?: string, activeOnly?: boolean) => {
    const params = new URLSearchParams();
    if (actionType) params.set("action_type", actionType);
    if (activeOnly) params.set("active_only", "true");
    const qs = params.toString();
    return req<Policy[]>(`/v1/policies${qs ? `?${qs}` : ""}`);
  },
  get: (id: string) => req<Policy>(`/v1/policies/${id}`),
  create: (body: { action_type: string; yaml_source: string; promote?: boolean }) =>
    req<Policy>("/v1/policies", { method: "POST", body: JSON.stringify(body) }),
  promote: (id: string) => req<Policy>(`/v1/policies/${id}/promote`, { method: "POST" }),
  deactivate: (id: string) => req<Policy>(`/v1/policies/${id}/deactivate`, { method: "POST" }),
  test: (id: string, payload: Record<string, unknown>) =>
    req<PolicyTestResult>(`/v1/policies/${id}/test`, {
      method: "POST",
      body: JSON.stringify({ payload }),
    }),
};

export function adminTokenConfigured(): boolean {
  return Boolean(ADMIN_TOKEN);
}
