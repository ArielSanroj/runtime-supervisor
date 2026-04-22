const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8000";
const ADMIN_TOKEN = process.env.SUPERVISOR_ADMIN_TOKEN ?? "";

export type Tenant = {
  id: string;
  name: string;
  active: boolean;
  created_at: string;
};

async function req<T>(path: string): Promise<T> {
  const r = await fetch(`${API}${path}`, {
    headers: {
      "content-type": "application/json",
      "x-admin-token": ADMIN_TOKEN,
    },
    cache: "no-store",
  });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}: ${await r.text()}`);
  return r.json() as Promise<T>;
}

export const tenantsApi = {
  list: () => req<Tenant[]>("/v1/tenants"),
  get: (id: string) => req<Tenant>(`/v1/tenants/${id}`),
};

/** Admin-token presence gate for tenant-aware pages (same pattern as policies/integrations). */
export function adminTokenConfigured(): boolean {
  return ADMIN_TOKEN.length > 0;
}
