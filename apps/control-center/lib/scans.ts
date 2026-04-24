/**
 * Server-side client for the public `/v1/scans` endpoint.
 *
 * The endpoint is public (no JWT required), but we still sign with the
 * internal APP_ID/SECRET when available — consistent with the rest of the
 * BFF and lets us add tenant-scoped scans later without changing the
 * frontend.
 */
import { buildToken } from "@runtime-supervisor/client";

const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8000";
const APP_ID = process.env.SUPERVISOR_APP_ID;
const SECRET = process.env.SUPERVISOR_SECRET;

export type ScanStatus = "queued" | "scanning" | "done" | "error";

export type ScanFinding = {
  scanner: string;
  file: string;
  line: number;
  snippet: string;
  suggested_action_type: string;
  confidence: "low" | "medium" | "high";
  rationale: string;
  extra: Record<string, unknown>;
  tier: string | null;
};

export type RepoSummary = {
  frameworks: string[];
  http_routes: number;
  payment_integrations: Record<string, string[]>;
  llm_providers: string[];
  real_world_actions: Record<string, string[]>;
  agent_chokepoints: { file: string; line: number; kind: string; label: string }[];
  agent_tools: string[];
  mcp_tools?: string[];
  db_tables_touched: string[];
  sensitive_tables: string[];
  scheduled_jobs: number;
  total_findings: number;
  one_liner: string;
  // "mcp-server" | "mcp-server+langchain" | "langchain-agent" | null
  repo_type?: string | null;
};

export type ScanResponse = {
  scan_id: string;
  status: ScanStatus;
  github_url?: string | null;
  ref?: string | null;
  error?: string | null;
  elapsed_ms?: number | null;
  repo_summary?: RepoSummary | null;
  findings?: ScanFinding[] | null;
  findings_truncated: boolean;
  created_at?: string | null;
  completed_at?: string | null;
};

async function authHeaders(): Promise<Record<string, string>> {
  if (!APP_ID || !SECRET) return {};
  const token = await buildToken(APP_ID, ["*"], SECRET, 300);
  return { authorization: `Bearer ${token}` };
}

export async function createScan(github_url: string, ref?: string): Promise<ScanResponse> {
  const res = await fetch(`${API}/v1/scans`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(await authHeaders()) },
    body: JSON.stringify({ github_url, ref }),
    cache: "no-store",
  });
  const body = await res.text();
  if (!res.ok) {
    throw Object.assign(new Error(body || res.statusText), { status: res.status });
  }
  return JSON.parse(body) as ScanResponse;
}

export async function getScan(scan_id: string): Promise<ScanResponse> {
  const res = await fetch(`${API}/v1/scans/${encodeURIComponent(scan_id)}`, {
    headers: await authHeaders(),
    cache: "no-store",
  });
  const body = await res.text();
  if (!res.ok) {
    throw Object.assign(new Error(body || res.statusText), { status: res.status });
  }
  return JSON.parse(body) as ScanResponse;
}

export type ScanSummary = {
  id: string;
  repo_url: string;
  ref: string | null;
  total_findings: number;
  priority_count: number;
  scan_seconds: number | null;
  status: "done" | "error";
  created_at: string;
};

export async function listScans(tenantId?: string | null, limit = 20): Promise<ScanSummary[]> {
  const params = new URLSearchParams();
  if (tenantId) params.set("tenant_id", tenantId);
  params.set("limit", String(limit));
  const res = await fetch(`${API}/v1/scans?${params}`, {
    headers: await authHeaders(),
    cache: "no-store",
  });
  if (!res.ok) {
    throw Object.assign(new Error(await res.text()), { status: res.status });
  }
  return (await res.json()) as ScanSummary[];
}
