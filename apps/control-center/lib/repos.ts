/**
 * Server-side client for the `/v1/repos` endpoints (see
 * services/supervisor_api/src/supervisor_api/routes/repos.py).
 */
import { buildToken } from "@runtime-supervisor/client";
import type { ScanCombo, ScanFinding } from "@/lib/scans";

const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8000";
const APP_ID = process.env.SUPERVISOR_APP_ID;
const SECRET = process.env.SUPERVISOR_SECRET;

export type RepoModeCounts = {
  money: number;
  real_world_actions: number;
  customer_data: number;
  business_data: number;
  llm: number;
  general: number;
};

export type RepoOverview = {
  repo_id: string;
  github_url: string;
  latest_scan_id: string | null;
  latest_scan_at: string | null;
  latest_scan_seconds: number | null;
  scan_count: number;
  total_findings: number;
  high_findings: number;
  priority_count: number;
  critical_combos: number;
  risk_shape: RepoModeCounts;
  repo_summary: Record<string, unknown> | null;
  mode: "shadow" | "sample" | "enforce" | null;
};

export type RepoScanHistoryItem = {
  scan_id: string;
  ref: string | null;
  status: string;
  total_findings: number;
  priority_count: number;
  high_findings: number;
  completed_at: string;
  new_high: number | null;
  fixed: number | null;
};

async function authHeaders(): Promise<Record<string, string>> {
  if (!APP_ID || !SECRET) return {};
  const token = await buildToken(APP_ID, ["*"], SECRET, 300);
  return { authorization: `Bearer ${token}` };
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    headers: await authHeaders(),
    cache: "no-store",
  });
  const body = await res.text();
  if (!res.ok) {
    throw Object.assign(new Error(body || res.statusText), { status: res.status });
  }
  return JSON.parse(body) as T;
}

export function getRepoByUrl(github_url: string): Promise<RepoOverview> {
  return get<RepoOverview>(`/v1/repos/by-url?github_url=${encodeURIComponent(github_url)}`);
}

export function getRepo(repo_id: string): Promise<RepoOverview> {
  return get<RepoOverview>(`/v1/repos/${encodeURIComponent(repo_id)}`);
}

export function getRepoFindings(
  repo_id: string,
  opts: { tier?: string; confidence?: "low" | "medium" | "high"; limit?: number } = {},
): Promise<ScanFinding[]> {
  const params = new URLSearchParams();
  if (opts.tier) params.set("tier", opts.tier);
  if (opts.confidence) params.set("confidence", opts.confidence);
  if (opts.limit) params.set("limit", String(opts.limit));
  const qs = params.toString();
  return get<ScanFinding[]>(`/v1/repos/${encodeURIComponent(repo_id)}/findings${qs ? `?${qs}` : ""}`);
}

export function getRepoCombos(repo_id: string): Promise<ScanCombo[]> {
  return get<ScanCombo[]>(`/v1/repos/${encodeURIComponent(repo_id)}/combos`);
}

export function getRepoHistory(repo_id: string): Promise<RepoScanHistoryItem[]> {
  return get<RepoScanHistoryItem[]>(`/v1/repos/${encodeURIComponent(repo_id)}/scans`);
}
