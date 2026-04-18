const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8000";
const APP_ID = process.env.SUPERVISOR_APP_ID;
const SECRET = process.env.SUPERVISOR_SECRET;

export type ThreatLevel = "info" | "warn" | "critical";

export type ThreatSignal = {
  detector_id: string;
  owasp_ref: string;
  level: ThreatLevel;
  message: string;
  evidence: Record<string, unknown>;
};

export type ThreatAssessmentRow = {
  id: number;
  action_id: string | null;
  integration_id: string | null;
  detector_id: string;
  owasp_ref: string;
  level: ThreatLevel;
  signals: Array<{ message: string; evidence: Record<string, unknown> }>;
  created_at: string;
};

export type ThreatCatalogEntry = {
  id: string;
  title: string;
  owasp_ref: string;
  one_liner: string;
  severity: ThreatLevel;
  remediation: string;
  sample_attack: Record<string, unknown>;
};

export type SimulatedAttack = {
  threat_id: string;
  decision: {
    action_id: string;
    decision: "allow" | "deny" | "review";
    reasons: string[];
    risk_score: number;
    policy_version: string;
    threat_level: "none" | ThreatLevel;
    threats: ThreatSignal[];
  };
  threats: ThreatSignal[];
};

async function authedReq<T>(path: string): Promise<T> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (APP_ID && SECRET) {
    const { buildToken } = await import("@runtime-supervisor/client");
    headers.authorization = `Bearer ${await buildToken(APP_ID, ["*"], SECRET, 300)}`;
  }
  const r = await fetch(`${API}${path}`, { headers, cache: "no-store" });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}: ${await r.text()}`);
  return r.json() as Promise<T>;
}

export const threatsApi = {
  list: (limit = 50, level?: ThreatLevel) =>
    authedReq<ThreatAssessmentRow[]>(`/v1/threats?limit=${limit}${level ? `&level=${level}` : ""}`),
  get: (id: number) => authedReq<ThreatAssessmentRow>(`/v1/threats/${id}`),
  catalog: async (): Promise<ThreatCatalogEntry[]> => {
    const r = await fetch(`${API}/v1/threats/catalog`, { cache: "no-store" });
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    return r.json() as Promise<ThreatCatalogEntry[]>;
  },
};
