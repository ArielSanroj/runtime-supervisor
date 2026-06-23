/**
 * Server-side Superloop client for the ops dashboard.
 *
 * Reads the Registro Canónico + the human approval queue. Signs requests with
 * SUPERVISOR_APP_ID/SECRET when configured (same pattern as lib/metrics.ts);
 * falls back to plain fetch for local dev (REQUIRE_AUTH=false). Mutations
 * (run / approve / resume) happen client-side in SuperloopActions so they can
 * carry an X-Approver header and refresh the view — mirroring the review flow.
 */
const API = process.env.SUPERVISOR_API_URL ?? "http://localhost:8000";
const APP_ID = process.env.SUPERVISOR_APP_ID;
const SECRET = process.env.SUPERVISOR_SECRET;

export type Claim = { texto: string; etiqueta: "HECHO" | "INFERENCIA" | "SUPUESTO" | "PREGUNTA" };

export type BusinessCard = {
  producto: string;
  producto_id: string;
  kind: "repo" | "supervisor";
  estado_operativo: string | null;
  estado_comercial: string | null;
  confianza: number | null;
  problema_principal: string | null;
  metrica_principal: string | null;
  decision_recomendada: string | null;
  accion_tipo: string | null;
  riesgo: string | null;
  nivel_autonomia: number | null;
  requiere_aprobacion: boolean | null;
  proxima_accion: string | null;
  decision_id: string | null;
  estado_aprobacion: string | null;
  review_item_id: string | null;
};

export type EvidencePack = {
  resumen_ejecutivo: string;
  afirmaciones: Claim[];
  kpis: Record<string, unknown>;
  hipotesis: string | null;
  plan_de_accion: {
    metrica_objetivo: string | null;
    criterio_exito: string | null;
    ventana_medicion: string | null;
    accion_tipo: string | null;
  };
  siguiente_movimiento: string;
};

export type RegistryProduct = {
  producto_id: string;
  kind: "repo" | "supervisor";
  nombre: string;
  estado_operativo: string | null;
  estado_comercial: string | null;
  confianza_estado: number | null;
  metrica_principal: string | null;
  proxima_mejor_accion: string | null;
  estado_aprobacion: string;
  decision_recomendada_ref: string | null;
  updated_at: string | null;
};

export type QueueItem = {
  decision_id: string;
  producto_id: string;
  review_item_id: string | null;
  nivel_autonomia: number;
  business_card: BusinessCard | null;
  evidence_pack: EvidencePack | null;
};

async function authHeaders(): Promise<Record<string, string>> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (APP_ID && SECRET) {
    const { buildToken } = await import("@runtime-supervisor/client");
    headers.authorization = `Bearer ${await buildToken(APP_ID, ["*"], SECRET, 300)}`;
  }
  return headers;
}

async function get<T>(path: string): Promise<T> {
  const r = await fetch(`${API}${path}`, { headers: await authHeaders(), cache: "no-store" });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}: ${await r.text()}`);
  return r.json() as Promise<T>;
}

export const superloopApi = {
  getRegistry: () => get<{ products: RegistryProduct[] }>("/v1/superloop/registry"),
  getQueue: () => get<{ queue: QueueItem[] }>("/v1/superloop/queue"),
  getRuns: () => get<{ runs: Array<{ run_id: string; scope: string; count: number; created_at: string | null }> }>(
    "/v1/superloop/runs",
  ),
};
