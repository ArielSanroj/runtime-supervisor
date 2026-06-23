import { getSession } from "@/lib/session";
import {
  superloopApi,
  type Claim,
  type QueueItem,
  type RegistryProduct,
} from "@/lib/superloop";
import { ResolveButtons, RunControls } from "./SuperloopActions";

export const dynamic = "force-dynamic";

const LABEL_TONE: Record<Claim["etiqueta"], string> = {
  HECHO: "text-emerald-400",
  INFERENCIA: "text-sky-400",
  SUPUESTO: "text-amber-400",
  PREGUNTA: "text-zinc-400",
};

const POSTURE_TONE: Record<string, string> = {
  alta_oportunidad: "text-amber-400",
  defender: "text-red-400",
  reactivar: "text-sky-400",
  optimizar: "text-emerald-400",
  cerrar: "text-zinc-500",
  desconocido: "text-zinc-500",
};

function nivelLabel(n: number | null): string {
  return ["read-only", "draft", "internal write", "external action", "business-critical"][n ?? 0] ?? `L${n}`;
}

function kindBadge(kind: string) {
  return (
    <span className="rounded border border-zinc-700 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-zinc-400">
      {kind}
    </span>
  );
}

export default async function SuperloopPage() {
  const session = await getSession();
  const approver = session?.user?.email ?? "anonymous";

  let products: RegistryProduct[] = [];
  let queue: QueueItem[] = [];
  let error: string | null = null;
  try {
    [{ products }, { queue }] = await Promise.all([
      superloopApi.getRegistry(),
      superloopApi.getQueue(),
    ]);
  } catch (e) {
    error = (e as Error).message;
  }

  return (
    <div className="mx-auto max-w-7xl px-6 py-8 text-zinc-100">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-mono text-xl font-semibold">
            <span className="text-emerald-400">$</span> superloop
          </h1>
          <p className="mt-1 max-w-2xl text-sm text-zinc-400">
            A supervised loop that watches each repo and supervisor, proposes the next
            guard to add, and waits for your approval before anything changes. Nothing
            with blast radius runs on its own.
          </p>
        </div>
        <RunControls />
      </div>

      {error && (
        <p className="mb-6 rounded border border-red-900 bg-red-950/40 px-4 py-3 font-mono text-sm text-red-300">
          Could not reach the supervisor API: {error}
        </p>
      )}

      {/* Approval queue (R1) */}
      <section className="mb-10">
        <h2 className="mb-3 font-mono text-sm uppercase tracking-wide text-zinc-400">
          Approval queue · {queue.length} pending
        </h2>
        {queue.length === 0 ? (
          <p className="rounded border border-zinc-800 bg-zinc-950 px-4 py-6 text-sm text-zinc-500">
            Nothing waiting on you. Run the loop to surface the next guard worth adding.
          </p>
        ) : (
          <div className="grid gap-4 lg:grid-cols-2">
            {queue.map((item) => {
              const c = item.business_card;
              const p = item.evidence_pack;
              if (!c) return null;
              return (
                <article
                  key={item.decision_id}
                  className="rounded-lg border border-zinc-800 bg-zinc-950 p-4"
                >
                  <div className="mb-2 flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2 font-mono text-sm">
                      <span className="font-semibold text-zinc-100">{c.producto}</span>
                      {kindBadge(c.kind)}
                    </div>
                    <span className="rounded bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] uppercase text-amber-400">
                      {nivelLabel(c.nivel_autonomia)} · needs approval
                    </span>
                  </div>
                  <p className="mb-3 text-sm text-zinc-200">{c.decision_recomendada}</p>

                  {p && (
                    <>
                      <div className="mb-3 overflow-hidden rounded border border-zinc-800">
                        <table className="w-full text-left text-xs">
                          <tbody>
                            {p.afirmaciones.slice(0, 6).map((a, i) => (
                              <tr key={i} className="border-b border-zinc-900 last:border-0">
                                <td className={`w-24 px-2 py-1 font-mono ${LABEL_TONE[a.etiqueta]}`}>
                                  {a.etiqueta}
                                </td>
                                <td className="px-2 py-1 text-zinc-300">{a.texto}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                      <dl className="mb-3 grid grid-cols-1 gap-1 text-xs text-zinc-400 sm:grid-cols-2">
                        <div><span className="text-zinc-500">Hypothesis:</span> {p.hipotesis}</div>
                        <div><span className="text-zinc-500">Success:</span> {p.plan_de_accion.criterio_exito}</div>
                        <div><span className="text-zinc-500">Metric:</span> {p.plan_de_accion.metrica_objetivo}</div>
                        <div><span className="text-zinc-500">Window:</span> {p.plan_de_accion.ventana_medicion}</div>
                      </dl>
                    </>
                  )}
                  <ResolveButtons decisionId={item.decision_id} approver={approver} />
                </article>
              );
            })}
          </div>
        )}
      </section>

      {/* Registro Canónico (R4) */}
      <section>
        <h2 className="mb-3 font-mono text-sm uppercase tracking-wide text-zinc-400">
          Canonical registry · {products.length} unit(s)
        </h2>
        {products.length === 0 ? (
          <p className="rounded border border-zinc-800 bg-zinc-950 px-4 py-6 text-sm text-zinc-500">
            No units observed yet. Scan a repo or send supervised actions, then run the loop.
          </p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-zinc-800">
            <table className="w-full text-left text-sm">
              <thead className="bg-zinc-900/60 font-mono text-xs uppercase tracking-wide text-zinc-500">
                <tr>
                  <th className="px-3 py-2">Unit</th>
                  <th className="px-3 py-2">Usage</th>
                  <th className="px-3 py-2">Risk posture</th>
                  <th className="px-3 py-2">Confidence</th>
                  <th className="px-3 py-2">Next best action</th>
                  <th className="px-3 py-2">Approval</th>
                </tr>
              </thead>
              <tbody className="font-mono text-xs">
                {products.map((p) => (
                  <tr key={p.producto_id} className="border-t border-zinc-900">
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-2">
                        <span className="text-zinc-200">{p.nombre}</span>
                        {kindBadge(p.kind)}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-zinc-300">{p.estado_operativo ?? "—"}</td>
                    <td className={`px-3 py-2 ${POSTURE_TONE[p.estado_comercial ?? "desconocido"] ?? "text-zinc-300"}`}>
                      {p.estado_comercial ?? "—"}
                    </td>
                    <td className="px-3 py-2 text-zinc-400">
                      {p.confianza_estado != null ? p.confianza_estado.toFixed(2) : "—"}
                    </td>
                    <td className="max-w-md px-3 py-2 text-zinc-300">{p.proxima_mejor_accion ?? "—"}</td>
                    <td className="px-3 py-2 text-zinc-400">{p.estado_aprobacion}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
