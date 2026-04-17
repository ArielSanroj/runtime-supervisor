import Link from "next/link";
import { getLandingData } from "@/lib/landing-data";
import type { ActionTypeSpec, DecisionOut } from "@/lib/api";

export const revalidate = 300;

function formatMoney(v: unknown, currency: unknown): string {
  if (typeof v !== "number") return "—";
  const cur = typeof currency === "string" ? currency : "USD";
  try {
    return new Intl.NumberFormat("en-US", { style: "currency", currency: cur, maximumFractionDigits: 0 }).format(v);
  } catch {
    return `${v} ${cur}`;
  }
}

function decisionBadge(decision: DecisionOut["decision"]): { label: string; cls: string } {
  switch (decision) {
    case "allow":
      return { label: "Allowed automatically", cls: "bg-emerald-100 text-emerald-800" };
    case "deny":
      return { label: "Blocked before execution", cls: "bg-rose-100 text-rose-800" };
    case "review":
      return { label: "Human review required", cls: "bg-amber-100 text-amber-800" };
  }
}

function humanizeReason(r: string): string {
  return r.replace(/-/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

function humanizeSignal(s: string): string {
  return s.replace(/_/g, " ");
}

function LiveDemoCard({ data }: { data: { spec: ActionTypeSpec; decision: DecisionOut } | null }) {
  if (!data) {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="text-sm font-medium text-slate-500">Live decision preview</div>
        <div className="mt-2 text-slate-700">
          Supervisor API unreachable during build. Start it with{" "}
          <code className="rounded bg-slate-100 px-1.5 py-0.5 text-xs">uv run uvicorn supervisor_api.main:app</code> and rebuild.
        </div>
      </div>
    );
  }

  const { spec, decision } = data;
  const payload = spec.sample_payload ?? {};
  const badge = decisionBadge(decision.decision);

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-sm font-medium text-slate-500">Live decision · {spec.policy_ref}</div>
          <div className="mt-1 text-xl font-semibold">{spec.title}</div>
        </div>
        <span className={`rounded-full px-3 py-1 text-xs font-medium ${badge.cls}`}>{badge.label}</span>
      </div>
      <div className="mt-5 space-y-3 text-sm">
        <div className="flex items-center justify-between rounded-xl bg-slate-50 px-4 py-3">
          <span className="text-slate-600">Amount</span>
          <span className="font-medium">{formatMoney(payload["amount"], payload["currency"])}</span>
        </div>
        <div className="flex items-center justify-between rounded-xl bg-slate-50 px-4 py-3">
          <span className="text-slate-600">Customer age</span>
          <span className="font-medium">{String(payload["customer_age_days"] ?? "—")} days</span>
        </div>
        <div className="flex items-center justify-between rounded-xl bg-slate-50 px-4 py-3">
          <span className="text-slate-600">Refunds (24h)</span>
          <span className="font-medium">{String(payload["refund_velocity_24h"] ?? "—")}</span>
        </div>
        <div className="flex items-center justify-between rounded-xl bg-slate-50 px-4 py-3">
          <span className="text-slate-600">Risk score</span>
          <span className="font-medium">{decision.risk_score}</span>
        </div>
        <div className="flex items-center justify-between rounded-xl bg-slate-50 px-4 py-3">
          <span className="text-slate-600">Decision</span>
          <span className="font-medium text-slate-900 capitalize">{decision.decision}</span>
        </div>
      </div>
      <div className="mt-5 rounded-2xl border border-slate-200 p-4 text-sm text-slate-600">
        <div className="font-medium text-slate-700">Reasons returned by the supervisor</div>
        <ul className="mt-2 list-disc pl-5 space-y-1">
          {decision.reasons.map((r) => (
            <li key={r}>{humanizeReason(r)}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function StatusPill({ status }: { status: "live" | "planned" }) {
  return status === "live" ? (
    <span className="rounded-full bg-emerald-100 px-2.5 py-0.5 text-xs font-semibold text-emerald-800">Live</span>
  ) : (
    <span className="rounded-full bg-slate-200 px-2.5 py-0.5 text-xs font-medium text-slate-600">Planned</span>
  );
}

function UseCaseCard({ spec, dark = false }: { spec: ActionTypeSpec; dark?: boolean }) {
  const border = dark ? "border-slate-700" : "border-slate-200";
  const mutedText = dark ? "text-slate-300" : "text-slate-600";
  const subtle = dark ? "text-slate-400" : "text-slate-500";
  return (
    <div className={`rounded-3xl border ${border} p-6`}>
      <div className="flex items-start justify-between gap-3">
        <h3 className="text-xl font-semibold">{spec.title}</h3>
        <StatusPill status={spec.status} />
      </div>
      <p className={`mt-3 ${mutedText}`}>{spec.one_liner}</p>
      <div className={`mt-4 text-xs font-medium ${subtle}`}>Intercepted signals</div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {spec.intercepted_signals.map((s) => (
          <span key={s} className={`rounded-md px-2 py-0.5 text-xs ${dark ? "bg-slate-800 text-slate-200" : "bg-slate-100 text-slate-700"}`}>
            {humanizeSignal(s)}
          </span>
        ))}
      </div>
    </div>
  );
}

export default async function AgenticInternalControlsLanding() {
  const { actionTypes, liveDemo, sourcedFromApi } = await getLandingData();
  const live = actionTypes.filter((a) => a.status === "live");
  const planned = actionTypes.filter((a) => a.status === "planned");

  return (
    <div className="min-h-screen bg-white text-slate-900">
      <section className="border-b border-slate-200">
        <div className="mx-auto max-w-7xl px-6 py-6 flex items-center justify-between">
          <div className="font-semibold tracking-tight text-lg">Agentic Internal Controls</div>
          <div className="flex items-center gap-3">
            <Link href="#supervisors" className="rounded-2xl border border-slate-300 px-4 py-2 text-sm font-medium hover:bg-slate-50">
              Supervised actions
            </Link>
            <Link href="/dashboard" className="rounded-2xl bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800">
              Open console
            </Link>
          </div>
        </div>
      </section>

      <section className="mx-auto grid max-w-7xl gap-12 px-6 py-20 lg:grid-cols-2 lg:items-center">
        <div>
          <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-slate-200 px-3 py-1 text-xs font-medium text-slate-600">
            <span className={`h-1.5 w-1.5 rounded-full ${sourcedFromApi ? "bg-emerald-500" : "bg-slate-400"}`} />
            {sourcedFromApi ? "Live catalog from supervisor" : "Static catalog"}
          </div>
          <h1 className="max-w-2xl text-5xl font-semibold tracking-tight sm:text-6xl">
            Control the specific actions your AI agents take.
          </h1>
          <p className="mt-6 max-w-2xl text-lg leading-8 text-slate-600">
            Every agent action we supervise — refunds, payments, account changes, data access, tool calls, compliance decisions —
            runs through a policy + risk evaluation <em>before</em> it reaches your systems. The catalog below reflects what&apos;s
            actually implemented today, not a brochure.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link href="mailto:ariel@cliocircle.com?subject=Demo%20-%20Agentic%20Internal%20Controls" className="rounded-2xl bg-slate-900 px-5 py-3 text-sm font-medium text-white hover:bg-slate-800">
              Book a demo
            </Link>
            <Link href="#supervisors" className="rounded-2xl border border-slate-300 px-5 py-3 text-sm font-medium hover:bg-slate-50">
              See the catalog
            </Link>
          </div>
          <div className="mt-8 grid max-w-xl grid-cols-3 gap-4 text-sm text-slate-600">
            <div className="rounded-2xl border border-slate-200 p-4">
              <div className="text-2xl font-semibold text-slate-900">Allow</div>
              <div className="mt-1">Safe actions pass automatically</div>
            </div>
            <div className="rounded-2xl border border-slate-200 p-4">
              <div className="text-2xl font-semibold text-slate-900">Deny</div>
              <div className="mt-1">Unsafe actions stop before execution</div>
            </div>
            <div className="rounded-2xl border border-slate-200 p-4">
              <div className="text-2xl font-semibold text-slate-900">Review</div>
              <div className="mt-1">Escalated cases route to a human</div>
            </div>
          </div>
        </div>

        <div className="rounded-3xl border border-slate-200 bg-slate-50 p-6 shadow-sm">
          <LiveDemoCard data={liveDemo} />
        </div>
      </section>

      <section id="supervisors" className="border-y border-slate-200 bg-slate-50">
        <div className="mx-auto max-w-7xl px-6 py-16">
          <div className="max-w-3xl">
            <h2 className="text-3xl font-semibold tracking-tight">The agent actions we supervise</h2>
            <p className="mt-4 text-lg text-slate-600">
              This is the live catalog. <strong>Live</strong> means the supervisor is implemented, tested, and callable right now.
              <strong> Planned</strong> is on the roadmap — we won&apos;t pretend otherwise.
            </p>
          </div>

          {live.length > 0 && (
            <>
              <h3 className="mt-10 text-sm font-semibold tracking-wide text-emerald-700 uppercase">Live today</h3>
              <div className="mt-4 grid gap-6 md:grid-cols-2 xl:grid-cols-3">
                {live.map((spec) => (
                  <UseCaseCard key={spec.id} spec={spec} />
                ))}
              </div>
            </>
          )}

          {planned.length > 0 && (
            <>
              <h3 className="mt-10 text-sm font-semibold tracking-wide text-slate-500 uppercase">On the roadmap</h3>
              <div className="mt-4 grid gap-6 md:grid-cols-2 xl:grid-cols-3">
                {planned.map((spec) => (
                  <UseCaseCard key={spec.id} spec={spec} />
                ))}
              </div>
            </>
          )}
        </div>
      </section>

      <section id="how" className="mx-auto max-w-7xl px-6 py-20">
        <div className="max-w-3xl">
          <h2 className="text-3xl font-semibold tracking-tight">How a single action flows through the supervisor</h2>
          <p className="mt-4 text-lg text-slate-600">
            Every supervised action runs the same five steps. The only thing that changes per action type is the policy and the risk signals.
          </p>
        </div>
        <div className="mt-10 grid gap-6 md:grid-cols-5">
          {[
            ["1", "Agent proposes the action", "POST /v1/actions/evaluate with the proposed payload"],
            ["2", "Policy evaluates the action", "Declarative rules (YAML) on the payload — hard caps, forbidden combinations"],
            ["3", "Risk engine scores it", "Weighted signals: amount, velocity, actor tenure, anomaly flags"],
            ["4", "Decision: allow / deny / review", "Worst-of policy + risk threshold; review goes to the queue"],
            ["5", "Evidence is hashed & stored", "Append-only log with hash chain; exportable bundle for audit"],
          ].map(([num, title, detail]) => (
            <div key={num} className="rounded-3xl bg-white p-6 shadow-sm ring-1 ring-slate-200">
              <div className="text-3xl font-semibold">{num}</div>
              <div className="mt-3 font-medium text-slate-900">{title}</div>
              <div className="mt-2 text-sm text-slate-600">{detail}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="bg-slate-900 text-white">
        <div className="mx-auto max-w-7xl px-6 py-20">
          <div className="max-w-3xl">
            <h2 className="text-3xl font-semibold tracking-tight">Built for teams deploying AI in production</h2>
            <p className="mt-4 text-lg text-slate-300">
              The buyers care about risk. The operators care about speed. The same catalog serves both.
            </p>
          </div>
          <div className="mt-10 grid gap-6 lg:grid-cols-2">
            <div className="rounded-3xl border border-slate-700 p-6">
              <h3 className="text-xl font-semibold">Who buys it</h3>
              <ul className="mt-4 space-y-2 text-slate-300">
                <li>Chief Risk Officer · Chief Compliance Officer</li>
                <li>CFO · VP Finance</li>
                <li>CISO · CIO</li>
                <li>VP Customer Operations</li>
                <li>Head of AI Governance</li>
              </ul>
            </div>
            <div className="rounded-3xl border border-slate-700 p-6">
              <h3 className="text-xl font-semibold">Who uses it day to day</h3>
              <ul className="mt-4 space-y-2 text-slate-300">
                <li>Fraud ops</li>
                <li>Compliance ops</li>
                <li>Support operations</li>
                <li>Internal audit</li>
                <li>Security / platform teams</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-6 py-20">
        <div className="grid gap-10 lg:grid-cols-2 lg:items-center">
          <div>
            <h2 className="text-3xl font-semibold tracking-tight">Deploy AI agents without losing control.</h2>
            <p className="mt-4 text-lg text-slate-600">
              Start with one high-risk action type. Prove the ROI in one quarter. Expand the catalog as the product grows.
            </p>
          </div>
          <div className="flex flex-wrap gap-3 lg:justify-end">
            <Link href="mailto:ariel@cliocircle.com?subject=Demo%20-%20Agentic%20Internal%20Controls" className="rounded-2xl bg-slate-900 px-5 py-3 text-sm font-medium text-white hover:bg-slate-800">
              Request demo
            </Link>
            <Link href="/dashboard" className="rounded-2xl border border-slate-300 px-5 py-3 text-sm font-medium hover:bg-slate-50">
              Open reviewer console
            </Link>
          </div>
        </div>
      </section>

      <footer className="border-t border-slate-200">
        <div className="mx-auto max-w-7xl px-6 py-8 flex items-center justify-between text-sm text-slate-500">
          <div>© {new Date().getFullYear()} Agentic Internal Controls</div>
          <div className="flex gap-4">
            <Link href="/dashboard" className="hover:text-slate-900">Console</Link>
            <Link href="#supervisors" className="hover:text-slate-900">Catalog</Link>
            <Link href="mailto:ariel@cliocircle.com" className="hover:text-slate-900">Contact</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
