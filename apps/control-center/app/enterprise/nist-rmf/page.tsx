import type { Metadata } from "next";
import Link from "next/link";

const TITLE =
  "NIST AI RMF crosswalk — Vibefixing artifacts mapped to GOVERN, MAP, MEASURE, MANAGE";
const DESCRIPTION =
  "A crosswalk between NIST AI Risk Management Framework (1.0) functions and the artifacts Vibefixing emits today. Mapping, not certification. Built for security questionnaires and the conversation your compliance team has with engineering.";
const URL = "https://www.vibefixing.me/enterprise/nist-rmf";

export const metadata: Metadata = {
  title: `${TITLE} — Vibefixing`,
  description: DESCRIPTION,
  alternates: { canonical: URL },
  openGraph: {
    title: TITLE,
    description: DESCRIPTION,
    url: URL,
    type: "article",
    siteName: "Vibefixing",
  },
  twitter: {
    card: "summary_large_image",
    title: TITLE,
    description: DESCRIPTION,
  },
};

type Mapping = {
  ref: string;
  control: string;
  vibefixingArtifact: string;
  evidence: string;
  status: "supported" | "partial" | "not-addressed";
};

type FunctionBlock = {
  id: string;
  letter: string;
  name: string;
  intent: string;
  mappings: Mapping[];
};

const FUNCTIONS: FunctionBlock[] = [
  {
    id: "govern",
    letter: "G",
    name: "Govern",
    intent:
      "Culture, accountability structures, and policies that make AI risk management a managed activity, not a side effect.",
    mappings: [
      {
        ref: "GOVERN 1.1",
        control:
          "Policies, processes, procedures, and practices across the organization are documented.",
        vibefixingArtifact:
          "Versioned YAML policies under packages/policies/. Each policy is a file with a semantic version; every change ships through git review.",
        evidence:
          "Policy files in source control with author, timestamp, and review trail. Policy version is stamped on every supervisor decision.",
        status: "supported",
      },
      {
        ref: "GOVERN 1.2",
        control:
          "Accountability structures for AI risk are clear and documented.",
        vibefixingArtifact:
          "Per-action ownership is encoded in the action_type registry: each action type names a responsible policy and a default enforcement mode (shadow / enforce).",
        evidence:
          "/v1/action-types lists every action the supervisor knows about with its current policy_ref.",
        status: "supported",
      },
      {
        ref: "GOVERN 4.1",
        control:
          "Organizational practices are in place to ensure diverse perspectives in AI design.",
        vibefixingArtifact: "Not addressed.",
        evidence:
          "This is an organizational practice, not an artifact a runtime supervisor can produce. We do not claim coverage.",
        status: "not-addressed",
      },
    ],
  },
  {
    id: "map",
    letter: "M",
    name: "Map",
    intent:
      "Establish the context: what the AI system does, what it is used for, what its capabilities and limitations are, and what risks it could create.",
    mappings: [
      {
        ref: "MAP 2.2",
        control:
          "Information about the AI system's knowledge limits and the conditions under which the system may fail are documented.",
        vibefixingArtifact:
          "Each action_type ships intercepted_signals (the inputs the policy can decide on) and the sample_payload that triggered evaluation. Gaps in coverage are visible by inspection.",
        evidence:
          "action_type.intercepted_signals enumerates the supervisor's decision inputs. Anything outside that list is, explicitly, out of policy scope.",
        status: "supported",
      },
      {
        ref: "MAP 3.1",
        control:
          "Potential benefits and costs of the AI system are characterized.",
        vibefixingArtifact:
          "The action_type registry assigns each action to a tier (security / reliability / efficiency / quality) and ships a one-liner explaining the business outcome being protected.",
        evidence:
          "/v1/action-types responses include title, one_liner, and the policy_ref so the cost-of-violation is traceable.",
        status: "partial",
      },
      {
        ref: "MAP 4.1",
        control:
          "Approaches for mapping AI technology and use cases to legal and regulatory requirements are documented.",
        vibefixingArtifact:
          "Threat catalog at /v1/threats/catalog links each known threat to an OWASP LLM Top 10 reference where one applies, plus a remediation string.",
        evidence:
          "ThreatCatalogEntry.owasp_ref is non-empty for every cataloged threat. The crosswalk you are reading is the GOVERN-side analog.",
        status: "supported",
      },
    ],
  },
  {
    id: "measure",
    letter: "S",
    name: "Measure",
    intent:
      "Use quantitative, qualitative, or mixed-method tools to analyze, assess, benchmark, and monitor AI risk and related impacts.",
    mappings: [
      {
        ref: "MEASURE 2.7",
        control:
          "AI system security and resilience are evaluated and documented.",
        vibefixingArtifact:
          "Every supervised action produces a deterministic risk score and a list of threat signals that fired, written to the evidence chain. Re-running the same input against the current policy is a dry-run via /v1/actions/evaluate.",
        evidence:
          "Evidence events carry risk_score, threats[], reasons[], policy_version. Replay is reproducible.",
        status: "supported",
      },
      {
        ref: "MEASURE 3.1",
        control:
          "Mechanisms for tracking identified AI risks over time are in place.",
        vibefixingArtifact:
          "Evidence chain is append-only and hash-linked. Threat assessments are stored as ThreatAssessmentRow with timestamp, detector_id, severity level, and the signals that matched.",
        evidence:
          "/v1/threats lists historical assessments. The hash link breaks visibly if a row is modified.",
        status: "supported",
      },
      {
        ref: "MEASURE 4.2",
        control:
          "Measurement results regarding AI system trustworthiness are informed by feedback from users.",
        vibefixingArtifact:
          "Findings carry confidence tiers (high / medium / low). Public scans only surface high-confidence priority findings; the dashboard tracks user-initiated overrides as policy edits.",
        evidence:
          "Decision overrides become policy diffs in source control; the feedback loop is the policy change.",
        status: "partial",
      },
    ],
  },
  {
    id: "manage",
    letter: "N",
    name: "Manage",
    intent:
      "Allocate risk resources to mapped and measured risks on a regular basis and as defined by the Govern function.",
    mappings: [
      {
        ref: "MANAGE 1.3",
        control:
          "Responses to AI risks are developed and documented based on the assessment of, and prioritization of, AI risks.",
        vibefixingArtifact:
          "Enforcement mode is a per-deployment environment variable: shadow (log without blocking) and enforce (block on violation). The mode is stamped on every decision so historical analysis distinguishes 'would have blocked' from 'did block'.",
        evidence:
          "SUPERVISOR_ENFORCEMENT_MODE is read at decision time and recorded with the evidence event.",
        status: "supported",
      },
      {
        ref: "MANAGE 4.1",
        control:
          "Post-deployment AI system monitoring plans are implemented.",
        vibefixingArtifact:
          "The supervisor exposes Prometheus-style metrics on decision counts, denial rates, policy violations, and self-check drops. The threat assessment endpoint streams new assessments as they are recorded.",
        evidence:
          "/metrics endpoint on the supervisor; ThreatAssessmentRow timestamps on /v1/threats.",
        status: "partial",
      },
      {
        ref: "MANAGE 4.3",
        control:
          "Incidents and errors are communicated to relevant AI actors, including affected communities.",
        vibefixingArtifact:
          "Not addressed end-to-end.",
        evidence:
          "Vibefixing surfaces incidents to operators via the dashboard and webhooks. Communication to end users or affected communities is a downstream workflow your team owns.",
        status: "not-addressed",
      },
    ],
  },
];

export default function NistRmfCrosswalk() {
  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <header className="sticky top-0 z-10 border-b border-zinc-800 bg-zinc-950/85 backdrop-blur">
        <div className="mx-auto flex max-w-4xl items-center justify-between px-6 py-4">
          <Link href="/" className="flex items-baseline gap-2 font-mono text-sm">
            <span className="text-emerald-400">$</span>
            <span className="font-semibold text-zinc-100">vibefixing</span>
            <span className="text-xs text-zinc-500">// enterprise · nist-rmf</span>
          </Link>
          <a
            href="mailto:ariel@vibefixing.me?subject=Enterprise%20-%20NIST%20AI%20RMF"
            className="rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2 text-sm font-semibold text-zinc-100 hover:border-emerald-700/50"
          >
            contact sales
          </a>
        </div>
      </header>

      <section className="mx-auto max-w-4xl px-6 py-16">
        <Link href="/compliance" className="font-mono text-xs text-zinc-500 hover:text-zinc-300">
          ← compliance overview
        </Link>

        <p className="mt-8 font-mono text-xs uppercase tracking-widest text-emerald-400">
          enterprise resource · crosswalk
        </p>
        <h1 className="mt-3 text-3xl font-bold leading-tight tracking-tight sm:text-4xl">
          NIST AI Risk Management Framework — Vibefixing crosswalk
        </h1>
        <p className="mt-4 max-w-3xl text-zinc-400">
          A mapping between NIST AI RMF 1.0 functions (Govern, Map, Measure,
          Manage) and the artifacts Vibefixing produces today. Intended for
          security questionnaires and conversations between your compliance
          team and the engineers integrating the supervisor.
        </p>

        <div className="mt-8 rounded-xl border border-amber-700/40 bg-amber-500/5 p-5">
          <p className="font-mono text-xs uppercase tracking-widest text-amber-300">
            scope of this document
          </p>
          <p className="mt-3 text-sm leading-7 text-zinc-300">
            This crosswalk maps Vibefixing artifacts to NIST AI RMF
            sub-categories. It is not a certification. It does not
            constitute legal advice. Vibefixing does not hold a SOC 2 Type II
            report on the supervisor itself; the artifacts described below
            are intended to be consumed inside your organization&apos;s
            existing audit programs.
          </p>
        </div>

        <div className="mt-10 grid gap-3 sm:grid-cols-4">
          {FUNCTIONS.map((f) => (
            <a
              key={f.id}
              href={`#${f.id}`}
              className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 transition-colors hover:border-emerald-700/40"
            >
              <div className="flex items-center gap-3">
                <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/10 font-mono text-sm font-semibold text-emerald-300">
                  {f.letter}
                </span>
                <span className="font-semibold text-zinc-100">{f.name}</span>
              </div>
              <p className="mt-3 text-xs leading-6 text-zinc-500">
                {f.mappings.length} sub-categories mapped
              </p>
            </a>
          ))}
        </div>

        <div className="mt-16 space-y-16">
          {FUNCTIONS.map((f) => (
            <FunctionSection key={f.id} fn={f} />
          ))}
        </div>

        <hr className="my-16 border-zinc-900" />

        <h2 className="text-2xl font-bold tracking-tight">How to use this document</h2>
        <ol className="mt-4 list-decimal space-y-3 pl-6 text-zinc-300">
          <li>
            For each sub-category your audit covers, copy the
            <em> Vibefixing artifact</em> column into your response, and
            attach the underlying record from the endpoint named in
            <em> Evidence</em>.
          </li>
          <li>
            For sub-categories marked <strong className="text-zinc-100">not addressed</strong>,
            state explicitly that Vibefixing is not a control for that
            requirement and document the compensating control inside your
            organization.
          </li>
          <li>
            For sub-categories marked <strong className="text-zinc-100">partial</strong>,
            confirm scope with your sales contact before relying on the
            mapping in a regulator-facing document.
          </li>
        </ol>

        <hr className="my-16 border-zinc-900" />

        <div className="rounded-2xl border border-zinc-800 bg-zinc-900/50 p-7">
          <h2 className="text-2xl font-bold tracking-tight">Need a deeper review?</h2>
          <p className="mt-3 leading-7 text-zinc-300">
            Enterprise engagements include a working session with your
            compliance team to walk through each sub-category and identify
            the gaps where Vibefixing does not apply. The deliverable is a
            populated questionnaire your team can submit, not a marketing
            deck.
          </p>
          <div className="mt-5 flex flex-wrap gap-3">
            <a
              href="mailto:ariel@vibefixing.me?subject=Enterprise%20-%20NIST%20AI%20RMF"
              className="rounded-xl bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-black hover:bg-emerald-400"
            >
              email sales →
            </a>
            <Link
              href="/compliance"
              className="rounded-xl border border-zinc-800 bg-zinc-950 px-5 py-2.5 text-sm font-semibold text-zinc-200 hover:border-emerald-700/50"
            >
              back to compliance overview
            </Link>
          </div>
        </div>

        <p className="mt-12 text-center font-mono text-xs text-zinc-600">
          NIST AI Risk Management Framework (AI RMF 1.0) is a publication of
          the National Institute of Standards and Technology, U.S.
          Department of Commerce. Vibefixing is not affiliated with NIST.
        </p>
      </section>

      <footer className="border-t border-zinc-800 bg-zinc-950">
        <div className="mx-auto flex max-w-4xl flex-wrap items-center justify-between gap-4 px-6 py-8 text-sm text-zinc-600">
          <div className="font-mono">
            <span className="text-emerald-400">$</span>{" "}
            <span className="text-zinc-400">vibefixing</span>{" "}
            <span className="text-zinc-700">enterprise</span>
          </div>
          <div className="flex gap-6 font-mono">
            <Link href="/" className="hover:text-zinc-300">/home</Link>
            <Link href="/compliance" className="hover:text-zinc-300">/compliance</Link>
            <Link href="/risks" className="hover:text-zinc-300">/risks</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}

function FunctionSection({ fn }: { fn: FunctionBlock }) {
  return (
    <section id={fn.id} className="scroll-mt-24">
      <div className="flex items-center gap-4">
        <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/10 font-mono text-lg font-semibold text-emerald-300">
          {fn.letter}
        </span>
        <div>
          <p className="font-mono text-xs uppercase tracking-widest text-emerald-400">
            function
          </p>
          <h2 className="text-2xl font-bold tracking-tight text-zinc-100">{fn.name}</h2>
        </div>
      </div>
      <p className="mt-4 max-w-3xl text-sm leading-7 text-zinc-400">{fn.intent}</p>

      <div className="mt-6 space-y-4">
        {fn.mappings.map((m) => (
          <MappingRow key={m.ref} m={m} />
        ))}
      </div>
    </section>
  );
}

function MappingRow({ m }: { m: Mapping }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <div className="flex items-baseline gap-3">
          <span className="font-mono text-xs text-emerald-400">{m.ref}</span>
          <span className="font-semibold text-zinc-100">{m.control}</span>
        </div>
        <StatusChip status={m.status} />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div>
          <p className="font-mono text-xs uppercase tracking-widest text-zinc-500">
            vibefixing artifact
          </p>
          <p className="mt-2 text-sm leading-7 text-zinc-300">{m.vibefixingArtifact}</p>
        </div>
        <div>
          <p className="font-mono text-xs uppercase tracking-widest text-zinc-500">
            evidence
          </p>
          <p className="mt-2 text-sm leading-7 text-zinc-400">{m.evidence}</p>
        </div>
      </div>
    </div>
  );
}

function StatusChip({ status }: { status: Mapping["status"] }) {
  const palette = {
    supported: {
      label: "supported",
      cls: "border-emerald-700/40 bg-emerald-500/10 text-emerald-300",
    },
    partial: {
      label: "partial",
      cls: "border-amber-700/40 bg-amber-500/10 text-amber-300",
    },
    "not-addressed": {
      label: "not addressed",
      cls: "border-zinc-700/60 bg-zinc-800 text-zinc-400",
    },
  }[status];
  return (
    <span
      className={`rounded-full border px-2.5 py-0.5 font-mono text-[10px] uppercase tracking-widest ${palette.cls}`}
    >
      {palette.label}
    </span>
  );
}
