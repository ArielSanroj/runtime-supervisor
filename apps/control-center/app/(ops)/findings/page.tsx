import Link from "next/link";

export const dynamic = "force-static";

export default function FindingsPage() {
  return (
    <div>
      <h1>Findings</h1>
      <p className="muted" style={{ marginTop: -8, marginBottom: 20 }}>
        Static-analysis surface: what <code>supervisor-discover scan</code> found in your codebase.
      </p>

      <div className="card" style={{ marginBottom: 16 }}>
        <h2 style={{ marginTop: 0 }}>No scan ingested yet</h2>
        <p className="muted">
          This page will show the output of <code>supervisor-discover scan</code> — priority
          actions, combos detected, tier breakdown, call-sites to gate. For now, run the
          scan from your repo root and open the generated files locally.
        </p>

        <h2>Run the scan</h2>
        <pre>$ cd /path/to/your-repo
$ supervisor-discover scan</pre>
        <p className="muted" style={{ fontSize: 13 }}>
          Writes to <code>./runtime-supervisor/</code> with five files worth reading:
        </p>

        <div className="grid cols-3" style={{ marginTop: 12 }}>
          <FileCard
            title="SUMMARY.md"
            desc="Priority actions. What to wrap first, how long each takes, the timeline. Open this first."
          />
          <FileCard
            title="ROLLOUT.md"
            desc="Phased deploy playbook (shadow → sample → enforce) tailored to your risk surface."
          />
          <FileCard
            title="report.md"
            desc="Full technical detail. Tier breakdown, OWASP coverage, policies that would apply, every call-site found."
          />
          <FileCard
            title="combos/"
            desc="Per-combo playbooks for dangerous capability pairs (e.g. voice-clone + outbound-call)."
          />
          <FileCard
            title="stubs/"
            desc="Copy-paste wrappers for each high-confidence call-site, with on_review='shadow' by default."
          />
          <FileCard
            title="policies/"
            desc="YAML policies (payment, refund, account_change, tool_use, data_access, compliance) ready to promote."
          />
        </div>
      </div>

      <div className="card">
        <h2 style={{ marginTop: 0 }}>What this page will show once wired up</h2>
        <ul style={{ paddingLeft: 20, lineHeight: 1.8 }}>
          <li>
            <strong>Surface summary</strong> — stack, payment integrations, LLM providers,
            real-world-action capabilities, orchestrator frameworks detected.
          </li>
          <li>
            <strong>Tier breakdown</strong> — Money / Real-world actions / Customer data /
            LLM tool-use / General — high / medium / low counts per tier.
          </li>
          <li>
            <strong>Priority actions</strong> — the 3-5 wrap points that cover the most surface
            (orchestrator chokepoints first).
          </li>
          <li>
            <strong>Combos detected</strong> — dangerous capability pairs with linked playbooks.
          </li>
          <li>
            <strong>Rollout phase status</strong> — current <code>SUPERVISOR_ENFORCEMENT_MODE</code>,
            volume observed per tier, exit criteria met/pending.
          </li>
          <li>
            <strong>Cross-reference with runtime</strong> — each call-site in findings linked to the
            decisions it's produced on the <Link href="/review">Review</Link> and{" "}
            <Link href="/dashboard">Dashboard</Link> pages.
          </li>
        </ul>
        <p className="muted" style={{ fontSize: 13, marginTop: 16 }}>
          Pending work: ingestion endpoint <code>POST /v1/scans</code> in the supervisor API,
          plus a <code>--upload</code> flag on <code>supervisor-discover scan</code>. Tracked as
          its own epic — the CLI output is the single source of truth today.
        </p>
      </div>
    </div>
  );
}

function FileCard({ title, desc }: { title: string; desc: string }) {
  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderRadius: 8,
        padding: 14,
        background: "var(--panel-2)",
      }}
    >
      <div className="mono" style={{ fontWeight: 600, marginBottom: 6 }}>
        {title}
      </div>
      <div className="muted" style={{ fontSize: 13, lineHeight: 1.5 }}>
        {desc}
      </div>
    </div>
  );
}
