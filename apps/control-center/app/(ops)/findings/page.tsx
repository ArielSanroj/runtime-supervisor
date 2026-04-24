import Link from "next/link";
import InfoTip from "../InfoTip";

export const dynamic = "force-static";

export default function FindingsPage() {
  return (
    <div>
      <h1 style={{ display: "flex", alignItems: "center", gap: 8 }}>
        Scans
        <InfoTip>
          <strong>What:</strong> static analysis of risky call-sites before runtime.
          Use it to find what needs a supervisor wrapper.<br /><br />
          <strong>Paid path:</strong> Builder keeps scan history and diffs. The free web scan
          shows a preview for public repos.
        </InfoTip>
      </h1>
      <p className="muted" style={{ marginTop: -8, marginBottom: 20 }}>
        Static surface area: the code paths your agent could execute unchecked.
      </p>

      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <div className="card">
          <h2 style={{ marginTop: 0 }}>Run a free public scan</h2>
          <p className="muted" style={{ lineHeight: 1.7 }}>
            Paste a public GitHub URL and get a risk-ranked preview: payments, DB mutations,
            LLM calls, shell/filesystem tools, agent chokepoints, and routes.
          </p>
          <Link className="badge approved" href="/scan" style={{ marginTop: 14 }}>
            open /scan
          </Link>
        </div>

        <div className="card" style={{ borderColor: "var(--accent)" }}>
          <h2 style={{ marginTop: 0 }}>Builder export</h2>
          <p className="muted" style={{ lineHeight: 1.7 }}>
            Unlock private repos, the complete <code>runtime-supervisor/</code> export,
            scan history, diffs, and CI comments.
          </p>
          <div className="row" style={{ justifyContent: "space-between", marginTop: 14 }}>
            <strong style={{ fontSize: 24 }}>$29/mo</strong>
            <Link className="badge approved" href="/scan?upgrade=builder">
              upgrade
            </Link>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <h2 style={{ marginTop: 0 }}>Local CLI workflow</h2>
        <p className="muted" style={{ lineHeight: 1.7 }}>
          The CLI writes the full artifact bundle to <code>./runtime-supervisor/</code>.
          Open <code>SUMMARY.md</code> first, then use stubs and policies to wrap the highest-risk paths.
        </p>
        <pre>$ pipx install supervisor-discover
$ cd /path/to/your-repo
$ supervisor-discover scan</pre>
        <div className="grid cols-3" style={{ marginTop: 12 }}>
          <FileCard title="SUMMARY.md" desc="The prioritized fix list. Open this first." />
          <FileCard title="ROLLOUT.md" desc="Shadow to enforce plan for risky call-sites." />
          <FileCard title="report.md" desc="Full scanner detail, grouped by tier." />
          <FileCard title="combos/" desc="Playbooks for dangerous capability pairs." />
          <FileCard title="stubs/" desc="Copy-paste wrappers for Python and TS." />
          <FileCard title="policies/" desc="YAML rules ready to promote." />
        </div>
      </div>

      <div className="card">
        <h2 style={{ marginTop: 0 }}>Builder scan history</h2>
        <div className="grid cols-3">
          <RoadmapCard title="Diff scans" desc="See new and resolved risks across commits." />
          <RoadmapCard title="PR comments" desc="Comment risky new call-sites directly on GitHub." />
          <RoadmapCard title="Runtime links" desc="Connect each finding to the blocks and reviews it produced." />
        </div>
      </div>
    </div>
  );
}

function FileCard({ title, desc }: { title: string; desc: string }) {
  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 14, background: "var(--panel-2)" }}>
      <div className="mono" style={{ fontWeight: 600, marginBottom: 6 }}>{title}</div>
      <div className="muted" style={{ fontSize: 13, lineHeight: 1.5 }}>{desc}</div>
    </div>
  );
}

function RoadmapCard({ title, desc }: { title: string; desc: string }) {
  return (
    <div>
      <div style={{ fontWeight: 600 }}>{title}</div>
      <p className="muted" style={{ marginTop: 6, lineHeight: 1.6 }}>{desc}</p>
    </div>
  );
}
