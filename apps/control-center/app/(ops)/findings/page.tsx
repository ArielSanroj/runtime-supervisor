import Link from "next/link";
import { listScans, type ScanSummary } from "@/lib/scans";
import { getSession } from "@/lib/session";
import InfoTip from "../InfoTip";

export const dynamic = "force-dynamic";

function age(iso: string): string {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

function repoShort(url: string): string {
  // Strip https://github.com/ prefix for readability: `owner/repo`.
  return url.replace(/^https?:\/\/github\.com\//, "").replace(/\.git\/?$/, "");
}

export default async function FindingsPage() {
  const session = await getSession();
  const tenantId = session?.user.tenant_id ?? null;

  let scans: ScanSummary[] = [];
  let err: string | null = null;
  try {
    scans = await listScans(tenantId, 20);
  } catch (e) {
    err = (e as Error).message;
  }

  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between", alignItems: "baseline" }}>
        <div>
          <h1 style={{ display: "flex", alignItems: "center", gap: 8, margin: 0 }}>
            Scans
            <InfoTip>
              <strong>What:</strong> past runs of <code>supervisor-discover</code>{" "}
              against a repo. Each row links to the full finding list.
              <br /><br />
              <strong>Empty?</strong> Run your first scan at <Link href="/scan">/scan</Link>.
            </InfoTip>
          </h1>
          <p className="muted" style={{ margin: "6px 0 0 0", fontSize: 13 }}>
            Your scan history — newest first. Open any row to see the full finding list.
          </p>
        </div>
        <Link href="/scan" className="badge approved">
          run new scan →
        </Link>
      </div>

      {err && (
        <div className="card" style={{ borderColor: "var(--danger)", color: "var(--danger)", marginTop: 20 }}>
          Could not load scan history.
          <div className="muted mono" style={{ marginTop: 8, fontSize: 12 }}>{err}</div>
        </div>
      )}

      {!err && scans.length === 0 && (
        <div className="card" style={{ borderColor: "var(--accent)", padding: 28, marginTop: 24, textAlign: "center" }}>
          <div style={{ fontSize: 12, fontFamily: "var(--font-mono, monospace)", color: "var(--accent)", letterSpacing: 1.2 }}>
            NO SCANS YET
          </div>
          <h2 style={{ margin: "8px 0 6px" }}>Run your first scan</h2>
          <p className="muted" style={{ maxWidth: 520, margin: "0 auto 18px", lineHeight: 1.6 }}>
            Paste a public GitHub URL. The scanner finds the unwrapped call-sites
            your agent can execute (payments, DB mutations, LLM calls, shell, tools).
            Builder unlocks private repos and scan history; Pro adds team workflows and org controls.
          </p>
          <Link href="/scan" className="badge approved">open /scan →</Link>
        </div>
      )}

      {!err && scans.length > 0 && (
        <div className="card" style={{ marginTop: 20, padding: 0 }}>
          <table>
            <thead>
              <tr>
                <th>Repo</th>
                <th>Priority / total</th>
                <th>Duration</th>
                <th>Scanned</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id}>
                  <td className="mono">
                    <Link href={`/findings/${s.id}`} style={{ color: "inherit" }}>
                      {repoShort(s.repo_url)}
                      {s.ref && <span className="muted"> @{s.ref}</span>}
                    </Link>
                  </td>
                  <td>
                    <span className={s.priority_count > 0 ? "" : "muted"}>
                      <strong>{s.priority_count}</strong>
                      <span className="muted"> / {s.total_findings}</span>
                    </span>
                  </td>
                  <td className="muted mono" style={{ fontSize: 12 }}>
                    {s.scan_seconds ? `${s.scan_seconds.toFixed(1)}s` : "—"}
                  </td>
                  <td className="muted" style={{ fontSize: 13 }}>{age(s.created_at)}</td>
                  <td>
                    <Link href={`/findings/${s.id}`} className="muted">open →</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="card" style={{ marginTop: 20 }}>
        <h3 style={{ marginTop: 0 }}>Local CLI workflow</h3>
        <p className="muted" style={{ lineHeight: 1.7, marginBottom: 10 }}>
          For the full artifact bundle (SUMMARY.md, ROLLOUT.md, combos, stubs,
          policies), run the CLI against your local checkout:
        </p>
        <pre>$ pipx install supervisor-discover
$ cd /path/to/your-repo
$ supervisor-discover scan</pre>
      </div>
    </div>
  );
}
