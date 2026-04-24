import Link from "next/link";
import { getMetrics, type MetricsSummary } from "@/lib/metrics";
import { api, type RecentAction, type ReviewCase } from "@/lib/api";
import { listScans, type ScanSummary } from "@/lib/scans";
import { threatsApi, type ThreatAssessmentRow } from "@/lib/threats";
import { getSession } from "@/lib/session";
import { AutoRefresh } from "../review/AutoRefresh";
import InfoTip from "../InfoTip";
import RepoKpis from "./RepoKpis";

export const dynamic = "force-dynamic";

type Window = "24h" | "7d" | "30d";
type FixTone = "danger" | "warn" | "good" | "muted";

type FixItem = {
  id: string;
  title: string;
  body: string;
  meta: string;
  href: string;
  cta: string;
  tone: FixTone;
};

function age(iso: string): string {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  return h < 24 ? `${h}h` : `${Math.floor(h / 24)}d`;
}

function pct(num: number, total: number): string {
  if (!total) return "0%";
  return `${Math.round((num / total) * 100)}%`;
}

function fmtAge(minutes: number | null): string {
  if (minutes === null) return "none";
  if (minutes < 60) return `${minutes}m`;
  const h = Math.floor(minutes / 60);
  if (h < 24) return `${h}h ${minutes % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

function windowLabel(w: string): string {
  if (w === "24h") return "24 hours";
  if (w === "7d") return "7 days";
  if (w === "30d") return "30 days";
  return w;
}

function payloadOneLiner(c: ReviewCase): string {
  const amt = c.action_payload["amount"];
  const cur = c.action_payload["currency"] ?? "USD";
  const cust = c.action_payload["customer_id"];
  const tool = c.action_payload["tool"] ?? c.action_payload["tool_name"];
  const reason = c.action_payload["reason"];
  const bits: string[] = [c.action_type];
  if (tool) bits.push(String(tool));
  if (typeof amt === "number") bits.push(`${amt.toLocaleString()} ${cur}`);
  if (cust) bits.push(`for ${cust}`);
  if (reason) bits.push(`- ${String(reason).slice(0, 42)}`);
  return bits.join(" ");
}

function buildFixQueue(
  m: MetricsSummary,
  blocks: RecentAction[],
  pending: ReviewCase[],
  threats: ThreatAssessmentRow[],
  latestScan: ScanSummary | null,
): FixItem[] {
  const items: FixItem[] = [];

  for (const c of pending.slice(0, 3)) {
    items.push({
      id: `review-${c.id}`,
      title: `Decide ${c.action_type}`,
      body: payloadOneLiner(c),
      meta: `risk ${c.risk_score} - ${age(c.created_at)} ago - ${c.policy_hits[0]?.reason ?? "review required"}`,
      href: `/review/${c.id}`,
      cta: "decide",
      tone: c.priority === "high" ? "danger" : "warn",
    });
  }

  for (const b of blocks.slice(0, 3)) {
    items.push({
      id: `block-${b.action_id}`,
      title: `Inspect blocked ${b.action_type}`,
      body: b.reasons.slice(0, 2).join(", ") || "Denied by active policy or threat detector.",
      meta: `${age(b.created_at)} ago - risk ${b.risk_score}${b.shadow ? " - shadow" : ""}`,
      href: "/policies",
      cta: "tune rule",
      tone: "danger",
    });
  }

  for (const t of threats.slice(0, 3)) {
    items.push({
      id: `threat-${t.id}`,
      title: `Review ${t.detector_id}`,
      body: t.signals[0]?.message ?? `${t.owasp_ref} threat detected.`,
      meta: `${t.level} - ${age(t.created_at)} ago`,
      href: `/threats/${t.id}`,
      cta: "open",
      tone: t.level === "critical" ? "danger" : "warn",
    });
  }

  if (m.actions_total === 0) {
    items.push({
      id: "connect-first-action",
      title: "Send the first supervised action",
      body: "Connect an integration and call evaluate from one risky tool path so runtime data appears here.",
      meta: "setup",
      href: "/integrations",
      cta: "connect",
      tone: "good",
    });
  }

  // Live hook into the last persisted scan. If the most recent scan has
  // priority findings, surface them as a fix-queue item linking to the
  // detail page. No scan yet → fall back to the generic "run a scan" CTA.
  if (latestScan && latestScan.status === "done" && latestScan.priority_count > 0) {
    items.push({
      id: `scan-${latestScan.id}`,
      title: `${latestScan.priority_count} priority finding${latestScan.priority_count === 1 ? "" : "s"} from last scan`,
      body: "Wrap these call-sites before they fire in prod.",
      meta: `${latestScan.repo_url.replace(/^https?:\/\/github\.com\//, "").replace(/\.git\/?$/, "")} - ${latestScan.total_findings} total`,
      href: `/findings/${latestScan.id}`,
      cta: "review",
      tone: "warn",
    });
  } else {
    items.push({
      id: "scan-static-surface",
      title: "Scan static call-sites",
      body: "Run the scanner to find unwrapped payment, DB, LLM, filesystem, and agent chokepoints before they execute.",
      meta: "free public scan - Builder unlocks private repos",
      href: "/scan",
      cta: "scan",
      tone: "muted",
    });
  }

  return items.slice(0, 8);
}

export default async function Dashboard({
  searchParams,
}: {
  searchParams: Promise<{ window?: string }>;
}) {
  const sp = await searchParams;
  const win = (sp.window as Window) ?? "24h";
  const session = await getSession();
  const tenantId = session?.user.tenant_id ?? null;

  let m: MetricsSummary | null = null;
  let err: string | null = null;
  let blocks: RecentAction[] = [];
  let pending: ReviewCase[] = [];
  let threats: ThreatAssessmentRow[] = [];
  let latestScan: ScanSummary | null = null;

  try {
    const [metrics, blocksRes, pendingRes, threatsRes, scansRes] = await Promise.all([
      getMetrics(win),
      api.listRecentActions({ decision: "deny", limit: 12 }).catch(() => []),
      api.listReviews("pending").catch(() => []),
      threatsApi.list(12).catch(() => []),
      listScans(tenantId, 1).catch(() => []),
    ]);
    m = metrics;
    blocks = blocksRes;
    pending = pendingRes;
    threats = threatsRes;
    latestScan = scansRes[0] ?? null;
  } catch (e) {
    err = (e as Error).message;
  }

  if (err || !m) {
    const baseUrl = process.env.SUPERVISOR_API_URL ?? "http://localhost:8000";
    return (
      <div>
        <h1>Fix Queue</h1>
        <div className="card" style={{ borderColor: "var(--danger)", color: "var(--danger)" }}>
          Cannot connect to the supervisor at <code>{baseUrl}</code>.
          {err && <div className="muted mono" style={{ marginTop: 8, fontSize: 12 }}>{err}</div>}
        </div>
      </div>
    );
  }

  const fixQueue = buildFixQueue(m, blocks, pending, threats, latestScan);
  const totalDecisions = m.decisions.allow + m.decisions.deny + m.decisions.review;
  const threatRate = m.actions_total ? Math.round((m.threats.total / m.actions_total) * 100) : 0;
  const isZeroState = m.actions_total === 0;

  return (
    <div>
      <AutoRefresh intervalMs={5000} />

      <div className="row" style={{ justifyContent: "space-between", alignItems: "center", gap: 16 }}>
        <div>
          <div className="row" style={{ alignItems: "center", gap: 8 }}>
            <h1 style={{ margin: 0 }}>Fix this first</h1>
            <InfoTip>
              <strong>What:</strong> the workbench for shipping safely: decide reviews, inspect blocks,
              scan static call-sites, and tune rules.<br /><br />
              <strong>Refresh:</strong> every 5 seconds.
            </InfoTip>
          </div>
          <p className="muted" style={{ margin: "8px 0 0" }}>
            What your agent can do unchecked, where it is, and how to gate it.
          </p>
        </div>
        <div className="row" style={{ gap: 6 }}>
          {(["24h", "7d", "30d"] as Window[]).map((w) => (
            <Link key={w} href={`/dashboard?window=${w}`} className={`badge ${win === w ? "approved" : ""}`}>
              {w}
            </Link>
          ))}
        </div>
      </div>

      <RepoKpis />

      <section className="grid cols-3" style={{ marginTop: 20 }}>
        <MetricCard
          value={isZeroState ? "—" : String(pending.length)}
          label="needs your decision"
          tone={isZeroState ? "muted" : pending.length ? "warn" : "good"}
          href="/review?status=pending"
        />
        <MetricCard
          value={isZeroState ? "—" : String(blocks.length)}
          label="recently blocked"
          tone={isZeroState ? "muted" : blocks.length ? "danger" : "good"}
          href="/policies"
        />
        <MetricCard
          value={isZeroState ? "—" : String(m.threats.total)}
          label={isZeroState ? "threats - awaiting traffic" : `threats - ${threatRate}% of traffic`}
          tone={isZeroState ? "muted" : m.threats.critical ? "danger" : m.threats.total ? "warn" : "good"}
          href="/threats"
        />
      </section>

      <section style={{ marginTop: 24 }}>
        <div className="row" style={{ justifyContent: "space-between", alignItems: "baseline" }}>
          <h2 style={{ marginTop: 0 }}>Fix first</h2>
          <span className="muted mono" style={{ fontSize: 12 }}>auto-refreshing</span>
        </div>
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          {fixQueue.map((item) => (
            <FixRow key={item.id} item={item} />
          ))}
        </div>
      </section>

      <section className="grid cols-2" style={{ marginTop: 24 }}>
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Shipping checklist</h3>
          <ChecklistRow done label="Public repo scan available" href="/scan" />
          <ChecklistRow done={m.active_integrations > 0} label="Integration connected" href="/integrations" />
          <ChecklistRow done={m.actions_total > 0} label="First action evaluated" href="/integrations" />
          <ChecklistRow done={m.decisions.deny + m.decisions.review > 0} label="At least one policy decision observed" href="/policies" />
        </div>
        {isZeroState ? (
          <div className="card">
            <h3 style={{ marginTop: 0 }}>What this catches</h3>
            <p className="muted" style={{ lineHeight: 1.6, marginTop: 0 }}>
              Once your app calls <code>evaluate</code>, the supervisor blocks or escalates these
              before your tools execute:
            </p>
            <ul className="muted" style={{ marginTop: 10, paddingLeft: 18, lineHeight: 1.85, fontSize: 13.5 }}>
              <li><strong>Prompt injections</strong> — agent told to ignore its rules</li>
              <li><strong>PII / secret exfiltration</strong> in tool args</li>
              <li><strong>Tool abuse</strong> — unbounded loops, off-scope calls</li>
              <li><strong>Refunds &amp; payments</strong> over your caps</li>
              <li><strong>DB writes</strong> without <code>WHERE</code>, sandbox escapes</li>
            </ul>
            <Link href="/threats" className="badge" style={{ marginTop: 14, display: "inline-block" }}>
              see all detectors →
            </Link>
          </div>
        ) : (
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Builder unlock</h3>
            <p className="muted" style={{ lineHeight: 1.7 }}>
              Upgrade when you need private repo scans, full <code>runtime-supervisor/</code> export,
              scan history, and CI comments.
            </p>
            <div className="row" style={{ justifyContent: "space-between", marginTop: 18 }}>
              <div>
                <div style={{ fontSize: 28, fontWeight: 700 }}>$29/mo</div>
                <div className="muted mono" style={{ fontSize: 12 }}>solo builder</div>
              </div>
              <Link className="badge approved" href="/scan?upgrade=builder">upgrade</Link>
            </div>
          </div>
        )}
      </section>

      {!isZeroState && (
        <section style={{ marginTop: 24 }}>
          <h2>Runtime health</h2>
          <div className="grid cols-3">
            <MetricCard value={String(m.actions_total)} label={`actions reviewed - ${windowLabel(m.window)}`} tone="muted" />
            <MetricCard value={pct(m.decisions.deny + m.decisions.review, totalDecisions)} label="blocked or escalated" tone="warn" />
            <MetricCard value={fmtAge(m.reviews.oldest_pending_age_minutes)} label="oldest pending review" tone={m.reviews.pending ? "warn" : "good"} />
          </div>
        </section>
      )}

      {!isZeroState && (
        <>
          <section style={{ marginTop: 24 }}>
            <h2>Decision mix</h2>
            <div className="card">
              <DecisionBar m={m} />
            </div>
          </section>

          <section className="grid cols-2" style={{ marginTop: 24 }}>
            <div className="card" style={{ padding: 0 }}>
              <TableTitle title="Traffic by action type" />
              <table>
                <thead><tr><th>Type</th><th>Volume</th><th>Policy</th></tr></thead>
                <tbody>
                  {Object.keys(m.volume_by_action_type).length === 0 ? (
                    <tr><td className="muted" colSpan={3} style={{ padding: 16 }}>No traffic in this window.</td></tr>
                  ) : (
                    Object.entries(m.volume_by_action_type).map(([at, n]) => (
                      <tr key={at}>
                        <td className="mono">{at}</td>
                        <td>{n}</td>
                        <td className="mono muted">{m.active_policies_by_type[at] ? `v${m.active_policies_by_type[at]}` : "YAML"}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
            <div className="card" style={{ padding: 0 }}>
              <TableTitle title="Top threat detectors" />
              <table>
                <thead><tr><th>Detector</th><th>Attempts</th></tr></thead>
                <tbody>
                  {m.threats.top_detectors.length === 0 ? (
                    <tr><td className="muted" colSpan={2} style={{ padding: 16 }}>No threats detected.</td></tr>
                  ) : (
                    m.threats.top_detectors.map((t) => (
                      <tr key={t.detector_id}>
                        <td className="mono">{t.detector_id}</td>
                        <td>{t.count}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  );
}

function MetricCard({
  value,
  label,
  tone,
  href,
}: {
  value: string;
  label: string;
  tone: FixTone;
  href?: string;
}) {
  const color = tone === "danger" ? "var(--danger)" : tone === "warn" ? "var(--warn)" : tone === "good" ? "var(--ok)" : "var(--text)";
  const body = (
    <div className="card kpi" style={{ borderColor: tone === "muted" ? "var(--border)" : color }}>
      <span style={{ color }}>{value}</span>
      <span className="label">{label}</span>
    </div>
  );
  return href ? <Link href={href} style={{ color: "inherit", textDecoration: "none" }}>{body}</Link> : body;
}

function FixRow({ item }: { item: FixItem }) {
  const color = item.tone === "danger" ? "var(--danger)" : item.tone === "warn" ? "var(--warn)" : item.tone === "good" ? "var(--ok)" : "var(--muted)";
  return (
    <Link
      href={item.href}
      style={{
        display: "grid",
        gridTemplateColumns: "12px 1fr auto",
        gap: 14,
        alignItems: "center",
        padding: "14px 16px",
        borderBottom: "1px solid var(--border)",
        color: "inherit",
        textDecoration: "none",
      }}
    >
      <span style={{ width: 8, height: 8, borderRadius: "50%", background: color }} />
      <span>
        <strong>{item.title}</strong>
        <span className="muted" style={{ display: "block", marginTop: 4 }}>{item.body}</span>
        <span className="mono muted" style={{ display: "block", marginTop: 4, fontSize: 12 }}>{item.meta}</span>
      </span>
      <span className="badge approved">{item.cta}</span>
    </Link>
  );
}

function ChecklistRow({ done, label, href }: { done: boolean; label: string; href: string }) {
  return (
    <Link href={href} className="row" style={{ justifyContent: "space-between", padding: "10px 0", borderBottom: "1px solid var(--border)", color: "inherit" }}>
      <span>{label}</span>
      <span className={`badge ${done ? "approved" : "pending"}`}>{done ? "done" : "next"}</span>
    </Link>
  );
}

function DecisionBar({ m }: { m: MetricsSummary }) {
  const t = m.decisions.allow + m.decisions.deny + m.decisions.review;
  if (t === 0) return <p className="muted">No decisions in this time window.</p>;
  const allow = (m.decisions.allow / t) * 100;
  const deny = (m.decisions.deny / t) * 100;
  const review = (m.decisions.review / t) * 100;
  return (
    <div>
      <div style={{ display: "flex", height: 24, borderRadius: 6, overflow: "hidden", border: "1px solid var(--border)" }}>
        <div style={{ width: `${allow}%`, background: "var(--ok)" }} />
        <div style={{ width: `${review}%`, background: "var(--warn)" }} />
        <div style={{ width: `${deny}%`, background: "var(--danger)" }} />
      </div>
      <div className="row" style={{ gap: 16, marginTop: 8, fontSize: 13, flexWrap: "wrap" }}>
        <span><span className="chain-ok">●</span> allowed: {m.decisions.allow} - {pct(m.decisions.allow, t)}</span>
        <span style={{ color: "var(--warn)" }}>● review: {m.decisions.review} - {pct(m.decisions.review, t)}</span>
        <span style={{ color: "var(--danger)" }}>● blocked: {m.decisions.deny} - {pct(m.decisions.deny, t)}</span>
      </div>
    </div>
  );
}

function TableTitle({ title }: { title: string }) {
  return <h3 style={{ margin: 0, padding: "16px 18px 4px" }}>{title}</h3>;
}
