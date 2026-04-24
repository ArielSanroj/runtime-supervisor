import { getRepo } from "@/lib/repos";
import type { RepoSummary, ScanFinding } from "@/lib/scans";
import NotWorriedAbout from "@/app/scan/NotWorriedAbout";

export const dynamic = "force-dynamic";

const TIER_ORDER: Array<{ key: keyof RiskShape; label: string; tone: string }> = [
  { key: "money", label: "Money movement", tone: "#fb7185" },
  { key: "real_world_actions", label: "Real-world actions", tone: "#fbbf24" },
  { key: "customer_data", label: "Customer data", tone: "#f472b6" },
  { key: "business_data", label: "Business data", tone: "#facc15" },
  { key: "llm", label: "LLM tool-use", tone: "#22d3ee" },
  { key: "general", label: "General / informational", tone: "#a1a1aa" },
];

type RiskShape = {
  money: number;
  real_world_actions: number;
  customer_data: number;
  business_data: number;
  llm: number;
  general: number;
};

export default async function RepoOverviewPage({
  params,
}: {
  params: Promise<{ repo_id: string }>;
}) {
  const { repo_id } = await params;
  const overview = await getRepo(repo_id);
  const summary = (overview.repo_summary ?? {}) as RepoSummary;
  const findings: ScanFinding[] = []; // Overview doesn't fetch full findings — the NotWorriedAbout helper handles empty gracefully.

  return (
    <div className="grid" style={{ gap: 20 }}>
      <section className="card">
        <h2 style={{ marginTop: 0 }}>Risk shape</h2>
        <p className="muted" style={{ marginTop: 4 }}>
          High-confidence findings by blast radius. Start with the top of the list.
        </p>
        <div style={{ marginTop: 16, display: "grid", gap: 10 }}>
          {TIER_ORDER.map((t) => (
            <RiskRow
              key={t.key}
              label={t.label}
              count={overview.risk_shape[t.key] ?? 0}
              tone={t.tone}
            />
          ))}
        </div>
      </section>

      {Object.keys(summary).length > 0 && <NotWorriedAbout summary={summary} findings={findings} />}
    </div>
  );
}

function RiskRow({ label, count, tone }: { label: string; count: number; tone: string }) {
  const zero = count === 0;
  return (
    <div className="row" style={{ justifyContent: "space-between", alignItems: "baseline", padding: "8px 0", borderBottom: "1px solid #27272a" }}>
      <span style={{ color: zero ? "#52525b" : tone, fontSize: 14 }}>{label}</span>
      <span className="mono" style={{ color: zero ? "#52525b" : tone, fontSize: 16, fontWeight: 600 }}>
        {count} high
      </span>
    </div>
  );
}
