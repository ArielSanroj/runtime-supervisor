import { getRepoFindings } from "@/lib/repos";
import type { ScanFinding } from "@/lib/scans";

export const dynamic = "force-dynamic";

const TIER_LABEL: Record<string, string> = {
  money: "money",
  real_world_actions: "real-world",
  customer_data: "customer-data",
  business_data: "business-data",
  llm: "llm",
  general: "general",
};

const TIER_TONE: Record<string, string> = {
  money: "#fb7185",
  real_world_actions: "#fbbf24",
  customer_data: "#f472b6",
  business_data: "#facc15",
  llm: "#22d3ee",
  general: "#a1a1aa",
};

export default async function RepoFindingsPage({
  params,
  searchParams,
}: {
  params: Promise<{ repo_id: string }>;
  searchParams: Promise<{ tier?: string; confidence?: "low" | "medium" | "high" }>;
}) {
  const { repo_id } = await params;
  const sp = await searchParams;
  const findings = await getRepoFindings(repo_id, {
    tier: sp.tier,
    confidence: sp.confidence,
    limit: 500,
  });

  return (
    <div>
      <div className="row" style={{ gap: 16, marginBottom: 12, flexWrap: "wrap" }}>
        <FilterChip currentKey="tier" currentValue={sp.tier} target="" label="All tiers" />
        <FilterChip currentKey="tier" currentValue={sp.tier} target="money" label="Money" />
        <FilterChip currentKey="tier" currentValue={sp.tier} target="real_world_actions" label="Real-world" />
        <FilterChip currentKey="tier" currentValue={sp.tier} target="customer_data" label="Customer data" />
        <FilterChip currentKey="tier" currentValue={sp.tier} target="business_data" label="Business" />
        <FilterChip currentKey="tier" currentValue={sp.tier} target="llm" label="LLM" />
        <FilterChip currentKey="tier" currentValue={sp.tier} target="general" label="General" />
      </div>

      {findings.length === 0 ? (
        <div className="card" style={{ padding: 20 }}>
          <p className="muted">No findings match this filter.</p>
        </div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <Th>Tier</Th>
                <Th>File</Th>
                <Th>Scanner</Th>
                <Th>Action type</Th>
                <Th>Confidence</Th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f, i) => (
                <FindingRow key={`${f.file}:${f.line}:${i}`} f={f} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function FindingRow({ f }: { f: ScanFinding }) {
  const tier = f.tier ?? "general";
  const tone = TIER_TONE[tier] ?? "#a1a1aa";
  return (
    <tr>
      <Td>
        <span className="mono" style={{ color: tone, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.08em" }}>
          {TIER_LABEL[tier] ?? tier}
        </span>
      </Td>
      <Td>
        <span className="mono" style={{ fontSize: 13, color: "#e4e4e7" }}>{f.file}</span>
        <span className="muted mono" style={{ fontSize: 13 }}>:{f.line}</span>
        <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>{f.rationale}</div>
      </Td>
      <Td>
        <span className="mono" style={{ fontSize: 11, color: "#a1a1aa" }}>{f.scanner}</span>
      </Td>
      <Td>
        <span className="mono" style={{ fontSize: 11, padding: "2px 6px", background: "#27272a", borderRadius: 4, color: "#d4d4d8" }}>
          {f.suggested_action_type}
        </span>
      </Td>
      <Td>
        <ConfidenceDot confidence={f.confidence} />
      </Td>
    </tr>
  );
}

function ConfidenceDot({ confidence }: { confidence: "low" | "medium" | "high" }) {
  const color = confidence === "high" ? "#22c55e" : confidence === "medium" ? "#f59e0b" : "#71717a";
  return (
    <span className="row" style={{ gap: 6, alignItems: "center" }}>
      <span style={{ width: 8, height: 8, borderRadius: 999, background: color, display: "inline-block" }} />
      <span className="mono" style={{ fontSize: 12, color }}>{confidence}</span>
    </span>
  );
}

function FilterChip({
  currentKey,
  currentValue,
  target,
  label,
}: {
  currentKey: "tier";
  currentValue: string | undefined;
  target: string;
  label: string;
}) {
  const active = (currentValue ?? "") === target;
  const href = target ? `?${currentKey}=${encodeURIComponent(target)}` : "?";
  return (
    <a
      href={href}
      className="mono"
      style={{
        fontSize: 12,
        padding: "4px 10px",
        borderRadius: 6,
        border: active ? "1px solid #10b981" : "1px solid #27272a",
        color: active ? "#34d399" : "#a1a1aa",
        textDecoration: "none",
      }}
    >
      {label}
    </a>
  );
}

function Th({ children }: { children?: React.ReactNode }) {
  return (
    <th style={{ padding: "10px 14px", textAlign: "left", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.1em", color: "#71717a", borderBottom: "1px solid #27272a" }}>
      {children}
    </th>
  );
}

function Td({ children }: { children?: React.ReactNode }) {
  return (
    <td style={{ padding: "12px 14px", fontSize: 14, borderBottom: "1px solid #27272a", verticalAlign: "top" }}>
      {children}
    </td>
  );
}
