import { ImageResponse } from "next/og";
import { buildEnglishBanner, getScan, type RepoSummary, type ScanResponse } from "@/lib/scans";

export const runtime = "nodejs";
export const alt = "Vibefixing — scan result";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

type Props = {
  params: { scan_id: string };
};

type Counts = {
  priority: number;
  combos: number;
  general: number;
};

function counts(scan: ScanResponse): Counts {
  const findings = scan.findings ?? [];
  const priority = findings.filter((f) => {
    const tier = f.tier ?? "general";
    return tier !== "general";
  }).length;
  const general = findings.filter((f) => (f.tier ?? "general") === "general").length;
  return { priority, combos: (scan.combos ?? []).length, general };
}

function safeBanner(summary: RepoSummary | null | undefined): string {
  if (!summary) return "your repo";
  try {
    return buildEnglishBanner(summary);
  } catch {
    return "your repo";
  }
}

export default async function OG({ params }: Props) {
  const { scan_id } = params;
  let banner = "your repo";
  let stats: Counts = { priority: 0, combos: 0, general: 0 };
  let status: ScanResponse["status"] | "unknown" = "unknown";
  try {
    const scan = await getScan(scan_id, null);
    status = scan.status;
    banner = safeBanner(scan.repo_summary ?? null);
    stats = counts(scan);
  } catch {
    // fall through to defaults; we'd rather ship a generic card than 500
  }

  const headline = status === "done"
    ? `Wraps for ${banner}.`
    : status === "queued" || status === "scanning"
    ? "Scan in progress."
    : "Scan result.";

  const totalCalled = stats.priority + stats.combos + stats.general;

  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          padding: 80,
          backgroundColor: "#000000",
          backgroundImage:
            "radial-gradient(ellipse at top, rgba(52,211,153,0.18), rgba(0,0,0,0) 60%)",
          color: "#e6e9ef",
          fontFamily: "ui-sans-serif, system-ui, sans-serif",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "baseline",
            gap: 14,
            fontFamily: "ui-monospace, monospace",
            fontSize: 28,
          }}
        >
          <span style={{ color: "#34d399" }}>$</span>
          <span style={{ color: "#fff", fontWeight: 700 }}>vibefixing</span>
          <span style={{ color: "#71717a" }}>// scan {scan_id.slice(0, 8)}</span>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 28 }}>
          <div
            style={{
              alignSelf: "flex-start",
              display: "flex",
              padding: "8px 18px",
              borderRadius: 999,
              border: "1px solid rgba(52,211,153,0.35)",
              background: "rgba(52,211,153,0.10)",
              color: "#6ee7b7",
              fontFamily: "ui-monospace, monospace",
              fontSize: 22,
            }}
          >
            risk-ranked card layout
          </div>
          <div
            style={{
              fontSize: 76,
              fontWeight: 700,
              letterSpacing: "-0.025em",
              lineHeight: 1.05,
              color: "#fafafa",
              maxWidth: 1040,
              display: "flex",
              flexWrap: "wrap",
            }}
          >
            <span>{headline.split(banner)[0]}</span>
            {headline.includes(banner) && (
              <span
                style={{
                  background: "linear-gradient(90deg,#6ee7b7,#34d399,#a7f3d0)",
                  backgroundClip: "text",
                  color: "transparent",
                  WebkitBackgroundClip: "text",
                }}
              >
                {banner}
              </span>
            )}
            {headline.includes(banner) && <span>.</span>}
          </div>
          {totalCalled > 0 && status === "done" && (
            <div
              style={{
                display: "flex",
                gap: 36,
                color: "#a1a1aa",
                fontSize: 28,
                lineHeight: 1.3,
              }}
            >
              <div style={{ display: "flex", gap: 12 }}>
                <span style={{ color: "#fafafa", fontWeight: 700 }}>{stats.priority}</span>
                <span>priority findings</span>
              </div>
              <div style={{ display: "flex", gap: 12 }}>
                <span style={{ color: "#fafafa", fontWeight: 700 }}>{stats.combos}</span>
                <span>combos</span>
              </div>
            </div>
          )}
        </div>

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            color: "#71717a",
            fontFamily: "ui-monospace, monospace",
            fontSize: 22,
          }}
        >
          <div style={{ display: "flex", gap: 24 }}>
            <span>vibefixing.me</span>
            <span style={{ color: "#3f3f46" }}>·</span>
            <span>shareable scan</span>
          </div>
          <div style={{ display: "flex", gap: 12, color: "#34d399" }}>
            <span>scan your repo →</span>
          </div>
        </div>
      </div>
    ),
    { ...size },
  );
}
