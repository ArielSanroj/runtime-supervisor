import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "Vibefixing — AI Agent Security Scanner";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default async function OpengraphImage() {
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
          backgroundImage: "radial-gradient(ellipse at top, rgba(52,211,153,0.18), rgba(0,0,0,0) 60%)",
          color: "#e6e9ef",
          fontFamily: "ui-sans-serif, system-ui, sans-serif",
        }}
      >
        <div style={{ display: "flex", alignItems: "baseline", gap: 14, fontFamily: "ui-monospace, monospace", fontSize: 28 }}>
          <span style={{ color: "#34d399" }}>$</span>
          <span style={{ color: "#fff", fontWeight: 700 }}>vibefixing</span>
          <span style={{ color: "#71717a" }}>// runtime-supervisor</span>
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
            for vibe coders shipping AI agents
          </div>
          <div
            style={{
              fontSize: 88,
              fontWeight: 700,
              letterSpacing: "-0.025em",
              lineHeight: 1.04,
              color: "#fafafa",
              maxWidth: 1000,
              display: "flex",
              flexWrap: "wrap",
            }}
          >
            <span>Ship AI agents with&nbsp;</span>
            <span
              style={{
                background: "linear-gradient(90deg,#6ee7b7,#34d399,#a7f3d0)",
                backgroundClip: "text",
                color: "transparent",
                WebkitBackgroundClip: "text",
              }}
            >
              guardrails
            </span>
            <span>.</span>
          </div>
          <div style={{ display: "flex", color: "#a1a1aa", fontSize: 30, lineHeight: 1.4, maxWidth: 980 }}>
            Scan your repo for unsafe tool calls before an LLM touches Stripe, your DB, or customer data.
          </div>
        </div>

        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", color: "#71717a", fontFamily: "ui-monospace, monospace", fontSize: 22 }}>
          <div style={{ display: "flex", gap: 24 }}>
            <span>vibefixing.me</span>
            <span style={{ color: "#3f3f46" }}>·</span>
            <span>free public scan</span>
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
