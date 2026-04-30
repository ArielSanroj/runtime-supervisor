/**
 * Telemetry-driven nudge from shadow → enforce.
 *
 * Background: customers install runtime-supervisor in shadow mode by
 * default (the wrappers log but never block). Without a UI signal,
 * shadow becomes the permanent state — which is what happened in the
 * Andrea/cliocsbot incident: 6 days in shadow, 0 nudges, the gate
 * never fired.
 *
 * This component reads `/v1/metrics/enforcement` and renders one of
 * four states:
 *
 *   - warmup  (shadow_evaluations > 0 but window too short)
 *   - ready   (would_block > 0, FP < 5%, soak ≥ readiness threshold)
 *   - tune    (FP ≥ 5%, the dev should review policies first)
 *   - idle    (no shadow evaluations recorded — wiring or traffic gap)
 *
 * Server Component: no client interactivity required for v1; the
 * `[Flip to enforce]` action is a future hook (the API endpoint is
 * also out of scope for this PR — the readout is value on its own).
 */
import { getEnforcementReadiness, type EnforcementReadiness as ReadinessData } from "@/lib/metrics";

const READY_FP_CEILING = 0.05; // 5% — same gate as ROLLOUT.md's "tune policies"
const WARMUP_DAYS = 3;          // any window <3d is warmup; 7d is the readiness target

function daysSince(iso: string): number {
  return (Date.now() - new Date(iso).getTime()) / (1000 * 60 * 60 * 24);
}

function classify(d: ReadinessData): {
  state: "warmup" | "ready" | "tune" | "idle";
  copy: string;
  hint: string;
  tone: "good" | "warn" | "danger" | "muted";
} {
  const days = Math.max(0, daysSince(d.since));
  const wb = d.would_block_in_shadow;
  const fp = d.estimated_false_positive_rate;

  // No shadow traffic at all → wiring or zero-traffic gap.
  if (d.shadow_evaluations === 0 && d.enforced_evaluations === 0) {
    return {
      state: "idle",
      copy: "No supervisor traffic in this window.",
      hint:
        "Either the wrappers aren't installed yet, or your app hasn't received requests that " +
        "hit a supervised call-site. Check `runtime-supervisor/IMPLEMENTED.md` for the wrap " +
        "list and confirm the env vars are set on prod.",
      tone: "muted",
    };
  }

  // Soaking — too early to make a call. Show what's been seen so the
  // user knows the wrappers are alive, but don't suggest a flip yet.
  if (days < WARMUP_DAYS) {
    return {
      state: "warmup",
      copy: `Soaking — ${days.toFixed(1)} days in shadow so far.`,
      hint: `Keep going. Once you have ≥${WARMUP_DAYS} days of data and the FP rate looks clean, this card will recommend flipping to enforce.`,
      tone: "muted",
    };
  }

  // Have enough soak time + would-blocks. Decide ready vs tune by FP rate.
  if (wb > 0) {
    if (fp !== null && fp >= READY_FP_CEILING) {
      const pct = Math.round(fp * 100);
      return {
        state: "tune",
        copy: `${pct}% of escalations were later approved by a reviewer.`,
        hint:
          "FP rate is high enough that flipping to enforce would block legitimate traffic. " +
          "Open the policy editor and tighten the rules that matched those approved cases.",
        tone: "warn",
      };
    }
    return {
      state: "ready",
      copy: `${wb} call(s) would block today. FP rate ${fp === null ? "unmeasured" : `${Math.round(fp * 100)}%`}.`,
      hint:
        "Set `SUPERVISOR_ENFORCEMENT_MODE=enforce` on the prod environment. " +
        "The wrappers re-read the env at request time, so no redeploy is needed.",
      tone: "good",
    };
  }

  // Soak met, but zero would-blocks → policies aren't matching, OR there
  // hasn't been a risky call yet. Either way, flipping to enforce is safe
  // but doesn't actually change anything.
  return {
    state: "idle",
    copy: "No would-blocks recorded.",
    hint:
      "Either your policies are over-permissive for the traffic you saw, or the agent " +
      "hasn't tried anything risky in this window. Worth checking the policy `when:` " +
      "expressions against a known bad payload.",
    tone: "muted",
  };
}

const TONE_BG: Record<"good" | "warn" | "danger" | "muted", string> = {
  good: "rgba(16, 185, 129, 0.06)",
  warn: "rgba(245, 158, 11, 0.06)",
  danger: "rgba(239, 68, 68, 0.06)",
  muted: "rgba(148, 163, 184, 0.05)",
};

const TONE_BORDER: Record<"good" | "warn" | "danger" | "muted", string> = {
  good: "rgba(16, 185, 129, 0.32)",
  warn: "rgba(245, 158, 11, 0.32)",
  danger: "rgba(239, 68, 68, 0.32)",
  muted: "rgba(148, 163, 184, 0.18)",
};

const TONE_LABEL: Record<"warmup" | "ready" | "tune" | "idle", string> = {
  warmup: "soaking",
  ready: "ready to enforce",
  tune: "tune policies",
  idle: "idle",
};

export default async function EnforcementReadiness() {
  let data: ReadinessData;
  try {
    data = await getEnforcementReadiness("7d");
  } catch (e) {
    // Don't break the dashboard if telemetry is unreachable. The card
    // becomes a no-op so the rest of the page renders.
    return null;
  }

  const verdict = classify(data);
  return (
    <div
      className="card"
      style={{
        marginTop: 20,
        padding: 16,
        backgroundColor: TONE_BG[verdict.tone],
        borderColor: TONE_BORDER[verdict.tone],
      }}
    >
      <div className="row" style={{ alignItems: "baseline", justifyContent: "space-between" }}>
        <div className="eyebrow">// rollout</div>
        <span className="badge" style={{ fontSize: 11 }}>{TONE_LABEL[verdict.state]}</span>
      </div>
      <h3 style={{ marginTop: 8, marginBottom: 4 }}>Enforcement readiness</h3>
      <p style={{ margin: 0, fontSize: 14 }}>{verdict.copy}</p>
      <p className="muted" style={{ margin: "8px 0 0", fontSize: 13, lineHeight: 1.55 }}>
        {verdict.hint}
      </p>
      <div className="row" style={{ marginTop: 12, gap: 16, fontSize: 12, color: "var(--muted)" }}>
        <span>shadow: {data.shadow_evaluations}</span>
        <span>would-block: {data.would_block_in_shadow}</span>
        <span>enforced: {data.enforced_evaluations}</span>
        <span>actually-blocked: {data.actually_blocked}</span>
        <span>p95: {data.latency_ms.p95}ms</span>
      </div>
    </div>
  );
}
