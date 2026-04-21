import { createHash, randomUUID } from "node:crypto";
import {
  getAppId,
  getClient,
  getDefaultOnReview,
  getEnforcementMode,
  getPollIntervalMs,
  getSamplePercent,
  getTimeoutMs,
  type OnReview,
} from "./config.js";
import { SupervisorBlocked, SupervisorReviewPending } from "./errors.js";

function shouldShadow(actionType: string): boolean {
  const mode = getEnforcementMode();
  if (mode === "shadow") return true;
  if (mode === "enforce") return false;
  const pct = getSamplePercent();
  if (pct <= 0) return true;
  if (pct >= 100) return false;
  const token = `${getAppId()}:${actionType}:${randomUUID()}`;
  const hex = createHash("sha256").update(token).digest("hex");
  const bucket = Number(BigInt("0x" + hex) % 100n);
  return bucket >= pct;
}

async function pollReview(actionId: string): Promise<"allow" | "deny"> {
  const client = getClient();
  const deadline = Date.now() + getTimeoutMs();
  while (Date.now() < deadline) {
    for (const status of ["approved", "rejected"] as const) {
      try {
        const rows = await client.listReviews(status);
        if (rows.some((r) => r.action_id === actionId)) {
          return status === "approved" ? "allow" : "deny";
        }
      } catch {
        /* swallow transient errors and keep polling */
      }
    }
    await new Promise((r) => setTimeout(r, getPollIntervalMs()));
  }
  return "deny"; // timeout = fail closed
}

async function preCheck(
  actionType: string,
  payload: Record<string, unknown>,
  onReview: OnReview | undefined,
): Promise<string | undefined> {
  const mode: OnReview = onReview ?? getDefaultOnReview();
  const shadow = mode === "shadow" ? true : shouldShadow(actionType);
  const client = getClient();
  const dec = await client.evaluate(actionType, payload, { shadow });

  if (shadow) {
    // Server always returns allow in shadow mode; log the would-have so
    // ops can trace blocks before flipping enforcement on.
    if (dec.shadow_would_have && dec.shadow_would_have !== "allow") {
      // eslint-disable-next-line no-console
      console.info(
        `[supervisor-guards] shadow would have ${dec.shadow_would_have} for ${actionType} (action_id=${dec.action_id})`,
      );
    }
    return dec.action_id;
  }

  if (dec.decision === "allow") return dec.action_id;
  if (dec.decision === "deny") {
    throw new SupervisorBlocked("deny", dec.reasons, dec.action_id);
  }

  // review
  if (mode === "fail_open") return dec.action_id;
  if (mode === "fail_closed") {
    throw new SupervisorReviewPending(dec.action_id, dec.reasons);
  }
  const resolved = await pollReview(dec.action_id);
  if (resolved === "allow") return dec.action_id;
  throw new SupervisorBlocked("deny", ["review-rejected-or-timed-out"], dec.action_id);
}

export interface SupervisedOpts<TArgs extends unknown[]> {
  payloadFrom: (...args: TArgs) => Record<string, unknown>;
  onReview?: OnReview;
}

/** Higher-order function: wraps an async function so the supervisor
 * evaluates the payload BEFORE the function runs. */
export function supervised<TArgs extends unknown[], TResult>(
  actionType: string,
  opts: SupervisedOpts<TArgs>,
): (fn: (...args: TArgs) => Promise<TResult>) => (...args: TArgs) => Promise<TResult> {
  return (fn) => async (...args: TArgs) => {
    const payload = opts.payloadFrom(...args);
    await preCheck(actionType, payload, opts.onReview);
    return fn(...args);
  };
}

/** Imperative form. */
export async function guarded<TResult>(
  actionType: string,
  payload: Record<string, unknown>,
  fn: () => Promise<TResult> | TResult,
  onReview?: OnReview,
): Promise<TResult> {
  await preCheck(actionType, payload, onReview);
  return fn();
}
