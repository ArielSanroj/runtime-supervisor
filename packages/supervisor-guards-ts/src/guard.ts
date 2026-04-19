import { getClient, getDefaultOnReview, getPollIntervalMs, getTimeoutMs, type OnReview } from "./config.js";
import { SupervisorBlocked, SupervisorReviewPending } from "./errors.js";

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
  const client = getClient();
  const dec = await client.evaluate(actionType, payload);

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
