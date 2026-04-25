# @runtime-supervisor/guards

Wrap unsafe agent actions with one decorator. Shadow-mode by default — logs *would-have-blocked* without interrupting production traffic. Flip to `enforce` only when you've seen enough shadow data to trust the policy.

Works with any Node 20+ app. For the Python equivalent, see [`supervisor-guards`](https://pypi.org/project/supervisor-guards/) (same semantics, same env vars).

## Install

```bash
npm i @runtime-supervisor/guards @runtime-supervisor/client
```

## Configure once

```ts
import { configure } from "@runtime-supervisor/guards";

configure({
  baseUrl: process.env.SUPERVISOR_BASE_URL,   // e.g. https://vibefixing.ngrok.app
  appId: process.env.SUPERVISOR_APP_ID,       // from POST /v1/integrations
  sharedSecret: process.env.SUPERVISOR_SECRET,
  enforcementMode: "shadow",                   // "shadow" (default) | "sample" | "enforce"
});
```

All config reads env vars as fallback, so the call above can be zero-arg if you set `SUPERVISOR_*` in your environment. `SUPERVISOR_ENFORCEMENT_MODE` flips the mode without a code change.

## Wrap an action

Two forms — pick whichever reads better for the call site.

### Imperative (easier to bolt onto existing code):

```ts
import { guarded } from "@runtime-supervisor/guards";

async function sendReceiptEmail(user, order) {
  return guarded("email_send", { to: user.email, subject: "Your receipt" }, async () => {
    return mailer.send({ to: user.email, subject: "Your receipt", html: renderReceipt(order) });
  });
}
```

If the supervisor would deny, `guarded` throws `SupervisorBlocked`. In `shadow` mode (default) the call always runs and a `would-have-blocked` is logged + sent to your dashboard.

### Decorator (cleaner when you have the function ahead of time):

```ts
import { supervised } from "@runtime-supervisor/guards";

const doRefund = supervised("refund", {
  payloadFrom: (orderId: string, amount: number) => ({
    order_id: orderId,
    amount,
    currency: "USD",
  }),
})(async (orderId: string, amount: number) => {
  return stripe.refunds.create({ payment_intent: orderId, amount });
});

// Use normally — the supervisor check happens before stripe is called.
await doRefund("pi_abc", 4200);
```

## Modes (via `SUPERVISOR_ENFORCEMENT_MODE`)

| Mode       | Behavior                                                                 |
| ---------- | ------------------------------------------------------------------------ |
| `shadow`   | Always allow; log every would-be-block. **Default.** Safe to deploy day-1. |
| `sample`   | Enforce for `SUPERVISOR_SAMPLE_PERCENT` of traffic (hash-stable), shadow the rest. |
| `enforce`  | Block denies, wait for review approval on escalations.                   |

## On-review behavior

When the supervisor escalates an action to human review, you choose what the wrapped function does:

```ts
configure({ defaultOnReview: "block" });
```

- `block` (default) — polls until reviewer approves/rejects, up to `reviewTimeoutMs`. Timeout counts as deny.
- `fail_closed` — throws `SupervisorReviewPending` immediately. Use when you can't hold the call.
- `fail_open` — proceeds as if allowed. Use only when the action is fully reversible.
- `shadow` — logs and proceeds. For passive observation.

Override per call site via `opts.onReview` / 4th arg to `guarded`.

## Errors

```ts
import { SupervisorBlocked, SupervisorReviewPending } from "@runtime-supervisor/guards";

try {
  await doRefund("pi_abc", 99999);
} catch (e) {
  if (e instanceof SupervisorBlocked) {
    // policy denied; e.reasons explains why, e.actionId is the audit reference
  } else if (e instanceof SupervisorReviewPending) {
    // fail_closed mode; action is queued for review
  }
}
```

## What you see in the dashboard

Every guarded call — shadow, sample, or enforce — shows up at [vibefixing.me/dashboard](https://vibefixing.me/dashboard): live decisions, would-block rate, pending reviews, latency p95. Shadow mode is how you build confidence before flipping `enforce`.

## License

Apache-2.0. Copyright 2026 Ariel San Martín.
