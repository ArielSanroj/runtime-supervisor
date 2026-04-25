# supervisor-guards

Wrap unsafe agent actions with one decorator. Shadow-mode by default — logs *would-have-blocked* without interrupting production traffic. Flip to `enforce` only when you've seen enough shadow data to trust the policy.

Works with any Python 3.10+ app. For the TypeScript equivalent, see [`@runtime-supervisor/guards`](https://www.npmjs.com/package/@runtime-supervisor/guards) (same semantics, same env vars).

## Install

```bash
pip install supervisor-guards
```

## Configure once

```python
from supervisor_guards import configure

configure(
    base_url="https://vibefixing.ngrok.app",
    app_id=os.environ["SUPERVISOR_APP_ID"],         # from POST /v1/integrations
    shared_secret=os.environ["SUPERVISOR_SECRET"],
    enforcement_mode="shadow",                        # "shadow" (default) | "sample" | "enforce"
)
```

All config reads env vars as fallback, so the call above can be zero-arg if you set `SUPERVISOR_*` in your environment. `SUPERVISOR_ENFORCEMENT_MODE` flips the mode without a code change.

## Wrap an action

Two forms — pick whichever reads better for the call site.

### Decorator — sync or async:

```python
from supervisor_guards import supervised, supervised_async

@supervised_async(
    "refund",
    payload=lambda order_id, amount: {"order_id": order_id, "amount": amount, "currency": "USD"},
)
async def do_refund(order_id: str, amount: int) -> dict:
    return await stripe.refunds.create_async(payment_intent=order_id, amount=amount)

# Use normally — the supervisor check happens before stripe is called.
await do_refund("pi_abc", 4200)
```

For synchronous functions, use `@supervised(...)` with the same `payload=` kwarg. If you omit `payload=`, the decorator captures `(args, kwargs)` as the payload automatically.

### Imperative (easier to bolt onto existing code):

```python
from supervisor_guards import guarded

def send_receipt_email(user, order):
    return guarded(
        "email_send",
        {"to": user.email, "subject": "Your receipt"},
        mailer.send,
        to=user.email,
        subject="Your receipt",
        html=render_receipt(order),
    )
```

`guarded(action_type, payload, fn, *args, **kwargs)` pre-checks then calls `fn(*args, **kwargs)`. For async, wrap with `asyncio.to_thread` or use the `supervised_async` decorator.

If the supervisor would deny, `guarded` raises `SupervisorBlocked`. In `shadow` mode (default) the call always runs and a `would-have-blocked` is logged + sent to your dashboard.

## Modes (via `SUPERVISOR_ENFORCEMENT_MODE`)

| Mode       | Behavior                                                                 |
| ---------- | ------------------------------------------------------------------------ |
| `shadow`   | Always allow; log every would-be-block. **Default.** Safe to deploy day-1. |
| `sample`   | Enforce for `SUPERVISOR_SAMPLE_PERCENT` of traffic (hash-stable), shadow the rest. |
| `enforce`  | Block denies, wait for review approval on escalations.                   |

## On-review behavior

When the supervisor escalates an action to human review, you choose what the wrapped function does:

```python
configure(default_on_review="block")
```

- `block` (default) — polls until reviewer approves/rejects, up to `review_timeout_ms`. Timeout counts as deny.
- `fail_closed` — raises `SupervisorReviewPending` immediately. Use when you can't hold the call.
- `fail_open` — proceeds as if allowed. Use only when the action is fully reversible.
- `shadow` — logs and proceeds. For passive observation.

Override per call site via `on_review=` kwarg.

## Errors

```python
from supervisor_guards import SupervisorBlocked, SupervisorReviewPending

try:
    await do_refund("pi_abc", 99999)
except SupervisorBlocked as e:
    # policy denied; e.reasons explains why, e.action_id is the audit reference
    log.warn("blocked by supervisor", reasons=e.reasons)
except SupervisorReviewPending as e:
    # fail_closed mode; action is queued for review
    enqueue_manual_review(e.action_id)
```

## What you see in the dashboard

Every guarded call — shadow, sample, or enforce — shows up at [vibefixing.me/dashboard](https://vibefixing.me/dashboard): live decisions, would-block rate, pending reviews, latency p95. Shadow mode is how you build confidence before flipping `enforce`.

## License

Apache-2.0. Copyright 2026 Ariel San Martín.
