# supervisor-client

Python client for [runtime-supervisor](https://github.com/ArielSanroj/runtime-supervisor). Signs HS256 JWTs, handles auth headers, typed responses.

## Install

```bash
pip install supervisor-client  # once published
# for local development:
uv pip install -e packages/supervisor-client-py
```

## Register an integration (one-time, admin)

```bash
curl -s -X POST https://supervisor.example.com/v1/integrations \
  -H "X-Admin-Token: $ADMIN_BOOTSTRAP_TOKEN" \
  -H "content-type: application/json" \
  -d '{"name":"acme-refund-agent","scopes":["refund"]}'
# -> {"id": "...", "shared_secret": "kX...", ...}   (secret shown once)
```

## Use from an agent

```python
from supervisor_client import Client, SupervisorError

with Client(
    base_url="https://supervisor.example.com",
    app_id="acme-refund-agent",
    shared_secret=os.environ["SUPERVISOR_SECRET"],
    scopes=["refund"],
) as sup:
    try:
        decision = sup.evaluate("refund", {
            "amount": 420, "currency": "USD",
            "customer_id": "c_1234", "customer_age_days": 18,
            "refund_velocity_24h": 2, "reason": "changed_mind",
        })
    except SupervisorError as e:
        # network or validation failure: fail-closed
        raise

    if decision.allowed:
        execute_refund(...)
    elif decision.blocked:
        notify_user("refund policy blocked this request")
    else:  # needs_review
        enqueue_for_human_review(decision.action_id)
```

## Dry-run ("what would the supervisor do?")

```python
decision = sup.evaluate("refund", payload, dry_run=True)
# no row written to the supervisor; decision.action_id == "dry-run"
```
