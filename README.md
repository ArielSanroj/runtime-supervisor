# Agentic Internal Controls

Supervisor runtime that gates agent actions (refunds, payments, data access, etc.) against declarative policies and risk scoring, with a tamper-evident evidence log and a human review queue.

**Phase 1 scope: refund supervision MVP.**

## Quick start

```bash
cp .env.example .env
docker compose up -d postgres
cd services/supervisor_api
uv sync
uv run alembic upgrade head
uv run python -m supervisor_api.seed
uv run uvicorn supervisor_api.main:app --reload
```

In another terminal:

```bash
cd apps/control-center
pnpm install
pnpm dev
```

- API: http://localhost:8000  (docs: http://localhost:8000/docs)
- Control center: http://localhost:3000

## Smoke test

```bash
curl -s -X POST http://localhost:8000/v1/actions/evaluate \
  -H 'content-type: application/json' \
  -d '{"action_type":"refund","payload":{"amount":50,"currency":"USD","customer_id":"c1","customer_age_days":730,"refund_velocity_24h":0,"reason":"defective"}}' | jq
```

## Layout

```
services/supervisor_api/   FastAPI + SQLAlchemy, engines, evidence log
packages/policies/         Declarative policy YAMLs
apps/control-center/       Next.js reviewer UI
```

## Phase 2 candidates

- Reviewer authn/z (OAuth/SSO), audit of reviewers themselves
- `action_proxy` that executes approved actions against the downstream system
- Additional supervisors: payment, data access, account change
- Policy editor in UI with versioning & hot-reload
- Multi-tenant, rate limits, webhooks, metrics (OpenTelemetry)
