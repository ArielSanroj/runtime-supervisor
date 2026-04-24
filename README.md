# runtime-supervisor

Runtime control layer that gates AI-agent actions against declarative policy + risk scoring, with a tamper-evident evidence log and a human review queue.
> **Live demo:** [Vibefixing — AI agent security scanner for vibe coders](https://www.vibefixing.me)
**Phase 1** ships refund supervision (live). **Phase 2** adds the integration API (JWT-auth per app, outbound webhooks, Python + TypeScript SDKs, MCP server, repo-aware agent).

## Quick start

```bash
cp .env.example .env
docker compose up -d postgres
cd services/supervisor_api
uv sync
uv run alembic upgrade head
uv run python -m supervisor_api.seed        # creates control-center integration, seeds 5 fixtures
uv run uvicorn supervisor_api.main:app --reload
```

In another terminal:

```bash
cd apps/control-center
pnpm install
pnpm dev
```

- API: http://localhost:8000 (docs: `/docs`)
- Public landing: http://localhost:3000
- Reviewer console: http://localhost:3000/dashboard · http://localhost:3000/review

## Integration API — connect an external agent

All external writes (evaluate, resolve review, read evidence) flow through `/v1/*` endpoints. When `REQUIRE_AUTH=true`, they require a JWT HS256 token signed with the integration's shared secret. `/v1/action-types` and `/healthz` remain public.

### 1 · Register your app (admin, one-time)

```bash
curl -s -X POST http://localhost:8000/v1/integrations \
  -H "X-Admin-Token: $ADMIN_BOOTSTRAP_TOKEN" \
  -H "content-type: application/json" \
  -d '{"name":"acme-refund-agent","scopes":["refund"]}'
# → {"id":"…","shared_secret":"kX…","…"}    (secret shown once)
```

Rotate with `POST /v1/integrations/{id}/rotate-secret`, revoke with `/revoke`.

### 2 · Call evaluate with a signed JWT

Option A — **Python SDK** (`packages/supervisor-client-py`):

```python
from supervisor_client import Client
with Client(base_url="http://localhost:8000",
            app_id=INTEG_ID, shared_secret=SECRET,
            scopes=["refund"]) as sup:
    d = sup.evaluate("refund", {
        "amount": 420, "customer_id": "c1",
        "customer_age_days": 18, "refund_velocity_24h": 2, "reason": "changed_mind",
    })
    if d.allowed: execute_refund()
    elif d.blocked: reject(d.reasons)
    else: queue_for_review(d.action_id)
```

Option B — **TypeScript SDK** (`packages/supervisor-client-ts`, runs in Node/Browser/Edge/Deno/Bun via Web Crypto):

```ts
import { Client } from "@runtime-supervisor/client";
const sup = new Client({ baseUrl, appId, sharedSecret, scopes: ["refund"] });
const d = await sup.evaluate("refund", { amount: 420, /* … */ });
```

Option C — **MCP server** (`packages/mcp-supervisor`) — expose `evaluate_action`, `list_action_types`, `get_evidence` to Claude Desktop / Claude Code / any MCP-aware client. See `packages/mcp-supervisor/README.md` for config.

Option D — **Raw HTTP**: sign your own JWT (`alg: HS256`, claims `sub=integration_id`, `scopes`, `exp`), send `Authorization: Bearer <jwt>`.

### 3 · Receive outbound webhooks (optional)

Subscribe your app to events:

```bash
curl -s -X POST "http://localhost:8000/v1/integrations/$ID/webhooks" \
  -H "X-Admin-Token: $ADMIN_BOOTSTRAP_TOKEN" \
  -d '{"url":"https://you.example.com/hook","events":["decision.made","review.resolved","action.denied"]}'
```

The supervisor will POST JSON to that URL with an `x-supervisor-signature: sha256=<hex>` header (HMAC-SHA256 of the raw body using `WEBHOOK_SECRET`). Verify before trusting the payload.

Delivery history: `GET /v1/integrations/{id}/webhooks/{sub_id}/deliveries`.

### Action type catalog

`GET /v1/action-types` returns every action type, `live` or `planned`. The public landing renders from this — when you ship a new supervisor, marketing copy updates itself.

## Layout

```
services/supervisor_api/    FastAPI, Alembic, engines, evidence, auth, webhooks
apps/control-center/        Next.js 15 — public landing + reviewer console
packages/policies/          YAML policies per action type
packages/supervisor-client-py/   Python SDK
packages/supervisor-client-ts/   TypeScript SDK
packages/mcp-supervisor/    MCP stdio server exposing supervisor tools
.claude/agents/             Claude Code subagent (repo-aware guide)
```

## Ask the repo (Claude Code subagent)

Inside a Claude Code session in this repo, invoke:

```
Task({ subagent_type: "runtime-supervisor-guide", prompt: "how do I add a payment supervisor?" })
```

The subagent reads the live code and answers against current state.

## Tests

```bash
uv run --all-packages pytest                 # backend + python sdk
cd packages/supervisor-client-ts && pnpm test # typescript sdk
cd apps/control-center && pnpm typecheck     # frontend
```

## Phase 3 candidates

- Async webhook delivery with retry queue + exponential backoff
- Policy editor UI with versioning & hot-reload
- `action_proxy` that executes approved actions against downstream systems
- Multi-tenant (org scoping on integrations + evidence)
- OpenTelemetry instrumentation
- Additional supervisors: payment, account-change, data-access, tool-use, compliance
