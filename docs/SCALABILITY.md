# Scalability roadmap — Vibefixing

> Internal engineering doc. Audience: senior full-stack engineers working on
> the runtime-supervisor monorepo. Not user-facing copy.

This document maps the Vibefixing platform's current architecture, the
bottlenecks that gate scale, and the phased changes that unlock the next
order of magnitude. It is grounded in the real codebase — every file path
cited exists today.

---

## 1. Executive summary

| Dimension | Today (Phase 0) | Breaks at | Cause |
|---|---|---|---|
| Concurrent scans | ~5 in-flight | ~50 | `POST /v1/scans` runs in FastAPI `BackgroundTasks` |
| Tenants on one VPS | ~50 | ~500 | Single Postgres + single API replica |
| Webhook deliveries | ~1k/day | ~100k/day | Single retry worker, no leader election |
| Evaluate p95 latency | ~80 ms | ~500 ms at 500 RPS | Per-process policy cache + sync DB hit |
| Geographic latency | EU-only egress | non-EU users | Single VPS, no edge |

**Top 4 hard bottlenecks** (all observable in code today):

1. In-process rate limiter — `services/supervisor_api/src/supervisor_api/ratelimit.py`
2. Single-process retry worker — `services/supervisor_api/src/supervisor_api/retry_worker.py`
3. Per-process policy cache — `services/supervisor_api/src/supervisor_api/policy_engine.py`
4. In-process scan execution — `services/supervisor_api/src/supervisor_api/routes/scans.py`

Phase 1 (~2 weeks of focused work) clears items 1-3 and adds the queue
substrate that unblocks item 4. After Phase 1 the platform handles ~500
tenants on a 2-replica setup with negligible code rewrite.

---

## 2. Current architecture

```
                    +-----------------------------+
   Browser   --->   |  Vercel CDN / SSR           |   apps/control-center
                    |  Next.js 15 (App Router)    |   (vibefixing.me)
                    |  45 route handlers          |
                    +--------------+--------------+
                                   |
                                   |  rewrite /v1/* via SUPERVISOR_API_URL
                                   v
                    +--------------+--------------+
                    |  Caddy (single VPS)         |   Caddyfile
                    |  auto-HTTPS, 10 MB body cap |
                    +--------------+--------------+
                                   |
                                   v
   +---------------------------------------------------------------+
   |  supervisor_api (uvicorn, FastAPI 0.115)                      |
   |    routes/         policy_engine    threat_pipeline           |
   |    background tasks (in-process)                              |
   |    retry_worker (single replica, sleep loop)                  |
   |    rate limiter (sliding window, in-memory dict)              |
   +---------+----------------------------------+------------------+
             |                                  |
             v                                  v
   +---------+----------+               +-------+-------+
   | PostgreSQL 16      |               |  Local disk    |
   | single instance    |               |  scan blobs    |
   | 17 tables, 16 mig. |               |  evidence dump |
   +--------------------+               +---------------+

   GitHub App webhooks  --->  POST /webhook  --->  background scan
   MCP clients          --->  packages/mcp-supervisor (stdio)
   Agent SDKs           --->  POST /v1/actions/evaluate
```

**Component map** (entry files):

| Component | Path | Role |
|---|---|---|
| Landing + dashboard | `apps/control-center/app/` | Public + ops UI |
| Auth bridge | `apps/control-center/lib/session.ts` | JWT cookie, role ACL |
| API gateway | `apps/control-center/middleware.ts` | Currently pass-through |
| Policy engine | `services/supervisor_api/src/supervisor_api/policy_engine.py` | Action evaluation |
| Threat pipeline | `services/supervisor_api/src/supervisor_api/threat_pipeline.py` | Pre-evaluation enrichment |
| Scanner | `packages/supervisor-discover/src/supervisor_discover/cli.py` | 18 detectors, AST-based |
| MCP server | `packages/mcp-supervisor/` | stdio bridge for Claude/MCP clients |
| Reverse proxy | `Caddyfile` | TLS, body cap, upstream routing |
| Orchestration | `docker-compose.yml`, `docker-compose.prod.yml` | 3 services + caddy |

---

## 3. File structure

### Today (verified)

```
agentic-internal-controls/
  apps/
    control-center/                Next.js 15, App Router, Tailwind v4
      app/                         45 routes (public + /(ops) + /api/*)
      lib/                         api.ts, session.ts, landing-data.ts
      middleware.ts                pass-through (ACL TBD)
  services/
    supervisor_api/                FastAPI policy engine
      src/supervisor_api/
        routes/                    /v1/* handlers
        alembic/versions/          16 migrations (0001_init -> 0016_github)
        policy_engine.py
        threat_pipeline.py
        ratelimit.py
        retry_worker.py
        storage.py                 disk-backed blob writer
  packages/
    supervisor-discover/           Python scanner, 18 detectors
    supervisor-client-py/          Python SDK
    supervisor-client-ts/          TS SDK (Node/Browser/Edge/Bun)
    supervisor-guards-py/          @supervised decorator
    supervisor-guards-ts/          guarded() wrap
    mcp-supervisor/                MCP stdio
    agentic-controls/              local dev CLI (`ac start|stop`)
    policies/                      YAML action-type policies
  runtime-supervisor/              scan output artifacts (per-repo)
  docs/                            github-app-setup.md, this file
  docker-compose.yml
  docker-compose.prod.yml
  Caddyfile
  .github/workflows/ci.yml
```

### Target additions (only when Phase 1 starts — do not pre-create)

```
services/
  scan_worker/                     Phase 1: queue consumer for /v1/scans
                                   FastAPI-free, picks jobs from Postgres
                                   LISTEN/NOTIFY or Redis Streams
packages/
  supervisor-shared/               Phase 2: TS+Py types shared across SDKs
                                   (today duplicated in 4 packages)
apps/
  docs/                            Phase 3: docs.vibefixing.me (Mintlify or
                                   Nextra) — only when /docs grows past
                                   what the marketing site can hold
```

Anti-pattern to avoid: pre-creating `apps/docs/` or
`packages/supervisor-shared/` before there is duplication or content to
fill them. Empty packages bloat the dep graph and slow CI.

---

## 4. Database schema

Postgres 16 in prod, SQLite for dev (`aic.sqlite3`). Schema tracked by
Alembic in `services/supervisor_api/alembic/versions/0001_init.py`
through `0016_github_installations.py`.

### Tables today (17)

| Table | Role |
|---|---|
| `actions` | Inbound action requests from agents (idempotent by `action_id`) |
| `decisions` | Allow/deny/review verdict per action — hot read path |
| `evidence_log` | Append-only HMAC-chained audit trail |
| `review_items` | Items routed to human review |
| `threat_assessments` | Threat scores per action (joins to actions) |
| `policies` | Versioned policy definitions (YAML compiled to rows) |
| `tenants` | Workspace/account |
| `users` | Email + password or magic link |
| `integrations` | App registrations (HMAC keys, webhook URLs) |
| `webhook_subscriptions` | Per-integration event subscriptions |
| `webhook_deliveries` | Pending/failed webhook deliveries (retry queue) |
| `action_executions` | After-action records (executed/skipped) |
| `admin_events` | Audit of admin operations |
| `scans` | Public scan jobs (repo URL, status, findings pointer) |
| `magic_links` | One-time login tokens |
| `github_installations` | GitHub App installations per tenant |
| `stripe_customers` | Stripe customer + subscription bindings |

### Hot/cold split

| Table | Growth rate | Treatment as we scale |
|---|---|---|
| `decisions` | 1 row per action — fastest growth | Partition by `created_at` month, archive >180d to S3 |
| `evidence_log` | 1+ rows per action — append-only | Partition by month, mirror to object storage in real time |
| `webhook_deliveries` | bursty, mostly transient | Move to Redis Streams when cardinality outgrows DB sweep |
| `actions` | 1 per action | Partition by month |
| `scans` | bursty (PR webhooks) | Stays in DB; findings JSON moves to object storage |
| Everything else | low cardinality | No partitioning — vacuum + indexes suffice |

### Required schema work for scale

1. **Composite indexes for tenant isolation** (Phase 1)

   The scaffold added `tenant_id` (nullable FK) in migration
   `0011_row_tenant_id.py` but no enforcement. Add composite indexes and
   query-layer enforcement before turning on multi-tenant for paying
   customers:

   ```sql
   CREATE INDEX CONCURRENTLY idx_actions_tenant_created
     ON actions (tenant_id, created_at DESC);
   CREATE INDEX CONCURRENTLY idx_decisions_tenant_action
     ON decisions (tenant_id, action_id);
   CREATE INDEX CONCURRENTLY idx_scans_tenant_status_created
     ON scans (tenant_id, status, created_at DESC);
   ```

2. **Declarative partitioning** (Phase 2, when `decisions` > ~10M rows)

   ```sql
   CREATE TABLE decisions_2026_05 PARTITION OF decisions
     FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
   ```

   Drive via cron or `pg_partman`. Keep last 6 months hot; older
   partitions detach + archive to R2/B2.

3. **Read replica routing** (Phase 2)

   Dashboard reads (`/(ops)/findings`, `/(ops)/repos/[id]`) hit a
   replica. Writes stay on primary. Use a session-level router in
   `supervisor_api/db.py`:

   ```python
   engine_writer = create_engine(DATABASE_URL)
   engine_reader = create_engine(DATABASE_READ_URL or DATABASE_URL)
   ```

4. **Object storage for blobs** (Phase 1)

   Today `services/supervisor_api/src/supervisor_api/storage.py` writes
   JSON blobs to disk. At >1 replica this breaks (each replica has its
   own disk). Move to S3-compatible (R2 cheapest, B2 second cheapest):

   ```python
   def put_blob(key: str, data: bytes) -> str:
       s3.put_object(Bucket=BUCKET, Key=key, Body=data)
       return f"s3://{BUCKET}/{key}"
   ```

   Store the `s3://` pointer in DB; read-through with HTTP signed URLs.

---

## 5. API endpoints

### Surface today (`/v1/*` from `services/supervisor_api/src/supervisor_api/routes/`)

| Endpoint | Method | Purpose | Bottleneck at scale |
|---|---|---|---|
| `/v1/actions/evaluate` | POST | Allow/deny/review on agent action | Policy cache per-process; needs distributed invalidation |
| `/v1/decisions/{id}/evidence` | GET | Tamper-evident bundle | Reads `evidence_log` directly — needs read replica |
| `/v1/scans` | POST | Public repo scan | Runs in `BackgroundTasks` — must move to queue |
| `/v1/scans/{id}` | GET | Scan status + findings | Polling pattern; consider SSE in Phase 2 |
| `/v1/integrations` | POST | Register external app | Admin-token gated; low traffic |
| `/v1/auth/login` | POST | Email+password or magic link | Magic link send goes via Resend — async OK |
| `/v1/billing/checkout` | POST | Stripe Checkout session | External, no scale concern |
| `/v1/action-types` | GET | Public catalog | Static-ish; cache with `Cache-Control` 5 min |
| `/webhook` (GitHub) | POST | PR scan trigger | Today triggers in-process scan — must enqueue |

### Versioning + deprecation policy

`/v1` is the only version today. Before introducing `/v2`:

1. Lock breaking changes for 6 months under a `Sunset` header on `/v1`.
2. Mirror new behavior under `/v2` with explicit migration notes per
   endpoint.
3. Keep `/v1` returning a 410 with a redirect URL only after 12 months
   from the `Sunset` announcement.

### Endpoints to add (Phase 1-2)

| Endpoint | When | Why |
|---|---|---|
| `GET /v1/scans?cursor=...` | Phase 1 | Cursor-based pagination on listings; today returns full list |
| `POST /v1/scans/batch` | Phase 2 | GitHub installations with 100+ repos hit the per-repo POST limit |
| `GET /v1/decisions/stream` (SSE) | Phase 2 | Live dashboard tile updates; today the UI polls every 2s |
| `POST /v1/policies/{id}/canary` | Phase 2 | Canary policy promotion (10% of tenants → 50% → 100%) |

---

## 6. UI architecture

### State today

- Single Next.js 15 app, App Router, 45 routes
- `components/` directory exists but is empty — UI is inline in pages
- No client state library (no Zustand, Redux, Jotai, Context)
- Server components fetch via `lib/api.ts` and `lib/landing-data.ts`
- Client components use `useState` + native `fetch` (no SWR, no React
  Query)
- Tailwind v4 only — no design system, no shadcn, no radix wrap

This is fine for ~5 routes with low interactivity. The dashboard now has
~25 routes under `/(ops)/`, where the lack of cache and shared
primitives starts to bite.

### Phase 1 — local data layer

Introduce SWR (smaller bundle than React Query and matches the existing
"server component first" pattern) only for client components that
re-fetch on mutation:

```ts
// apps/control-center/lib/queries/policies.ts
import useSWR from 'swr'
const fetcher = (url: string) => fetch(url).then(r => r.json())
export const usePolicies = () => useSWR('/api/policies', fetcher)
```

Server components keep their direct `fetch` calls — no need to wrap
those.

### Phase 2 — extract `packages/ui`

The same `<CodeBlock>`, `<Badge>`, `<Card>`, `<Button>` markup is
repeated across:

- `apps/control-center/app/page.tsx` (landing)
- `apps/control-center/app/blog/voice-phishing-langchain-agent/page.tsx`
- `apps/control-center/app/(ops)/findings/page.tsx`

Extract into `packages/ui/` (workspace package) when there are 3+
duplicates of the same primitive. Keep the package framework-agnostic
(no Next.js imports) so the docs site can consume it later.

### Phase 3 — streaming + suspense boundaries

When dashboard pages start showing >1 second TTFB, wrap each section
in Suspense and stream:

```tsx
<Suspense fallback={<FindingsListSkeleton />}>
  <FindingsList scanId={scanId} />
</Suspense>
```

Today this is premature — page payloads are <300 KB and TTFB <500ms.

---

## 7. Bottlenecks (priority-ordered)

Each entry: signal, fix, effort. Pick top-down — don't skip ahead.

### B1. Rate limiter is in-process

**File**: `services/supervisor_api/src/supervisor_api/ratelimit.py`
(sliding window in a Python dict, `_WINDOW_SECONDS = 60.0`).

**Signal**: spinning up a 2nd replica today means each replica has its
own bucket, so a client can quietly do `2 * limit` per minute.

**Fix**: Redis-backed sliding window. Add `redis-py`, swap the
in-memory bucket dict for a Lua script (atomic ZADD + ZREMRANGEBYSCORE
+ ZCARD). Keep the existing API (`check(key, max_per_minute)`) so
callers don't change.

**Effort**: 2 days. **Phase**: 1.

### B2. Retry worker is single-process

**File**: `services/supervisor_api/src/supervisor_api/retry_worker.py`
(long-lived `while True` loop with 5s sleep, polls
`webhook_deliveries`).

**Signal**: ROADMAP.md flags this directly: "currently single-process;
move to Redis for locks or leader-election". A second replica would
cause double-delivery.

**Fix (cheap)**: Postgres advisory lock on a fixed key. Each replica
tries `SELECT pg_try_advisory_lock(42)`. Only the holder runs the
loop; the others poll for the lock every 30s. Survives restart, no new
infra.

```python
async def acquire_leader() -> bool:
    row = await session.execute(text("SELECT pg_try_advisory_lock(42)"))
    return row.scalar()
```

**Effort**: 3 days (advisory lock + tests + chaos test killing the
leader). **Phase**: 1.

### B3. Policy cache per-process

**File**: `services/supervisor_api/src/supervisor_api/policy_engine.py`
(loads YAML at startup, caches compiled rules in module-level dict).

**Signal**: promoting a policy via `POST /v1/policies/{id}/promote` on
replica A doesn't invalidate the cache on replica B until B restarts.

**Fix**: Postgres `LISTEN policy_changed` in each replica + `NOTIFY`
on every promote. Beats Redis pub/sub here because we already have
the DB connection and the throughput is tiny (<10 promotes/day).

```sql
NOTIFY policy_changed, '{"policy_id":"refund_v3"}';
```

```python
async def listen_invalidations(conn):
    await conn.execute("LISTEN policy_changed")
    async for notify in conn.notifies():
        cache.invalidate(json.loads(notify.payload)["policy_id"])
```

**Effort**: 2 days. **Phase**: 1.

### B4. Scan runs in the API process

**File**: `services/supervisor_api/src/supervisor_api/routes/scans.py`
(`POST /v1/scans` schedules a `BackgroundTasks` callback that clones +
runs the discover pipeline).

**Signal**: a 100k LOC repo blocks an API worker for 30-90s. With 4
uvicorn workers, 4 concurrent big scans = API unresponsive.

**Fix**: extract `services/scan_worker/`. The API only INSERTs a row
into a `scan_jobs` table (or pushes to Redis Streams) and returns
immediately. The worker pool consumes the queue. Rollout with
**shadow mode** for a week — both paths run, only one delivers
findings, compare diffs.

```
+----+   POST /v1/scans         +-----------+
| UI | -----------------------> | API       |
+----+                          | INSERT job|
                                +-----+-----+
                                      |
                            LISTEN job_ready
                                      |
                                      v
                          +-----------+-----------+
                          | scan_worker (N replicas)
                          | clones, runs, writes  |
                          | findings to S3 + DB   |
                          +-----------------------+
```

**Effort**: 5 days (new service + queue contract + shadow mode).
**Phase**: 1.

### B5. No object storage

**File**: `services/supervisor_api/src/supervisor_api/storage.py`
(writes blobs to local disk in the container).

**Signal**: with 2+ replicas, a scan written to replica A's disk is not
visible from replica B. Today this works only because there is one
replica.

**Fix**: S3-compatible client (Cloudflare R2 — cheapest egress, no
egress fee for HTTP reads). Store `s3://bucket/scans/{id}.json` pointer
in `scans.findings_blob_url`. Issue presigned URLs for direct browser
download in the dashboard.

**Effort**: 2 days. **Phase**: 1.

### B6. Single Caddy, single VPS

**File**: `Caddyfile` + `docker-compose.prod.yml`.

**Signal**: any node failure is total outage. Single VPS works at <50
tenants but has no redundancy.

**Fix path A (cheaper)**: 2 VPS instances behind a managed LB
(Hetzner LB €5/mo). Caddy on each handles its own TLS or share a
single cert via storage backend. Sticky sessions not needed (JWT in
cookie).

**Fix path B (faster)**: Move the API to Fly.io or Railway —
multi-region by default, both have managed Postgres. Vercel already
handles the frontend.

**Effort**: 1 week (path A) or 3 days (path B). **Phase**: 2.

### B7. Auth middleware is pass-through

**File**: `apps/control-center/middleware.ts` (matcher set to
`/(ops)/*` but the body lets every request through).

**Signal**: free-tier visitors can hit `/(ops)/dashboard` directly if
they know the URL. Pages 401 on data fetch but the route renders.

**Fix**: enforce session check + tier ACL in middleware. The
`getSession()` helper in `apps/control-center/lib/session.ts` already
exists.

```ts
const session = await getSession(request)
if (!session) return NextResponse.redirect(new URL('/login', request.url))
if (!ROUTE_ACCESS[session.user.role]?.includes(pathname)) {
  return NextResponse.redirect(new URL('/dashboard', request.url))
}
```

**Effort**: 1 day. **Phase**: 1 (do this first — it's a security gap,
not a scale gap).

---

## 8. Phased roadmap

| Phase | Trigger | Bottlenecks cleared | Net effort |
|---|---|---|---|
| **Phase 0 — current** | <50 tenants, <100 scans/day | — | shipped |
| **Phase 1 — distributed primitives** | 50–500 tenants, paying customers | B1, B2, B3, B4, B5, B7 | ~2 weeks |
| **Phase 2 — read scale** | 500–5k tenants | B6, partitioning, read replica, cursor pagination, SSE | ~3 weeks |
| **Phase 3 — multi-region** | 5k+ tenants, latency-sensitive customers | Active-active backend, regional DB writes via `pglogical` or Aurora Global Database | ~6 weeks |

### Phase 1 detailed (the only one to fully plan now)

Order of operations:

1. **Day 1** — turn on auth middleware (B7). Smallest change, real
   security risk.
2. **Day 2-3** — Redis stack: rate limiter (B1), policy cache notify
   (B3 doesn't actually need Redis — keep `LISTEN/NOTIFY`).
3. **Day 4-5** — leader election for retry worker (B2).
4. **Day 6-7** — object storage (B5). Independent, can ship in parallel
   with the queue work.
5. **Day 8-12** — scan worker extraction (B4) with shadow mode.
6. **Day 13-14** — bake, observe metrics, cut over.

Each day's work = one PR with one feature flag + one observability
metric + one rollback knob.

### Phase 2 — what to plan when Phase 1 lands

- Composite indexes (run with `CONCURRENTLY` to avoid lock)
- Read replica + read router in `db.py`
- Cursor pagination on listings — replace `LIMIT/OFFSET`
- Move from single VPS to LB'd pair (path A) or Fly.io (path B)
- Partition `decisions` and `evidence_log` by month

### Phase 3 — open questions to revisit then

- Active-active vs primary/standby for Postgres
- Per-region DB writes vs single writer (depends on tenant locality)
- Regional scan workers vs central
- These decisions change with cloud provider and customer mix — no
  point pre-committing today.

---

## 9. Observability and cost

### Observability today

Already wired in `services/supervisor_api/src/supervisor_api/`:

- `python-json-logger` — structured logs with `trace_id`, `span_id`
- OpenTelemetry — auto-instruments FastAPI + SQLAlchemy
- OTLP exporter (set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable)
- Custom metrics endpoint at `routes/metrics.py`

### What to add per phase

| Phase | Add |
|---|---|
| 1 | Grafana Cloud free tier (or Honeycomb), 4 dashboards: API latency, scan queue depth, webhook retry backlog, rate-limit rejections |
| 1 | SLOs: API p95 <200ms, scan p95 <120s, webhook delivery p95 <30s |
| 1 | PagerDuty (or Cronitor) on SLO burn rate >10x |
| 2 | Per-tenant dashboards (latency + error rate by `tenant_id` label) |
| 2 | Cost dashboard: $/scan, $/decision, $/tenant |

### Cost envelope (rough, not budgeted)

| Phase | Compute | DB | Object storage | Observability | Total/mo |
|---|---|---|---|---|---|
| 0 | $10 (VPS) | included | local disk | free | ~$10 |
| 1 | $30 (VPS + Redis) | $25 (managed PG) | $5 (R2) | free tier | ~$60 |
| 2 | $150 (LB + 2-3 replicas) | $100 (replica) | $20 | $50 | ~$320 |
| 3 | $1500 (multi-region) | $500 | $100 | $300 | ~$2.4k |

---

## 10. Security posture (scales with the app)

| Concern | Today | Action |
|---|---|---|
| Rate limiting | 10/min anon, 60/min auth, in-memory | Move to Redis (B1) |
| Tenant query isolation | `tenant_id` nullable in DB, no enforcement | Add SQLAlchemy event listener that injects `tenant_id` filter on every query for non-admin sessions (Phase 1) |
| Evidence HMAC | `EVIDENCE_HMAC_SECRET` in env | Phase 1: rotate key with overlap window (sign with new, verify with both) |
| Secrets | `.env.prod` on disk | Phase 1: Doppler or Infisical (Vault is overkill at this size) |
| Auth middleware | Pass-through (B7) | Phase 1, day 1 |
| GitHub App webhook signature | Already verified in `routes/github_app.py` | None — keep as-is |
| Magic-link tokens | One-time, short-lived (already in DB) | None |
| Stripe webhook | Verified by `stripe.Webhook.construct_event` | None |

---

## 11. Migration safety

Every change in section 7 (B1–B7) follows this contract:

1. **Feature flag** — gated by `ENABLE_<X>` env var. Default `false`.
2. **Shadow mode first** — run new path alongside old, compare results
   in metrics for 24-72 hours. No user impact.
3. **Per-tenant rollout** — flip flag for internal tenant first, then
   1%, 10%, 100%.
4. **Rollback < 5 min** — flipping the env var reverts. No code
   redeploy required.
5. **Observable metric** — every flag has a metric showing how many
   requests took the new path and how many fell back.
6. **One PR = one bottleneck**. Bundling causes review friction and
   slower rollback.

Schema migrations specifically:

- `CREATE INDEX CONCURRENTLY` (no exclusive lock)
- New columns nullable, backfill in a separate step
- `DROP COLUMN` only after 1 release of dual-write/dual-read
- Partitioning rollouts: detach + reattach in maintenance window if
  table is hot, otherwise online with `pg_partman`

---

## 12. What we are explicitly NOT doing

These are listed because the team has discussed them and the answer is
"not yet" — not "never". Revisit when the trigger condition fires.

| Not yet | Why not | Revisit when |
|---|---|---|
| Kubernetes | Two replicas behind a managed LB cover Phase 1 and 2. K8s ops cost > scale benefit until ~5k tenants. | >5k tenants OR multi-region with regional autoscaling |
| Microservices split | The FastAPI monolith scales vertically and the SDKs are already separate processes. The only natural split (scan_worker) is in Phase 1. | Each route file >2k LOC OR cross-team ownership friction |
| Event sourcing | `evidence_log` already gives tamper-evident audit. Full event sourcing rewrites the data model. | Compliance asks for time-travel queries beyond what `evidence_log` covers |
| GraphQL | REST + OpenAPI generates SDKs cleanly. GraphQL adds N+1 risks and caching complexity for no current win. | A consumer needs nested queries that take >3 round trips today |
| Internal gRPC | Internal latency is not a bottleneck. uvicorn-to-uvicorn over HTTP is fine at our scale. | API ↔ scan_worker latency p95 >100ms (won't happen at Phase 1 scale) |
| Custom CDN for scan output | R2 + Cloudflare cache covers global delivery. | R2 cache hit rate <80% on scan blob reads |

---

## 13. Open questions for the team

These need a call before Phase 1 starts:

1. **Cloud provider for managed Postgres** — Hetzner Cloud Database vs
   Neon vs Supabase. Trade-off: cost vs branching for staging.
2. **Redis vs Dragonfly** — Dragonfly is faster and one process,
   Redis has more ops familiarity. At our load either is fine.
3. **R2 vs B2 vs S3** — R2 wins on egress, B2 on price/GB, S3 on
   ecosystem. Default to R2 unless someone has a strong opinion.
4. **Fly.io vs LB'd VPS pair** — Fly.io is faster to multi-region but
   adds vendor lock-in. The VPS pair stays portable.
5. **OTel collector self-host vs Grafana Cloud** — Grafana Cloud free
   tier covers Phase 1. Self-host only if data egress becomes a cost.

---

## 14. References

- `ROADMAP.md` — feature roadmap, including Phase T tenant scaffold
  and Phase W webhook retry origins
- `DEPLOY.md` — single-VPS deploy guide
- `docs/github-app-setup.md` — GitHub App registration
- `services/supervisor_api/alembic/versions/` — schema history
- `Caddyfile` — current reverse proxy config
- `docker-compose.prod.yml` — production orchestration
