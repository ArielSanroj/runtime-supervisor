# Roadmap

What's shipped, what's deferred, and why.

## Shipped in this cycle (Phase 1 through Phase W + T/X scaffold)

- Phase 1 — refund supervision MVP + landing
- Phase 2 — integration API (JWT + SDKs + webhooks + MCP + subagent)
- Phase G — AI-security threat detection pipeline + public simulator
- Phase H — payment supervisor live
- Phase I — `action_proxy` downstream execution
- Phase J — policy editor (DB-managed + live test)
- Phase K — policy editor UI (control-center)
- Phase L — integrations admin UI
- Phase M — metrics dashboard + execution history
- Phase P — seed policies from YAML on startup
- Phase N — OpenTelemetry instrumentation
- Phase O — async webhook retry queue + standalone worker
- Phase Q — policy replay (what-would-have-happened)
- Phase R — policy diff viewer
- Phase S — prod hardening bundle (rate limit + payload size + JSON logs + audit log + webhook delivery UI)
- Phase U — evidence bundle S3/blob export
- Phase V — execution retry + critical.alert fanout
- Phase W — policy import/export
- Phase T+X **scaffold** — tenants CRUD + users + login (foundations; full enforcement below)

## Deferred with explicit design notes

### Multi-tenant row enforcement (Phase T full)

**Scaffolded:** `tenants` table, `Integration.tenant_id` nullable FK,
`/v1/tenants` CRUD. Users + session JWTs carry `tenant_id` claim.

**Not yet enforced:** every read query must filter by the caller's
`tenant_id`, every write must stamp it. Migration backfill assigns a
`default` tenant to existing rows. JWT audience claim enforcement in
`auth.require_any_scope` rejects cross-tenant tokens.

**Scope:** ~2 weeks of work.
- Migration 0009 backfills tenant_id="default" on actions/decisions/review_items/evidence_log/threat_assessments/webhook_*/action_executions/policies/admin_events.
- Update every `select(...)` in routes to `.where(Model.tenant_id == principal.tenant_id)`.
- Middleware reads session JWT or integration JWT, resolves tenant, injects into request state.
- Tests: cross-tenant isolation (tenant A cannot list tenant B's rows), a SaaS-style e2e.

**Why deferred:** a mechanical refactor that touches every route and
every test. Not faked well. Do it in a dedicated PR with a migration
backfill script and explicit audit plan.

### Full SSO + UI RBAC (Phase X full)

**Scaffolded:** `users` table with `role`, password login at
`/v1/auth/login`, session JWTs with role claim.

**Not yet enforced:**
- Control-center pages don't check the session JWT or role. Today the
  UI uses `SUPERVISOR_ADMIN_TOKEN` as a single shared secret. Need a
  session cookie or bearer flow.
- OIDC/SAML integration (Clerk, Auth0, Okta, Azure AD) not wired.
- RBAC gates: `auditor` should only see `/threats` + `/review`;
  `compliance` gets `/policies` + `/review`; `ops` adds `/integrations`
  + `/dashboard`; `admin` gets everything including `/users` and
  `/tenants`.

**Scope:** ~1 week.
- Option A: Clerk (fastest, external dep). `@clerk/nextjs` in the
  control-center, set session cookie, proxy routes read the session.
- Option B: self-hosted. Session cookie on login, FastAPI dependency
  that pulls user from the session JWT, React Context + middleware
  for role gating in Next.js.

**Why deferred:** auth is a multi-stakeholder decision (which IdP, SAML
vs OIDC, SCIM provisioning). Scaffolding unblocks the discussion
without committing to a provider.

## Post-this-cycle candidates

- **Horizontal scaling.** Retry worker currently single-process; move
  to Redis for locks or leader-election. Policy cache is per-process;
  add cache invalidation via webhook or PostgreSQL NOTIFY.
- **Per-subscription webhook secrets + rotation grace window.** Swap
  the global `WEBHOOK_SECRET` for per-sub secrets with an overlap
  period on rotation.
- **Threat detector tuning per tenant.** Regex patterns + thresholds
  as DB rows instead of code.
- **Backfill tooling for evidence retention.** S3 export is on-demand;
  add a periodic `export-all-since(days)` batch for cold storage.
- **OpenAPI SDK generation.** Emit client libraries for Java/Go/Ruby
  via `openapi-generator`.
- **Load tests.** k6/locust harness against `/v1/actions/evaluate` to
  characterize p95/p99 under realistic threat and policy mix.
