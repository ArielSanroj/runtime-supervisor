# GitHub App — setup notes (Phase E)

> **Status (2026-04-25)**: end-to-end install + webhook flow verified live.
> App registered on github.com, secret rotated through "Recent Deliveries
> redeliver", `installation.created` event accepted with HTTP 200, row
> persisted in `github_installations`. Next milestone: end-to-end PR scan
> against a real PR (this commit ships that test).

The skeleton is in `services/supervisor_api/src/supervisor_api/routes/github_app.py`
and `services/supervisor_api/alembic/versions/0016_github_installations.py`.
Both are committed but the handlers raise 501 until the App is registered
on github.com and the env vars below are set.

## What needs to happen, in order

### 1. Create the App on github.com

GitHub → Settings → Developer settings → GitHub Apps → New GitHub App.

Field values:

| Field | Value |
|---|---|
| GitHub App name | `Vibefixing` |
| Homepage URL | `https://vibefixing.me` |
| Callback URL | `https://vibefixing.me/api/github/install/callback` (proxied to backend) |
| Setup URL | same as Callback URL |
| Webhook URL | `https://vibefixing.ngrok.app/v1/integrations/github/webhook` (or whatever public origin the supervisor is on) |
| Webhook secret | generate a 32-byte hex random — save as `GITHUB_WEBHOOK_SECRET` |

Permissions:

- **Repository → Contents**: Read-only (so we can git-clone the repo to scan it)
- **Repository → Pull requests**: Read & write (post comments)
- **Repository → Metadata**: Read-only (always required)

Subscribe to events:

- `push`
- `pull_request`
- `installation`
- `installation_repositories`

After creating the App, GitHub gives you an **App ID** and lets you generate
a **private key (.pem file)**. Save both as env vars.

### 2. Set env vars on the supervisor host

```bash
GITHUB_APP_ID=123456                              # numeric, from the app page
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
GITHUB_WEBHOOK_SECRET=<the 32-byte hex you generated>
```

When all three are populated, `settings.github_app_enabled` returns true
and the routes accept real traffic. Today they 501 with a clear message.

### 3. Implement the handlers

The skeleton has the URL surface and the signature verification. What's
left for the next sprint:

- `install/callback` — exchange the install for an integration, redirect
  user to a "you're set up" page in the dashboard. Probably: create a
  pending row, link it to the user's email-issued integration, redirect.
- `webhook` event dispatch:
  - `pull_request.opened` / `synchronize` → clone HEAD, scan, diff against
    the base branch's last scan, post a PR comment listing new findings.
  - `installation` / `installation_repositories` → upsert the
    `github_installations` row (active=true on add, false on remove).
  - `push` (only on the default branch) → enqueue a scan and update the
    repo's overview; useful for `/repos/{repo_id}/history` to stay fresh
    without manual rescans.

The diff endpoint at `/repos/{repo_id}/history/{scan_id}` already does
the diff math against the previous scan. The PR comment is just a
markdown render of that.

### 4. The PR comment format

Aim for short and actionable:

```markdown
🔒 **Vibefixing detected 2 new unsafe call-sites**

| File | Type | Confidence |
|---|---|---|
| `src/api/refund.ts:42` | direct `stripe.refunds.create()` without `@supervised` | high |
| `src/workers/ingest.ts:108` | `fs.unlink()` in user-input path | high |

Wrap them with `@supervised('payment')` / `@supervised('tool_use')` before
merging. [Full diff →](https://vibefixing.me/repos/{repo_id}/history/{scan_id})

Fixed since the last scan: 5
```

## Phase ordering — what's done vs what's pending

Done:

- [x] `github_installations` model + migration 0016
- [x] `routes/github_app.py` real implementation:
  - install/callback: fetches installation info from GitHub, persists row, redirects to dashboard
  - webhook: HMAC-SHA256 signature verification + dispatcher for `installation`, `installation_repositories`, `pull_request`, `ping`
- [x] `github_api.py`: app JWT (RS256) + installation token exchange + PR comment posting + PR head lookup
- [x] `github_pr_comment.py`: markdown formatter (table of new findings, fixed count, dashboard link)
- [x] Settings: `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET` + `github_app_enabled` property
- [x] 13 pytest cases — signature verification, install/uninstall events, repo add/remove, PR queueing, 501 when unconfigured
- [x] Router registered in `main.py`
- [x] `pyjwt[crypto]` added as dep

Still pending (next iteration):

- [ ] Decide where `GITHUB_APP_PRIVATE_KEY` lives (Vercel env vs 1Password vs k8s secret)
- [ ] App registration on github.com (manual, see steps above)
- [ ] **PR scan pipeline** (`_run_pr_scan` is a stub) — needs: shallow git clone with installation token, run `supervisor-discover scan`, diff against base ref's last scan, render markdown via `render_pr_comment`, post via `post_pr_comment`. Currently logs and returns; the Phase E loop is wired except for this last leg.
- [ ] `apps/control-center/app/(ops)/integrations/github` dashboard view — pair `installation_id` with the user's email-issued integration. The install/callback already redirects there with the query param.
- [ ] Builder-only gate — anonymous shadow stays free; PR comments + auto-rescan-on-push gated to $29/mo.

## Why this is gated to paid

A GitHub App that auto-scans every push has real infra cost — every PR
on every installed repo creates a scan job. That's exactly the kind of
recurring infra you can't give away free. Builder ($29/mo) buys:

- automatic rescans on push
- PR comments
- private repo support (requires the install's installation token)
- multi-repo dashboard agregation

Anonymous shadow + manual scan + manual rescan stays free.
