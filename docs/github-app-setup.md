# GitHub App — setup notes (Phase E)

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

Done in the current commit:

- [x] `github_installations` model + migration 0016
- [x] `routes/github_app.py` with stub install callback + webhook handler
- [x] HMAC signature verification helper (works once secret is set)
- [x] Settings: `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET`
- [x] Router registered in `main.py`

Still pending (next sprint):

- [ ] Decide where `GITHUB_APP_PRIVATE_KEY` lives (Vercel env vs 1Password vs k8s secret)
- [ ] App registration on github.com
- [ ] `install/callback` real handler (link installation_id → integration_id → tenant_id)
- [ ] Webhook dispatcher: branch on `x_github_event`
- [ ] Cloning + scanning a PR head — the scanner already supports public URL inputs; private-repo support needs a token from the installation
- [ ] PR comment poster (use installation access token, see `Octokit` or the raw REST endpoint)
- [ ] `apps/control-center` dashboard view: `/integrations/github` with install button + list of installed repos
- [ ] Builder-only gate (Phase E is paid)

## Why this is gated to paid

A GitHub App that auto-scans every push has real infra cost — every PR
on every installed repo creates a scan job. That's exactly the kind of
recurring infra you can't give away free. Builder ($29/mo) buys:

- automatic rescans on push
- PR comments
- private repo support (requires the install's installation token)
- multi-repo dashboard agregation

Anonymous shadow + manual scan + manual rescan stays free.
