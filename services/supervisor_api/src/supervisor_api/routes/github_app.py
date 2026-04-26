"""GitHub App integration — Phase E real implementation.

Endpoints:
  GET  /v1/integrations/github/install/callback   (post-install redirect)
  POST /v1/integrations/github/webhook             (push / PR / install events)

The handlers go inert when env vars (`GITHUB_APP_ID`,
`GITHUB_APP_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET`) are absent — they
return 501 with an explicit message. Once configured, the dispatcher
upserts installations on `installation` / `installation_repositories`
events and posts PR comments on `pull_request.opened|synchronize`.

Out of scope here (deliberate): scan execution. The dispatcher
enqueues a background scan via `_run_pr_scan`; the scan helper is a
thin wrapper around the existing `_run_scan_sync` pipeline that already
backs `POST /v1/scans`.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, auth, github_api
from ..config import get_settings
from ..db import SessionLocal, get_db
from ..github_pr_comment import PrCommentInputs, render_pr_comment
from ..models import GitHubInstallation, Scan

log = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/integrations/github", tags=["github-app"])


# ----- helpers ---------------------------------------------------------------


def _require_app_configured() -> None:
    if not get_settings().github_app_enabled:
        raise HTTPException(
            status_code=501,
            detail=(
                "github app not wired — set GITHUB_APP_ID, "
                "GITHUB_APP_PRIVATE_KEY, GITHUB_WEBHOOK_SECRET; "
                "see docs/github-app-setup.md"
            ),
        )


def _verify_webhook_signature(payload_bytes: bytes, signature_header: str | None) -> bool:
    secret = (get_settings().github_webhook_secret or "").encode()
    if not secret or not signature_header:
        return False
    expected = "sha256=" + hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def _upsert_installation(
    db: Session,
    *,
    installation_id: int,
    account_login: str,
    account_type: str,
    repo_full_names: list[str],
    active: bool = True,
) -> GitHubInstallation:
    row = db.execute(
        select(GitHubInstallation).where(GitHubInstallation.installation_id == installation_id)
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if row is None:
        row = GitHubInstallation(
            id=str(uuid4()),
            installation_id=installation_id,
            github_account_login=account_login,
            github_account_type=account_type,
            repo_full_names=repo_full_names,
            active=active,
            installed_at=now,
        )
        db.add(row)
    else:
        row.github_account_login = account_login
        row.github_account_type = account_type
        row.repo_full_names = repo_full_names
        row.active = active
        if active:
            row.uninstalled_at = None
        else:
            row.uninstalled_at = now
    db.commit()
    db.refresh(row)
    return row


# ----- install callback ------------------------------------------------------


@router.get("/install/callback")
def install_callback(
    installation_id: int | None = None,
    setup_action: str | None = None,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """GitHub redirects here after install/update.

    Side-effects: fetches the install info via the App API and upserts
    a `github_installations` row. Then redirects the user to the
    dashboard page where they can pair the install with their tenant.
    """
    _require_app_configured()
    if installation_id is None:
        raise HTTPException(status_code=400, detail="missing installation_id query param")

    try:
        info = github_api.get_app_installation(installation_id)
    except github_api.GitHubApiError as e:
        log.exception("github install/callback: lookup failed for installation %s", installation_id)
        raise HTTPException(status_code=502, detail=f"github API error: {e}") from e

    account = info.get("account") or {}
    repos: list[str] = []
    selection = info.get("repository_selection")
    if selection == "all":
        repos = ["*"]
    else:
        # `repository_selection == "selected"` — fetch repo list with the
        # installation token so we know what we're allowed to scan.
        try:
            token = github_api.get_installation_token(installation_id)
            with __import__("httpx").Client(timeout=30.0) as client:
                r = client.get(
                    "https://api.github.com/installation/repositories",
                    headers={
                        "Authorization": f"Bearer {token.token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                )
                if r.status_code == 200:
                    repos = [r["full_name"] for r in r.json().get("repositories", [])]
        except Exception:
            log.exception("github install/callback: repo list fetch failed; storing empty")
            repos = []

    row = _upsert_installation(
        db,
        installation_id=installation_id,
        account_login=account.get("login", "unknown"),
        account_type=account.get("type", "unknown"),
        repo_full_names=repos,
    )

    audit.record(
        actor="github-app",
        action="github_installation.upsert",
        target_type="github_installation",
        target_id=row.id,
        details={
            "installation_id": installation_id,
            "setup_action": setup_action,
            "repos": repos,
            "account_login": row.github_account_login,
        },
    )

    site = get_settings().site_url.rstrip("/")
    # Bounce to the dashboard view where the user can pair the install
    # with their email-issued integration. Page exists at /integrations/github.
    return RedirectResponse(
        url=f"{site}/integrations/github?installation_id={installation_id}&action={setup_action or 'install'}",
        status_code=302,
    )


# ----- webhook ---------------------------------------------------------------


def _handle_installation_event(payload: dict[str, Any], db: Session) -> dict[str, Any]:
    """Handles `installation` (created/deleted/suspend/unsuspend) events."""
    action = payload.get("action")
    install = payload.get("installation") or {}
    installation_id = install.get("id")
    if not installation_id:
        return {"ignored": "missing installation.id"}

    account = install.get("account") or {}
    repos = [r["full_name"] for r in (payload.get("repositories") or [])] or ["*"]

    if action in ("created", "new_permissions_accepted", "unsuspend"):
        _upsert_installation(
            db,
            installation_id=installation_id,
            account_login=account.get("login", "unknown"),
            account_type=account.get("type", "unknown"),
            repo_full_names=repos,
            active=True,
        )
        return {"action": action, "installation_id": installation_id, "active": True}

    if action in ("deleted", "suspend"):
        _upsert_installation(
            db,
            installation_id=installation_id,
            account_login=account.get("login", "unknown"),
            account_type=account.get("type", "unknown"),
            repo_full_names=repos,
            active=False,
        )
        return {"action": action, "installation_id": installation_id, "active": False}

    return {"action": action, "installation_id": installation_id, "noop": True}


def _handle_installation_repositories_event(payload: dict[str, Any], db: Session) -> dict[str, Any]:
    """Handles repo add/remove on an existing install."""
    install = payload.get("installation") or {}
    installation_id = install.get("id")
    if not installation_id:
        return {"ignored": "missing installation.id"}

    row = db.execute(
        select(GitHubInstallation).where(GitHubInstallation.installation_id == installation_id)
    ).scalar_one_or_none()
    if row is None:
        # Create on first sight even if we missed the install event.
        account = install.get("account") or {}
        row = _upsert_installation(
            db,
            installation_id=installation_id,
            account_login=account.get("login", "unknown"),
            account_type=account.get("type", "unknown"),
            repo_full_names=[],
        )

    current = set(row.repo_full_names or [])
    added = {r["full_name"] for r in (payload.get("repositories_added") or [])}
    removed = {r["full_name"] for r in (payload.get("repositories_removed") or [])}
    new_set = (current | added) - removed
    row.repo_full_names = sorted(new_set)
    db.commit()
    return {
        "installation_id": installation_id,
        "added": sorted(added),
        "removed": sorted(removed),
    }


def _handle_pull_request_event(
    payload: dict[str, Any],
    background: BackgroundTasks,
) -> dict[str, Any]:
    """Handles `pull_request.opened` / `synchronize` / `reopened`.

    Enqueues a background scan via _run_pr_scan. The actual cloning +
    scanning + comment posting happens out-of-band so the webhook
    returns fast (GitHub retries on >10s).
    """
    action = payload.get("action")
    if action not in ("opened", "synchronize", "reopened"):
        return {"action": action, "skipped": "non-scanning action"}

    pr = payload.get("pull_request") or {}
    repo = payload.get("repository") or {}
    install = payload.get("installation") or {}
    installation_id = install.get("id")

    if not installation_id or not pr.get("number"):
        return {"ignored": "missing installation_id or pr.number"}

    background.add_task(
        _run_pr_scan,
        installation_id=installation_id,
        repo_full_name=repo.get("full_name", ""),
        pr_number=pr["number"],
        head_sha=(pr.get("head") or {}).get("sha", ""),
        head_clone_url=(pr.get("head") or {}).get("repo", {}).get("clone_url", ""),
    )
    return {
        "action": action,
        "pr": pr["number"],
        "repo": repo.get("full_name"),
        "queued": True,
    }


def _key_of(finding: Any) -> str:
    """Stable diff key — matches the frontend's diff drill-down logic.
    Finding may be a dataclass or a dict (from a stored scan)."""
    if hasattr(finding, "file"):
        file = finding.file
        line = finding.line
        scanner = finding.scanner
        family = (getattr(finding, "extra", None) or {}).get("family") or ""
    else:
        file = finding.get("file", "")
        line = finding.get("line", 0)
        scanner = finding.get("scanner", "")
        extra = finding.get("extra") or {}
        family = extra.get("family", "") if isinstance(extra, dict) else ""
    return f"{file}:{line}:{scanner}:{family}"


def _previous_scan_findings(db: Session, repo_url: str) -> dict[str, dict]:
    """Look up the most recent successful scan for this repo and return
    its findings keyed by `_key_of` so we can diff. Empty dict means
    no prior scan — in which case every finding in the PR head is "new"
    (first run of the App on this repo).
    """
    row = (
        db.query(Scan)
        .filter(Scan.repo_url == repo_url, Scan.status == "done")
        .order_by(Scan.created_at.desc())
        .first()
    )
    if row is None:
        return {}
    return {_key_of(f): f for f in (row.findings or [])}


def _run_pr_scan(
    *,
    installation_id: int,
    repo_full_name: str,
    pr_number: int,
    head_sha: str,
    head_clone_url: str,
) -> None:
    """Background task: clone PR head, scan, diff, post comment.

    Failures are logged but never propagate — webhooks already 200'd.
    Each step runs inside a try/except so a flake in one stage (token
    expired, git clone hung, etc) doesn't leave temp dirs hanging.
    """
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path

    from supervisor_discover.scanners import scan_all

    settings = get_settings()
    workdir: str | None = None

    try:
        # 1. Mint installation token (1h lifetime, fresh per dispatch).
        token = github_api.get_installation_token(installation_id)

        # 2. Shallow clone the PR head ref. Using x-access-token in URL
        # auths the clone with the install scope.
        workdir = tempfile.mkdtemp(prefix=f"vibefixing-pr-{pr_number}-")
        clone_url = f"https://x-access-token:{token.token}@github.com/{repo_full_name}.git"
        try:
            subprocess.run(
                ["git", "clone", "--quiet", "--depth=20", clone_url, workdir],
                check=True,
                timeout=120,
                capture_output=True,
            )
            if head_sha:
                # Fetch + checkout the exact head SHA — the default branch
                # of the clone is base, but we want the PR's tip.
                subprocess.run(
                    ["git", "-C", workdir, "fetch", "--quiet", "origin", head_sha, "--depth=1"],
                    check=True,
                    timeout=60,
                    capture_output=True,
                )
                subprocess.run(
                    ["git", "-C", workdir, "checkout", "--quiet", head_sha],
                    check=True,
                    timeout=30,
                    capture_output=True,
                )
        except subprocess.CalledProcessError as e:
            log.error(
                "github.pr.scan clone failed installation=%s repo=%s pr=%s: %s",
                installation_id,
                repo_full_name,
                pr_number,
                e.stderr.decode(errors="replace") if e.stderr else "",
            )
            return

        # 3. Run the scanner against the cloned tree.
        head_findings = scan_all(Path(workdir))

        # 4. Diff against the most recent persisted scan for this repo.
        repo_url = f"https://github.com/{repo_full_name}"
        with SessionLocal() as db:
            previous_by_key = _previous_scan_findings(db, repo_url)

        head_by_key = {_key_of(f): f for f in head_findings}
        new_findings = [f for k, f in head_by_key.items() if k not in previous_by_key]
        fixed_count = sum(1 for k in previous_by_key if k not in head_by_key)

        # 5. Render markdown. Empty body = clean PR; skip post.
        from supervisor_discover.findings import Confidence  # for type alignment

        repo_id_hash = __import__("hashlib").sha256(repo_url.lower().encode()).hexdigest()[:16]
        body = render_pr_comment(
            PrCommentInputs(
                repo_full_name=repo_full_name,
                repo_id=repo_id_hash,
                pr_number=pr_number,
                head_sha=head_sha,
                new_findings=new_findings,
                fixed_count=fixed_count,
                site_url=settings.site_url,
            )
        )
        if not body:
            log.info(
                "github.pr.scan clean installation=%s repo=%s pr=%s — no comment posted",
                installation_id,
                repo_full_name,
                pr_number,
            )
            return

        # 6. Post the comment.
        comment = github_api.post_pr_comment(
            installation_token=token.token,
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            body_markdown=body,
        )
        log.info(
            "github.pr.scan posted comment installation=%s repo=%s pr=%s comment_id=%s new=%d fixed=%d",
            installation_id,
            repo_full_name,
            pr_number,
            comment.get("id"),
            len(new_findings),
            fixed_count,
        )
    except Exception:
        log.exception(
            "github.pr.scan failed installation=%s repo=%s pr=%s",
            installation_id,
            repo_full_name,
            pr_number,
        )
    finally:
        if workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)


# ----- link an installation to a tenant (Builder paired flow) ---------------


class LinkInstallationRequest(BaseModel):
    tenant_id: str
    linked_by_email: str | None = None


@router.post("/installations/{installation_id}/link")
def link_installation(
    installation_id: int,
    body: LinkInstallationRequest,
    db: Session = Depends(get_db),
    principal: auth.Principal = Depends(auth.require_any_scope),
) -> dict[str, Any]:
    """Pair a GitHubInstallation with a tenant.

    The frontend gates this on a Builder session and forwards the
    user's tenant_id in the body. Backend trusts the frontend's
    admin-token-signed call (same trust model as other admin reads
    in the dashboard) and writes the link + an audit entry.

    Idempotent: re-linking to the same tenant is a no-op; re-linking
    to a different tenant overwrites + audits the change so we can
    trace ownership changes if a user transfers an install.
    """
    _require_app_configured()

    row = db.execute(
        select(GitHubInstallation).where(GitHubInstallation.installation_id == installation_id)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="installation not found")

    # Validate the tenant exists — protects against typos / stale
    # session IDs creating dangling links.
    from ..models import Tenant

    if db.get(Tenant, body.tenant_id) is None:
        raise HTTPException(status_code=400, detail=f"unknown tenant_id: {body.tenant_id}")

    previous_tenant_id = row.tenant_id
    row.tenant_id = body.tenant_id
    db.commit()
    db.refresh(row)

    audit.record(
        actor=body.linked_by_email or principal.name or "frontend",
        action="github_installation.link",
        target_type="github_installation",
        target_id=row.id,
        details={
            "installation_id": installation_id,
            "previous_tenant_id": previous_tenant_id,
            "new_tenant_id": body.tenant_id,
            "linked_by_email": body.linked_by_email,
        },
    )

    return {
        "installation_id": row.installation_id,
        "tenant_id": row.tenant_id,
        "linked_to_tenant": row.tenant_id is not None,
        "linked_at": datetime.now(UTC).isoformat(),
    }


# ----- public read of an installation (used by the post-install page) -------


@router.get("/installations/{installation_id}")
def get_installation_public(installation_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Public read of basic install fields. Used by the post-install
    confirmation page so anonymous browsers (the user's redirect from
    github.com) can render meaningful state without login.

    Exposes only fields that are not sensitive: account login + type,
    repo names (or "*"), active status, install timestamp. Anything
    that tied this install to an integration / tenant lives behind
    auth.
    """
    row = db.execute(
        select(GitHubInstallation).where(GitHubInstallation.installation_id == installation_id)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="installation not found")
    return {
        "installation_id": row.installation_id,
        "account_login": row.github_account_login,
        "account_type": row.github_account_type,
        "repos": list(row.repo_full_names or []),
        "active": row.active,
        # Linked = associated with a tenant (set by the pairing flow at
        # POST /installations/{id}/link). Implies the install belongs to
        # a known Vibefixing account; PR scan results route to that
        # tenant's dashboard.
        "linked_to_tenant": row.tenant_id is not None,
        "installed_at": row.installed_at.isoformat() if row.installed_at else None,
    }


@router.post("/webhook")
async def webhook(
    request: Request,
    background: BackgroundTasks,
    x_github_event: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
    x_github_delivery: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    _require_app_configured()
    body = await request.body()
    if not _verify_webhook_signature(body, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="invalid webhook signature")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="invalid JSON body")

    log.info(
        "github.webhook event=%s delivery=%s",
        x_github_event,
        x_github_delivery,
    )

    if x_github_event == "installation":
        result = _handle_installation_event(payload, db)
    elif x_github_event == "installation_repositories":
        result = _handle_installation_repositories_event(payload, db)
    elif x_github_event == "pull_request":
        result = _handle_pull_request_event(payload, background)
    elif x_github_event == "ping":
        result = {"pong": True}
    else:
        # Other subscribed events (push, etc.) — acknowledged but not yet
        # acted on. Adding handlers is purely additive.
        result = {"event": x_github_event, "noop": True}

    return {"received": True, "event": x_github_event, "result": result}
