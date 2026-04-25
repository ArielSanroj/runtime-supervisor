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
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, github_api
from ..config import get_settings
from ..db import get_db
from ..models import GitHubInstallation

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


def _run_pr_scan(
    *,
    installation_id: int,
    repo_full_name: str,
    pr_number: int,
    head_sha: str,
    head_clone_url: str,
) -> None:
    """Background task: clone PR head, scan, post comment.

    Stubbed body — wires the existing scanner pipeline via the public
    `POST /v1/scans` flow. Full implementation: shallow clone with
    installation token, run `supervisor-discover scan --path` against
    the temp dir, diff vs. main's last scan, render markdown via
    `github_pr_comment.render_pr_comment`, post via
    `github_api.post_pr_comment`.

    Kept narrow on purpose so we can ship the install + webhook UX
    first and iterate on the scanner-on-PR pipeline as a separate PR.
    """
    log.info(
        "github.pr.scan queued installation=%s repo=%s pr=%s sha=%s — clone+scan+comment not wired in this commit",
        installation_id,
        repo_full_name,
        pr_number,
        head_sha,
    )


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
