"""GitHub App integration — Phase E scaffolding.

NOT WIRED FOR PRODUCTION YET. The structure is here so the router is
discoverable and the install/webhook URLs are reservable, but the
handlers raise 501 until:
  - the App is created on github.com (see docs/github-app-setup.md)
  - GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, GITHUB_WEBHOOK_SECRET env
    vars are populated
  - the webhook signature verification + scan-on-push logic is
    implemented (next sprint)
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import GitHubInstallation

log = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/integrations/github", tags=["github-app"])


# ----- install callback ------------------------------------------------------


class InstallCallbackResponse(BaseModel):
    installation_id: int
    redirect_to: str


@router.get("/install/callback")
async def install_callback(
    installation_id: int | None = None,
    setup_action: str | None = None,
    code: str | None = None,
    state: str | None = None,
    db: Session = Depends(get_db),
) -> InstallCallbackResponse:
    """Lands here after the user installs the App on github.com.

    GitHub sends `installation_id` + `setup_action=install` (or `update`)
    as query params. We store the row and bounce the user to the
    onboarding page where they pair this install with an integration.
    """
    raise HTTPException(
        status_code=501,
        detail=(
            "github app install not wired yet — see docs/github-app-setup.md "
            "for the env vars and OAuth flow that need to ship before this "
            "route activates."
        ),
    )


# ----- webhook receiver ------------------------------------------------------


def _verify_webhook_signature(payload_bytes: bytes, signature_header: str | None) -> bool:
    """GitHub signs payloads with the App webhook secret using HMAC-SHA256.
    Header is `X-Hub-Signature-256: sha256=<hex>`.
    """
    settings = get_settings()
    secret = (settings.github_webhook_secret or "").encode()
    if not secret or not signature_header:
        return False
    expected = "sha256=" + hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


@router.post("/webhook")
async def webhook(
    request: Request,
    x_github_event: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
    x_github_delivery: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    """Receives push / pull_request events from the App.

    Production behaviour (after Phase E impl):
      - verify signature with GITHUB_WEBHOOK_SECRET
      - on `pull_request.opened` / `synchronize`: enqueue a scan against
        the head ref, then post a comment summarising new findings
      - on `installation` / `installation_repositories`: upsert the
        GitHubInstallation row and (un)set `active`
    """
    body = await request.body()
    if not _verify_webhook_signature(body, x_hub_signature_256):
        # Verification fails by design when GITHUB_WEBHOOK_SECRET is
        # unset (Phase E not provisioned yet) — return 501 so any test
        # delivery is loud about the missing config rather than silently
        # 200ing.
        raise HTTPException(
            status_code=501,
            detail="github webhook handler not wired yet — set GITHUB_WEBHOOK_SECRET and implement the dispatcher",
        )

    log.info(
        "github.webhook event=%s delivery=%s — handler stubbed",
        x_github_event,
        x_github_delivery,
    )
    return {"received": True, "event": x_github_event, "stub": True}
