"""Thin GitHub App API client.

Two responsibilities:
  1. Mint app-level JWTs (RS256) and exchange them for short-lived
     installation access tokens.
  2. Wrap the few REST endpoints we actually call (PR comments, repo
     access via installation token).

We keep this tiny on purpose. The full Octokit / PyGithub feature set
is overkill for what Phase E needs, and dropping a dep is one less
audit surface.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt

from .config import get_settings

log = logging.getLogger(__name__)


GITHUB_API = "https://api.github.com"
DEFAULT_TIMEOUT = 30.0


@dataclass(frozen=True)
class InstallationToken:
    token: str
    expires_at: int  # unix timestamp


class GitHubApiError(Exception):
    def __init__(self, status_code: int, body: str) -> None:
        super().__init__(f"GitHub API {status_code}: {body[:200]}")
        self.status_code = status_code
        self.body = body


def _app_jwt() -> str:
    """Mint a short-lived app-level JWT signed with the app's private key.

    GitHub accepts up to a 10-minute lifetime — we use 9 to leave room
    for clock skew. The `iss` claim is the numeric App ID.
    """
    settings = get_settings()
    if not settings.github_app_id or not settings.github_app_private_key:
        raise RuntimeError("github app not configured: GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY required")

    now = int(time.time())
    payload = {
        "iat": now - 60,         # backdate 60s to absorb clock skew
        "exp": now + 9 * 60,     # 9 minutes (max GitHub allows is 10)
        "iss": settings.github_app_id,
    }
    # The private key may arrive as a literal "\n"-escaped string from env
    # vars; normalise so PyJWT can parse it as PEM.
    pem = settings.github_app_private_key.replace("\\n", "\n")
    return jwt.encode(payload, pem, algorithm="RS256")


def get_installation_token(installation_id: int) -> InstallationToken:
    """Exchange the app JWT for an installation-scoped token.

    Tokens last 1 hour. Cache lifetime concerns are out of scope for the
    MVP — we mint a fresh one per webhook dispatch since the batch sizes
    are small. Add a TTL cache once volume justifies it.
    """
    app_token = _app_jwt()
    headers = {
        "Authorization": f"Bearer {app_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
        r = client.post(
            f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
            headers=headers,
        )
    if r.status_code != 201:
        raise GitHubApiError(r.status_code, r.text)
    data = r.json()
    # `expires_at` is ISO 8601; parse with fromisoformat after Z→+00:00.
    from datetime import datetime
    iso = data["expires_at"].replace("Z", "+00:00")
    expires_at = int(datetime.fromisoformat(iso).timestamp())
    return InstallationToken(token=data["token"], expires_at=expires_at)


def get_app_installation(installation_id: int) -> dict[str, Any]:
    """Fetch the installation's account info (login, type, repo selection).

    Used at install/callback time to enrich the GitHubInstallation row
    with the org/user that installed the app.
    """
    token = _app_jwt()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
        r = client.get(
            f"{GITHUB_API}/app/installations/{installation_id}",
            headers=headers,
        )
    if r.status_code != 200:
        raise GitHubApiError(r.status_code, r.text)
    return r.json()


def post_pr_comment(
    *,
    installation_token: str,
    repo_full_name: str,
    pr_number: int,
    body_markdown: str,
) -> dict[str, Any]:
    """POST a markdown comment to a pull request's discussion thread.

    Uses the issues endpoint (PR comments live on issues in the API).
    Returns the comment payload so we can persist comment_id for later
    edits if we want to update on subsequent pushes.
    """
    headers = {
        "Authorization": f"Bearer {installation_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = f"{GITHUB_API}/repos/{repo_full_name}/issues/{pr_number}/comments"
    with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
        r = client.post(url, headers=headers, json={"body": body_markdown})
    if r.status_code not in (200, 201):
        raise GitHubApiError(r.status_code, r.text)
    return r.json()


def get_pr_head(
    *,
    installation_token: str,
    repo_full_name: str,
    pr_number: int,
) -> dict[str, Any]:
    """Look up the head ref + sha of a PR. Used to know what commit to
    scan when a `pull_request` webhook arrives without the full payload.
    """
    headers = {
        "Authorization": f"Bearer {installation_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = f"{GITHUB_API}/repos/{repo_full_name}/pulls/{pr_number}"
    with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
        r = client.get(url, headers=headers)
    if r.status_code != 200:
        raise GitHubApiError(r.status_code, r.text)
    data = r.json()
    return {
        "head_ref": data["head"]["ref"],
        "head_sha": data["head"]["sha"],
        "base_ref": data["base"]["ref"],
        "base_sha": data["base"]["sha"],
    }
