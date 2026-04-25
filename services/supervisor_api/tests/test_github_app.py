"""Tests for the GitHub App endpoints + helpers.

Covers signature verification, installation event handling, PR comment
markdown formatting, and dispatcher routing. Network calls to
api.github.com are mocked so tests stay hermetic.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from supervisor_api.config import get_settings
from supervisor_api.db import SessionLocal
from supervisor_api.github_pr_comment import PrCommentInputs, render_pr_comment
from supervisor_api.models import GitHubInstallation
from supervisor_discover.findings import Finding


@pytest.fixture(autouse=True)
def _enable_github_app(monkeypatch):
    """Force the App to look configured for these tests. Real env-var
    lookups are bypassed because we mock the HTTP boundary."""
    monkeypatch.setenv("GITHUB_APP_ID", "123456")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "test-private-key")
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-webhook-secret")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _sign_payload(payload: bytes, secret: str = "test-webhook-secret") -> str:
    return "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


# ----- markdown formatter ----------------------------------------------------


def _finding(
    file: str = "src/api.py",
    line: int = 42,
    suggested_action_type: str = "payment",
    confidence: str = "high",
    rationale: str = "stripe.refunds.create called without supervision",
    family: str | None = "stripe-refund",
) -> Finding:
    extra = {"family": family} if family else {}
    return Finding(
        scanner="payment_calls",
        file=file,
        line=line,
        snippet="stripe.refunds.create(...)",
        suggested_action_type=suggested_action_type,
        confidence=confidence,
        rationale=rationale,
        extra=extra,
    )


def test_render_pr_comment_with_new_findings():
    out = render_pr_comment(
        PrCommentInputs(
            repo_full_name="acme/cliocsbot",
            repo_id="abc123",
            pr_number=42,
            head_sha="deadbeef" * 5,
            new_findings=[_finding(), _finding(file="src/email.py", line=8)],
            fixed_count=3,
            site_url="https://vibefixing.me",
        )
    )
    assert "2 new unsafe call-sites" in out
    assert "src/api.py:42" in out
    assert "src/email.py:8" in out
    assert "🔴" in out  # high confidence emoji
    assert "3 previously-flagged finding" in out
    assert "vibefixing.me/repos/abc123" in out
    assert out.count("|") > 10  # tabular structure rendered


def test_render_pr_comment_clean_pr_skipped():
    out = render_pr_comment(
        PrCommentInputs(
            repo_full_name="acme/cliocsbot",
            repo_id="abc",
            pr_number=1,
            head_sha="x",
            new_findings=[],
            fixed_count=0,
            site_url="https://vibefixing.me",
        )
    )
    assert out == ""  # caller should skip posting


def test_render_pr_comment_only_fixed_no_new():
    out = render_pr_comment(
        PrCommentInputs(
            repo_full_name="acme/cliocsbot",
            repo_id="abc",
            pr_number=1,
            head_sha="x",
            new_findings=[],
            fixed_count=2,
            site_url="https://vibefixing.me",
        )
    )
    assert "✅" in out
    assert "2 previously-flagged" in out


def test_render_pr_comment_truncates_after_25():
    findings = [_finding(file=f"src/f{i}.py", line=i) for i in range(40)]
    out = render_pr_comment(
        PrCommentInputs(
            repo_full_name="x",
            repo_id="r",
            pr_number=1,
            head_sha="s",
            new_findings=findings,
            fixed_count=0,
            site_url="https://vibefixing.me",
        )
    )
    assert "and 15 more" in out


# ----- signature verification ------------------------------------------------


def test_webhook_rejects_unsigned(client: TestClient):
    r = client.post(
        "/v1/integrations/github/webhook",
        headers={"x-github-event": "ping"},
        json={"zen": "test"},
    )
    assert r.status_code == 401
    assert "invalid webhook signature" in r.json()["detail"]


def test_webhook_rejects_bad_signature(client: TestClient):
    body = b'{"zen":"hi"}'
    r = client.post(
        "/v1/integrations/github/webhook",
        headers={
            "x-github-event": "ping",
            "x-hub-signature-256": "sha256=" + "0" * 64,
        },
        content=body,
    )
    assert r.status_code == 401


def test_webhook_accepts_signed_ping(client: TestClient):
    body = json.dumps({"zen": "Speak like a human."}).encode()
    sig = _sign_payload(body)
    r = client.post(
        "/v1/integrations/github/webhook",
        headers={
            "x-github-event": "ping",
            "x-hub-signature-256": sig,
            "content-type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 200
    body_json = r.json()
    assert body_json["event"] == "ping"
    assert body_json["result"]["pong"] is True


# ----- installation event handler --------------------------------------------


def test_webhook_installation_created_persists_row(client: TestClient):
    payload = {
        "action": "created",
        "installation": {
            "id": 7777,
            "account": {"login": "acme-org", "type": "Organization"},
        },
        "repositories": [
            {"full_name": "acme-org/api"},
            {"full_name": "acme-org/web"},
        ],
    }
    body = json.dumps(payload).encode()
    sig = _sign_payload(body)
    r = client.post(
        "/v1/integrations/github/webhook",
        headers={
            "x-github-event": "installation",
            "x-hub-signature-256": sig,
            "content-type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 200
    with SessionLocal() as s:
        row = s.query(GitHubInstallation).filter(GitHubInstallation.installation_id == 7777).one()
        assert row.active is True
        assert row.github_account_login == "acme-org"
        assert row.github_account_type == "Organization"
        assert sorted(row.repo_full_names) == ["acme-org/api", "acme-org/web"]


def test_webhook_installation_deleted_marks_inactive(client: TestClient):
    # Seed an active install.
    with SessionLocal() as s:
        s.add(GitHubInstallation(
            id="seed-id",
            installation_id=8888,
            github_account_login="acme-org",
            github_account_type="Organization",
            repo_full_names=["*"],
            active=True,
            installed_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        ))
        s.commit()

    payload = {
        "action": "deleted",
        "installation": {
            "id": 8888,
            "account": {"login": "acme-org", "type": "Organization"},
        },
    }
    body = json.dumps(payload).encode()
    sig = _sign_payload(body)
    r = client.post(
        "/v1/integrations/github/webhook",
        headers={
            "x-github-event": "installation",
            "x-hub-signature-256": sig,
            "content-type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 200
    with SessionLocal() as s:
        row = s.query(GitHubInstallation).filter(GitHubInstallation.installation_id == 8888).one()
        assert row.active is False
        assert row.uninstalled_at is not None


def test_webhook_installation_repositories_diffs_repo_set(client: TestClient):
    # Seed an install with one repo.
    with SessionLocal() as s:
        s.add(GitHubInstallation(
            id="seed-id-2",
            installation_id=9999,
            github_account_login="acme-org",
            github_account_type="Organization",
            repo_full_names=["acme-org/old"],
            active=True,
            installed_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        ))
        s.commit()

    payload = {
        "action": "added",
        "installation": {
            "id": 9999,
            "account": {"login": "acme-org", "type": "Organization"},
        },
        "repositories_added": [{"full_name": "acme-org/new"}],
        "repositories_removed": [{"full_name": "acme-org/old"}],
    }
    body = json.dumps(payload).encode()
    sig = _sign_payload(body)
    r = client.post(
        "/v1/integrations/github/webhook",
        headers={
            "x-github-event": "installation_repositories",
            "x-hub-signature-256": sig,
            "content-type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 200
    with SessionLocal() as s:
        row = s.query(GitHubInstallation).filter(GitHubInstallation.installation_id == 9999).one()
        assert row.repo_full_names == ["acme-org/new"]


# ----- PR webhook --------------------------------------------------------


def test_webhook_pull_request_opened_queues_scan(client: TestClient):
    """`pull_request.opened` should be acknowledged + queued, not 5xx.
    The actual scan runs as a background task; we don't await it here.
    """
    payload = {
        "action": "opened",
        "pull_request": {
            "number": 42,
            "head": {
                "sha": "abc123",
                "repo": {"clone_url": "https://github.com/acme/repo.git"},
            },
        },
        "repository": {"full_name": "acme/repo"},
        "installation": {"id": 1111},
    }
    body = json.dumps(payload).encode()
    sig = _sign_payload(body)
    with patch("supervisor_api.routes.github_app._run_pr_scan") as mock_scan:
        r = client.post(
            "/v1/integrations/github/webhook",
            headers={
                "x-github-event": "pull_request",
                "x-hub-signature-256": sig,
                "content-type": "application/json",
            },
            content=body,
        )
    assert r.status_code == 200
    body_json = r.json()
    assert body_json["result"]["queued"] is True
    assert body_json["result"]["pr"] == 42
    # Background task scheduled (FastAPI runs it after response).
    assert mock_scan.called


def test_webhook_pull_request_closed_skipped(client: TestClient):
    payload = {
        "action": "closed",
        "pull_request": {"number": 1, "head": {"sha": "x"}},
        "repository": {"full_name": "x/y"},
        "installation": {"id": 1},
    }
    body = json.dumps(payload).encode()
    sig = _sign_payload(body)
    r = client.post(
        "/v1/integrations/github/webhook",
        headers={
            "x-github-event": "pull_request",
            "x-hub-signature-256": sig,
            "content-type": "application/json",
        },
        content=body,
    )
    assert r.status_code == 200
    assert "skipped" in r.json()["result"]


# ----- 501 when not configured -------------------------------------------


def test_webhook_returns_501_when_app_unconfigured(client: TestClient, monkeypatch):
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    get_settings.cache_clear()
    r = client.post(
        "/v1/integrations/github/webhook",
        headers={"x-github-event": "ping"},
        json={},
    )
    assert r.status_code == 501
    assert "github app not wired" in r.json()["detail"].lower()
    get_settings.cache_clear()
