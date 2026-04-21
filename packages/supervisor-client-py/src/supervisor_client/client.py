"""Thin Python client for the runtime-supervisor.

Usage:

    from supervisor_client import Client

    sup = Client(
        base_url="https://supervisor.example.com",
        app_id="acme-refund-agent",
        shared_secret="...",      # from POST /v1/integrations
        scopes=["refund"],
    )
    decision = sup.evaluate("refund", {"amount": 50, "customer_id": "c1", ...})
    if decision.decision == "allow":
        ...
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

import httpx

from ._jwt import build_token


class SupervisorError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"{status_code}: {detail}")


@dataclass(frozen=True)
class Decision:
    action_id: str
    decision: Literal["allow", "deny", "review"]
    reasons: list[str]
    risk_score: int
    policy_version: str
    # In shadow mode the server returns decision="allow" but reports the
    # real decision here, so metrics + logs can tell the difference.
    shadow_would_have: Literal["allow", "deny", "review"] | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def blocked(self) -> bool:
        return self.decision == "deny"

    @property
    def needs_review(self) -> bool:
        return self.decision == "review"


@dataclass(frozen=True)
class ReviewCase:
    id: str
    action_id: str
    status: str
    action_type: str
    risk_score: int
    created_at: str


class Client:
    def __init__(
        self,
        base_url: str,
        app_id: str,
        shared_secret: str,
        scopes: list[str] | None = None,
        *,
        token_ttl_seconds: int = 300,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._app_id = app_id
        self._secret = shared_secret
        self._scopes = scopes or ["*"]
        self._ttl = token_ttl_seconds
        self._http = httpx.Client(base_url=self._base, timeout=timeout, transport=transport)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    def _headers(self) -> dict[str, str]:
        return {
            "authorization": f"Bearer {build_token(self._app_id, self._scopes, self._secret, self._ttl)}",
            "content-type": "application/json",
        }

    def _req(self, method: str, path: str, **kwargs: Any) -> Any:
        r = self._http.request(method, path, headers=self._headers(), **kwargs)
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except Exception:
                detail = r.text
            raise SupervisorError(r.status_code, detail)
        return r.json() if r.content else None

    # ---------- high-level helpers ----------

    def evaluate(
        self,
        action_type: str,
        payload: dict[str, Any],
        *,
        dry_run: bool = False,
        shadow: bool = False,
        agent_context: dict[str, Any] | None = None,
    ) -> Decision:
        path = "/v1/actions/evaluate" + ("?dry_run=true" if dry_run else "")
        body: dict[str, Any] = {
            "action_type": action_type,
            "payload": payload,
            "shadow": shadow,
        }
        if agent_context:
            body["agent_context"] = agent_context
        data = self._req("POST", path, json=body)
        return Decision(
            action_id=data["action_id"],
            decision=data["decision"],
            reasons=data["reasons"],
            risk_score=data["risk_score"],
            policy_version=data["policy_version"],
            shadow_would_have=data.get("shadow_would_have"),
        )

    def list_action_types(self) -> list[dict[str, Any]]:
        # public endpoint; still send auth (harmless)
        return self._req("GET", "/v1/action-types")["action_types"]

    def list_reviews(self, status: str | None = None) -> list[ReviewCase]:
        q = f"?status={status}" if status else ""
        items = self._req("GET", f"/v1/review-cases{q}")
        return [
            ReviewCase(
                id=i["id"], action_id=i["action_id"], status=i["status"],
                action_type=i["action_type"], risk_score=i["risk_score"],
                created_at=i["created_at"],
            )
            for i in items
        ]

    def get_review(self, review_id: str) -> dict[str, Any]:
        """Full review with payload + policy_hits. Summary-only clients
        should use `list_reviews`; callback HITL flows want this."""
        return self._req("GET", f"/v1/review-cases/{review_id}")

    def resolve_review(self, review_id: str, decision: Literal["approved", "rejected"], notes: str | None = None, approver: str | None = None) -> dict[str, Any]:
        headers = {}
        if approver:
            headers["x-approver"] = approver
        r = self._http.post(
            f"/v1/review-cases/{review_id}/resolve",
            headers={**self._headers(), **headers},
            json={"decision": decision, "notes": notes},
        )
        if r.status_code >= 400:
            raise SupervisorError(r.status_code, r.text)
        return r.json()

    def get_evidence(self, action_id: str) -> dict[str, Any]:
        return self._req("GET", f"/v1/decisions/{action_id}/evidence")
