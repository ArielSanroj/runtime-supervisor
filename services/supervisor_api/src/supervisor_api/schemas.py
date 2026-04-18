from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class EvaluateRequest(BaseModel):
    # Any string accepted here — runtime validates against registry.LIVE_ACTION_TYPES.
    # Keeps the schema stable as new supervisors ship.
    action_type: str
    payload: dict[str, Any]


class ThreatSignalOut(BaseModel):
    detector_id: str
    owasp_ref: str
    level: Literal["info", "warn", "critical"]
    message: str
    evidence: dict[str, Any]


class DecisionOut(BaseModel):
    action_id: str
    decision: Literal["allow", "deny", "review"]
    reasons: list[str]
    risk_score: int
    policy_version: str
    threat_level: Literal["none", "info", "warn", "critical"] = "none"
    threats: list[ThreatSignalOut] = Field(default_factory=list)


class PolicyHit(BaseModel):
    rule_id: str
    action: Literal["allow", "deny", "review"]
    reason: str


class RiskBreakdown(BaseModel):
    rule: str
    points: int


class EvidenceEventOut(BaseModel):
    seq: int
    event_type: str
    event_payload: dict[str, Any]
    prev_hash: str
    hash: str
    created_at: datetime


class EvidenceBundle(BaseModel):
    action_id: str
    action_type: str
    status: str
    events: list[EvidenceEventOut]
    chain_ok: bool
    broken_at_seq: int | None = None
    bundle_hash: str
    bundle_signature: str
    exported_at: datetime


class ReviewItemOut(BaseModel):
    id: str
    action_id: str
    status: Literal["pending", "approved", "rejected"]
    action_payload: dict[str, Any]
    action_type: str
    risk_score: int
    policy_hits: list[dict[str, Any]]
    created_at: datetime
    resolved_at: datetime | None = None
    approver: str | None = None
    approver_notes: str | None = None


class ReviewResolveRequest(BaseModel):
    decision: Literal["approved", "rejected"]
    notes: str | None = Field(default=None, max_length=2000)


class IntegrationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    scopes: list[str] = Field(default_factory=lambda: ["*"])


class IntegrationOut(BaseModel):
    id: str
    name: str
    scopes: list[str]
    active: bool
    created_at: datetime
    revoked_at: datetime | None = None
    execute_url: str | None = None
    execute_method: str = "POST"


class IntegrationCreated(IntegrationOut):
    shared_secret: str  # returned once at creation / rotation


class IntegrationRotate(BaseModel):
    # empty body; kept for future knobs like "set expiry"
    pass


class PolicyCreate(BaseModel):
    action_type: str = Field(min_length=1, max_length=64)
    yaml_source: str = Field(min_length=1, max_length=20000)
    promote: bool = Field(default=False, description="If true, deactivate any current active policy for this action_type and make this one active")


class PolicyOut(BaseModel):
    id: str
    action_type: str
    name: str
    version: int
    yaml_source: str
    is_active: bool
    created_by: str | None
    created_at: datetime
    deactivated_at: datetime | None


class PolicyTestRequest(BaseModel):
    payload: dict[str, Any]


class PolicyTestResult(BaseModel):
    decision: Literal["allow", "deny", "review"]
    hits: list[dict[str, Any]]
    reasons: list[str]


class ReplayDivergence(BaseModel):
    action_id: str
    created_at: datetime
    from_decision: Literal["allow", "deny", "review"]
    to_decision: Literal["allow", "deny", "review"]
    to_reasons: list[str]


class PolicyReplayResult(BaseModel):
    window: str
    total: int
    same: int
    differ: int
    would_tighten: int
    would_loosen: int
    divergences: list[ReplayDivergence]


class PolicyExportEntry(BaseModel):
    action_type: str
    name: str
    version: int
    is_active: bool
    yaml_source: str
    created_by: str | None
    created_at: datetime


class PolicyImportItem(BaseModel):
    action_type: str
    yaml_source: str
    promote: bool = False


class PolicyImportResult(BaseModel):
    imported: int
    promoted: int
    errors: list[dict[str, Any]]
    policy_ids: list[str]


class EvidenceExportResult(BaseModel):
    action_id: str
    key: str
    url: str
    bundle_hash: str
    bundle_signature: str
    exported_at: datetime
    size_bytes: int


class PolicyRef(BaseModel):
    id: str
    name: str
    version: int


class PolicyDiffResult(BaseModel):
    model_config = {"populate_by_name": True}
    action_type: str
    from_: PolicyRef = Field(alias="from")
    to: PolicyRef
    added_lines: int
    removed_lines: int
    diff: str


class ExecuteConfigRequest(BaseModel):
    url: str | None = Field(default=None, max_length=1024)
    method: Literal["POST", "PUT", "PATCH"] = "POST"

    @field_validator("url")
    @classmethod
    def _http(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("url must start with http:// or https://")
        return v


class ActionExecutionOut(BaseModel):
    id: int
    action_id: str
    integration_id: str | None
    url: str
    method: str
    status_code: int | None
    error: str | None
    attempts: int
    state: Literal["pending", "success", "failed"]
    triggered_by: Literal["allow", "review"]
    queued_at: datetime
    executed_at: datetime | None


class WebhookSubscriptionCreate(BaseModel):
    url: str = Field(min_length=1, max_length=1024)
    events: list[Literal["decision.made", "review.resolved", "action.denied", "threat.detected", "critical.alert"]] = Field(min_length=1)

    @field_validator("url")
    @classmethod
    def _url_is_http(cls, v: str) -> str:
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("url must start with http:// or https://")
        return v


class WebhookSubscriptionOut(BaseModel):
    id: str
    integration_id: str
    url: str
    events: list[str]
    active: bool
    created_at: datetime


class ThreatAssessmentOut(BaseModel):
    id: int
    action_id: str | None
    integration_id: str | None
    detector_id: str
    owasp_ref: str
    level: Literal["info", "warn", "critical"]
    signals: list[dict[str, Any]]
    created_at: datetime


class ThreatCatalogEntry(BaseModel):
    id: str
    title: str
    owasp_ref: str
    one_liner: str
    severity: Literal["info", "warn", "critical"]
    remediation: str
    sample_attack: dict[str, Any]


class SimulatedAttackOut(BaseModel):
    threat_id: str
    decision: DecisionOut
    threats: list[ThreatSignalOut]


class WebhookDeliveryOut(BaseModel):
    id: int
    subscription_id: str
    event_type: str
    status_code: int | None
    error: str | None
    attempts: int
    delivered_at: datetime | None
    created_at: datetime
