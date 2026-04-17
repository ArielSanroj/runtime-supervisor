from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class EvaluateRequest(BaseModel):
    # Any string accepted here — runtime validates against registry.LIVE_ACTION_TYPES.
    # Keeps the schema stable as new supervisors ship.
    action_type: str
    payload: dict[str, Any]


class DecisionOut(BaseModel):
    action_id: str
    decision: Literal["allow", "deny", "review"]
    reasons: list[str]
    risk_score: int
    policy_version: str


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
