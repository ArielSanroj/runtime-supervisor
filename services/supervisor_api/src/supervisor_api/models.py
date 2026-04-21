from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, BigInteger, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base

BigIntPk = BigInteger().with_variant(Integer, "sqlite")


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Action(Base):
    __tablename__ = "actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="received")
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    # When True, the call was evaluated but the decision was NOT enforced on
    # the caller (no deny, no review-block). The real decision is still on
    # the joined Decision row for metrics/replay.
    shadow: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    decision: Mapped[Decision | None] = relationship(back_populates="action", uselist=False)
    review: Mapped[ReviewItem | None] = relationship(back_populates="action", uselist=False)
    events: Mapped[list[EvidenceEvent]] = relationship(back_populates="action", order_by="EvidenceEvent.seq")


class Decision(Base):
    __tablename__ = "decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    action_id: Mapped[str] = mapped_column(ForeignKey("actions.id"), nullable=False, unique=True)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)  # allow|deny|review
    policy_hits: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_breakdown: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    # End-to-end evaluate latency (threat pipeline + policy + risk). Null on
    # rows created before this column existed; populated going forward.
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    action: Mapped[Action] = relationship(back_populates="decision")


class ReviewItem(Base):
    __tablename__ = "review_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    action_id: Mapped[str] = mapped_column(ForeignKey("actions.id"), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    # Priority buckets for routing: `low` = self-serve ops, `normal` = default,
    # `high` = paged compliance. Escalation bumps priority.
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="normal")
    # Role queue target. Null = anyone with review scope can pick up.
    assigned_to: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approver: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approver_notes: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    action: Mapped[Action] = relationship(back_populates="review")


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)  # admin | compliance | ops | auditor
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True)
    active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AdminEvent(Base):
    __tablename__ = "admin_events"

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class PolicyRecord(Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("action_type", "version", name="uq_policy_action_version"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    yaml_source: Mapped[str] = mapped_column(String(20000), nullable=False)
    is_active: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    deactivated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Integration(Base):
    __tablename__ = "integrations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    shared_secret: Mapped[str] = mapped_column(String(256), nullable=False)
    scopes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # action_proxy: where to POST approved actions for downstream execution
    execute_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    execute_method: Mapped[str] = mapped_column(String(8), nullable=False, default="POST")
    # Multi-tenant scaffold — nullable until row-level enforcement ships.
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True)


class ActionExecution(Base):
    __tablename__ = "action_executions"

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True, autoincrement=True)
    action_id: Mapped[str] = mapped_column(ForeignKey("actions.id"), nullable=False, unique=True, index=True)
    integration_id: Mapped[str | None] = mapped_column(ForeignKey("integrations.id"), nullable=True, index=True)
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    method: Mapped[str] = mapped_column(String(8), nullable=False, default="POST")
    status_code: Mapped[int | None] = mapped_column(nullable=True)
    response_body: Mapped[str | None] = mapped_column(String(4000), nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    attempts: Mapped[int] = mapped_column(default=0, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    triggered_by: Mapped[str] = mapped_column(String(32), nullable=False)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WebhookSubscription(Base):
    __tablename__ = "webhook_subscriptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    integration_id: Mapped[str] = mapped_column(ForeignKey("integrations.id"), nullable=False, index=True)
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    events: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True, autoincrement=True)
    subscription_id: Mapped[str] = mapped_column(ForeignKey("webhook_subscriptions.id"), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    status_code: Mapped[int | None] = mapped_column(nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    attempts: Mapped[int] = mapped_column(default=0, nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="success")  # pending|success|failed|dead
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)


class ThreatAssessmentRow(Base):
    __tablename__ = "threat_assessments"

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True, autoincrement=True)
    action_id: Mapped[str | None] = mapped_column(ForeignKey("actions.id"), nullable=True, index=True)
    integration_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    detector_id: Mapped[str] = mapped_column(String(64), nullable=False)
    owasp_ref: Mapped[str] = mapped_column(String(16), nullable=False)
    level: Mapped[str] = mapped_column(String(16), nullable=False)
    signals: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class EvidenceEvent(Base):
    __tablename__ = "evidence_log"
    __table_args__ = (UniqueConstraint("action_id", "seq", name="uq_evidence_action_seq"),)

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True, autoincrement=True)
    action_id: Mapped[str] = mapped_column(ForeignKey("actions.id"), nullable=False, index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    event_payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    hash: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    action: Mapped[Action] = relationship(back_populates="events")
