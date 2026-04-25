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
    # Phase 1 multi-tenant — nullable until Phase 2 backfills every writer.
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    # Anonymous shadow attribution. Set by the SDK on requests that have no
    # Bearer token; lets us later `claim` the events for an email-bound
    # tenant. Null on authenticated-integration requests.
    client_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
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
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
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
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
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
    # Nullable for users created via Stripe checkout (passwordless, magic-link only).
    password_hash: Mapped[str | None] = mapped_column(String(256), nullable=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False)  # admin | compliance | ops | auditor
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True)
    active: Mapped[bool] = mapped_column(default=True, nullable=False)
    # Subscription tier — gates dashboard access. "free" can run public scans
    # but cannot reach /(ops)/*. "builder" is the paid tier.
    tier: Mapped[str] = mapped_column(String(16), nullable=False, default="free")
    stripe_customer_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Mirror of Stripe sub status: active, trialing, past_due, canceled, etc.
    stripe_subscription_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Scan(Base):
    """Persisted record of a supervisor-discover scan.

    Each run of `POST /v1/scans` creates one row. tenant_id is nullable so
    anonymous landing-page scans still persist (NULL = public demo); Builder
    users get their tenant_id recorded and can list past scans via
    `GET /v1/scans?tenant_id=...`.

    The full findings + repo_summary payload is kept as JSON so the detail
    page can render the same `<FindingsList>` component used by the
    post-scan page, without re-deriving anything from the blob.
    """

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    repo_url: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Full payload: repo_summary + findings (truncated to the same limit the
    # UI receives). Kept as JSON to avoid a second schema / migrations dance
    # every time discover adds a field.
    repo_summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    findings: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    total_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    priority_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scan_seconds: Mapped[float | None] = mapped_column(nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="done")  # done|error
    error: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)


class MagicLinkToken(Base):
    """Single-use email-bound token for passwordless login.

    Issued after Stripe checkout completes (Builder onboarding) and on demand
    via /v1/auth/magic-link/send. Token is the primary key — the URL-safe value
    sent in the email.
    """

    __tablename__ = "magic_link_tokens"

    token: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Free-form metadata attached at issue time. Used by claim flow to carry
    # the client_id being linked. Null on plain login / signup tokens.
    token_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)
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
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
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
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WebhookSubscription(Base):
    __tablename__ = "webhook_subscriptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    integration_id: Mapped[str] = mapped_column(ForeignKey("integrations.id"), nullable=False, index=True)
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    events: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    active: Mapped[bool] = mapped_column(default=True, nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
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
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)


class ThreatAssessmentRow(Base):
    __tablename__ = "threat_assessments"

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True, autoincrement=True)
    action_id: Mapped[str | None] = mapped_column(ForeignKey("actions.id"), nullable=True, index=True)
    integration_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    detector_id: Mapped[str] = mapped_column(String(64), nullable=False)
    owasp_ref: Mapped[str] = mapped_column(String(16), nullable=False)
    level: Mapped[str] = mapped_column(String(16), nullable=False)
    signals: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class GitHubInstallation(Base):
    """One row per GitHub App install. Phase E scaffolding.

    `repo_full_names` is the list of repos the user picked at install
    time (or `["*"]` if they granted to all). The webhook handler maps
    incoming `repository.full_name` → installation_id → integration_id
    so events fire under the right tenant.
    """

    __tablename__ = "github_installations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    installation_id: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
    github_account_login: Mapped[str] = mapped_column(String(128), nullable=False)
    github_account_type: Mapped[str] = mapped_column(String(16), nullable=False)  # User | Organization
    repo_full_names: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    integration_id: Mapped[str | None] = mapped_column(ForeignKey("integrations.id"), nullable=True, index=True)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    active: Mapped[bool] = mapped_column(default=True, nullable=False)
    installed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    uninstalled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    action: Mapped[Action] = relationship(back_populates="events")
