"""integrations + webhooks

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-17

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "integrations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False, unique=True),
        sa.Column("shared_secret", sa.String(length=256), nullable=False),
        sa.Column("scopes", sa.JSON, nullable=False),
        sa.Column("active", sa.Boolean, nullable=False, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "webhook_subscriptions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("integration_id", sa.String(length=36), sa.ForeignKey("integrations.id"), nullable=False),
        sa.Column("url", sa.String(length=1024), nullable=False),
        sa.Column("events", sa.JSON, nullable=False),
        sa.Column("active", sa.Boolean, nullable=False, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_webhook_subscriptions_integration_id", "webhook_subscriptions", ["integration_id"])

    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer, "sqlite"), primary_key=True, autoincrement=True),
        sa.Column("subscription_id", sa.String(length=36), sa.ForeignKey("webhook_subscriptions.id"), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
        sa.Column("status_code", sa.Integer, nullable=True),
        sa.Column("error", sa.String(length=500), nullable=True),
        sa.Column("attempts", sa.Integer, nullable=False, default=0),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_webhook_deliveries_subscription_id", "webhook_deliveries", ["subscription_id"])


def downgrade() -> None:
    op.drop_index("ix_webhook_deliveries_subscription_id", table_name="webhook_deliveries")
    op.drop_table("webhook_deliveries")
    op.drop_index("ix_webhook_subscriptions_integration_id", table_name="webhook_subscriptions")
    op.drop_table("webhook_subscriptions")
    op.drop_table("integrations")
