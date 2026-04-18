"""action_proxy: execute_url + action_executions

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-18

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("integrations", sa.Column("execute_url", sa.String(length=1024), nullable=True))
    op.add_column("integrations", sa.Column("execute_method", sa.String(length=8), nullable=False, server_default="POST"))

    op.create_table(
        "action_executions",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer, "sqlite"), primary_key=True, autoincrement=True),
        sa.Column("action_id", sa.String(length=36), sa.ForeignKey("actions.id"), nullable=False, unique=True),
        sa.Column("integration_id", sa.String(length=36), sa.ForeignKey("integrations.id"), nullable=True),
        sa.Column("url", sa.String(length=1024), nullable=False),
        sa.Column("method", sa.String(length=8), nullable=False, server_default="POST"),
        sa.Column("status_code", sa.Integer, nullable=True),
        sa.Column("response_body", sa.String(length=4000), nullable=True),
        sa.Column("error", sa.String(length=500), nullable=True),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("state", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("triggered_by", sa.String(length=32), nullable=False),
        sa.Column("queued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_action_executions_action_id", "action_executions", ["action_id"])
    op.create_index("ix_action_executions_integration_id", "action_executions", ["integration_id"])


def downgrade() -> None:
    op.drop_index("ix_action_executions_integration_id", table_name="action_executions")
    op.drop_index("ix_action_executions_action_id", table_name="action_executions")
    op.drop_table("action_executions")
    op.drop_column("integrations", "execute_method")
    op.drop_column("integrations", "execute_url")
