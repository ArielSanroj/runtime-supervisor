"""policies store

Revision ID: 0005
Revises: 0004
Create Date: 2026-04-18

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policies",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("yaml_source", sa.String(length=20000), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deactivated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("action_type", "version", name="uq_policy_action_version"),
    )
    op.create_index("ix_policies_action_type", "policies", ["action_type"])


def downgrade() -> None:
    op.drop_index("ix_policies_action_type", table_name="policies")
    op.drop_table("policies")
