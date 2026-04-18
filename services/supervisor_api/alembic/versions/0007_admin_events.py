"""admin_events audit log

Revision ID: 0007
Revises: 0006
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "admin_events",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer, "sqlite"), primary_key=True, autoincrement=True),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column("details", sa.JSON, nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_admin_events_created_at", "admin_events", ["created_at"])
    op.create_index("ix_admin_events_target", "admin_events", ["target_type", "target_id"])


def downgrade() -> None:
    op.drop_index("ix_admin_events_target", table_name="admin_events")
    op.drop_index("ix_admin_events_created_at", table_name="admin_events")
    op.drop_table("admin_events")
