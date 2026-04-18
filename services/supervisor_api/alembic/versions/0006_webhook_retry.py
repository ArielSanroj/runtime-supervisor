"""webhook_deliveries: state + next_retry_at for async retry queue

Revision ID: 0006
Revises: 0005
Create Date: 2026-04-18

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "webhook_deliveries",
        sa.Column("state", sa.String(length=16), nullable=False, server_default="success"),
    )
    op.add_column(
        "webhook_deliveries",
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_webhook_deliveries_next_retry_at", "webhook_deliveries", ["next_retry_at"])


def downgrade() -> None:
    op.drop_index("ix_webhook_deliveries_next_retry_at", table_name="webhook_deliveries")
    op.drop_column("webhook_deliveries", "next_retry_at")
    op.drop_column("webhook_deliveries", "state")
