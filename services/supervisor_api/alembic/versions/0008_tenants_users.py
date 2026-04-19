"""tenants + users scaffold (Phase T+X foundation)

Adds the DB shape for multi-tenant + user accounts. Row-level tenant
enforcement and session-based auth for the control-center UI are
deferred — this migration establishes the columns so future PRs can
backfill and enforce incrementally.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False, unique=True),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("email", sa.String(length=256), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(length=256), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),  # admin|compliance|ops|auditor
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # SQLite can't ALTER with inline FK; use batch mode which does copy-and-move.
    with op.batch_alter_table("integrations") as batch:
        batch.add_column(sa.Column("tenant_id", sa.String(length=36), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("integrations") as batch:
        batch.drop_column("tenant_id")
    op.drop_table("users")
    op.drop_table("tenants")
