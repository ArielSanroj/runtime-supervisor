"""scans table — persist every `POST /v1/scans` run

Scans used to live in ephemeral blob storage only. This migration adds a
relational record per run so the dashboard `/findings` page can list past
scans per tenant, and anonymous public-landing scans still persist
(tenant_id=NULL) for the free scan history Builder users will eventually
unlock.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("repo_url", sa.String(length=512), nullable=False),
        sa.Column("ref", sa.String(length=128), nullable=True),
        sa.Column("repo_summary", sa.JSON, nullable=False),
        sa.Column("findings", sa.JSON, nullable=False),
        sa.Column("total_findings", sa.Integer, nullable=False, server_default="0"),
        sa.Column("priority_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("scan_seconds", sa.Float, nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="done"),
        sa.Column("error", sa.String(length=1000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scans_tenant_id", "scans", ["tenant_id"], unique=False)
    op.create_index("ix_scans_repo_url", "scans", ["repo_url"], unique=False)
    op.create_index("ix_scans_created_at", "scans", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_scans_created_at", table_name="scans")
    op.drop_index("ix_scans_repo_url", table_name="scans")
    op.drop_index("ix_scans_tenant_id", table_name="scans")
    op.drop_table("scans")
