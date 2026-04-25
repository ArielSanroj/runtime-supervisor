"""github_installations table — Phase E scaffolding

Holds one row per GitHub App installation. Used by the webhook handler
to look up which integration / tenant a repo belongs to when a push or
pull_request event arrives.

Schema is intentionally minimal — extend in a follow-up migration once
the OAuth flow + scan-on-push routes are wired.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "github_installations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.BigInteger, nullable=False, unique=True),
        sa.Column("github_account_login", sa.String(128), nullable=False),
        sa.Column("github_account_type", sa.String(16), nullable=False),  # User | Organization
        sa.Column("repo_full_names", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("integration_id", sa.String(36), sa.ForeignKey("integrations.id"), nullable=True, index=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=True, index=True),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("installed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("uninstalled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )


def downgrade() -> None:
    op.drop_table("github_installations")
