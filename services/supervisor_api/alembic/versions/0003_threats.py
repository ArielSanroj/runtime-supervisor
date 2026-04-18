"""threat_assessments

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-18

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "threat_assessments",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer, "sqlite"), primary_key=True, autoincrement=True),
        sa.Column("action_id", sa.String(length=36), sa.ForeignKey("actions.id"), nullable=True),
        sa.Column("integration_id", sa.String(length=36), nullable=True),
        sa.Column("detector_id", sa.String(length=64), nullable=False),
        sa.Column("owasp_ref", sa.String(length=16), nullable=False),
        sa.Column("level", sa.String(length=16), nullable=False),
        sa.Column("signals", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_threat_assessments_action_id", "threat_assessments", ["action_id"])
    op.create_index("ix_threat_assessments_integration_id", "threat_assessments", ["integration_id"])
    op.create_index("ix_threat_assessments_created_at", "threat_assessments", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_threat_assessments_created_at", table_name="threat_assessments")
    op.drop_index("ix_threat_assessments_integration_id", table_name="threat_assessments")
    op.drop_index("ix_threat_assessments_action_id", table_name="threat_assessments")
    op.drop_table("threat_assessments")
