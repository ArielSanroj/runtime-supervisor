"""init schema

Revision ID: 0001
Revises:
Create Date: 2026-04-17

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "actions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "decisions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("action_id", sa.String(length=36), sa.ForeignKey("actions.id"), nullable=False, unique=True),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("policy_hits", sa.JSON, nullable=False),
        sa.Column("risk_score", sa.Integer, nullable=False),
        sa.Column("risk_breakdown", sa.JSON, nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "review_items",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("action_id", sa.String(length=36), sa.ForeignKey("actions.id"), nullable=False, unique=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("approver", sa.String(length=128), nullable=True),
        sa.Column("approver_notes", sa.String(length=2000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "evidence_log",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer, "sqlite"), primary_key=True, autoincrement=True),
        sa.Column("action_id", sa.String(length=36), sa.ForeignKey("actions.id"), nullable=False),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("event_payload", sa.JSON, nullable=False),
        sa.Column("prev_hash", sa.String(length=128), nullable=False),
        sa.Column("hash", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("action_id", "seq", name="uq_evidence_action_seq"),
    )
    op.create_index("ix_evidence_log_action_id", "evidence_log", ["action_id"])


def downgrade() -> None:
    op.drop_index("ix_evidence_log_action_id", table_name="evidence_log")
    op.drop_table("evidence_log")
    op.drop_table("review_items")
    op.drop_table("decisions")
    op.drop_table("actions")
