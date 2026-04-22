"""Row-level tenant_id on 9 scoped tables + default tenant backfill (Phase 1)

Adds nullable tenant_id FK on every table that stores per-tenant data so
the route layer (Phase 2) can filter queries with
`WHERE tenant_id = :tenant_id`. Also backfills pre-existing rows to a
"default" tenant so the column is never semantically empty from Phase 2
onwards.

Tables that gain a tenant_id:
  actions, decisions, policies, review_items, threat_assessments,
  webhook_subscriptions, webhook_deliveries, evidence_log,
  action_executions

Already had the column (0008): integrations, users — this migration
backfills any NULL rows on those two as well.

Why nullable now: dropping in NOT NULL on SQLite with batch_alter_table
on tables with data forces a table copy that fails on any NULL row. We
ship this as nullable + backfilled; a later migration flips to NOT NULL
once route filtering is verified (Phase 2).
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


_SCOPED_TABLES = [
    "actions",
    "decisions",
    "policies",
    "review_items",
    "threat_assessments",
    "webhook_subscriptions",
    "webhook_deliveries",
    "evidence_log",
    "action_executions",
]


def upgrade() -> None:
    conn = op.get_bind()

    # 1. Resolve the tenant every legacy row will be assigned to. Prefer an
    #    existing "default" tenant; if none, create one. If the install
    #    already has a single non-default tenant (early adopter), still
    #    prefer the explicit "default" so the backfill is predictable.
    row = conn.execute(sa.text("SELECT id FROM tenants WHERE name = 'default' LIMIT 1")).fetchone()
    if row is None:
        default_tenant_id = str(uuid.uuid4())
        conn.execute(
            sa.text(
                "INSERT INTO tenants (id, name, active, created_at) "
                "VALUES (:id, 'default', :active, :now)"
            ),
            {"id": default_tenant_id, "active": True, "now": datetime.now(UTC)},
        )
    else:
        default_tenant_id = row[0]

    # 2. Add nullable tenant_id to each scoped table. Index it for the
    #    WHERE tenant_id = ? filters Phase 2 will layer in.
    for table in _SCOPED_TABLES:
        with op.batch_alter_table(table) as batch:
            batch.add_column(sa.Column("tenant_id", sa.String(length=36), nullable=True))
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])

    # 3. Backfill the 9 new columns + the 2 pre-existing tenant_id columns
    #    (users, integrations) so no row is semantically empty.
    for table in _SCOPED_TABLES + ["users", "integrations"]:
        conn.execute(
            sa.text(f"UPDATE {table} SET tenant_id = :tid WHERE tenant_id IS NULL"),
            {"tid": default_tenant_id},
        )


def downgrade() -> None:
    for table in reversed(_SCOPED_TABLES):
        op.drop_index(f"ix_{table}_tenant_id", table_name=table)
        with op.batch_alter_table(table) as batch:
            batch.drop_column("tenant_id")
    # The "default" tenant row + backfilled users/integrations stay. That's
    # intentional: downgrading schema shouldn't silently orphan pre-existing
    # assignments. If an operator really wants to purge, they do it manually.
