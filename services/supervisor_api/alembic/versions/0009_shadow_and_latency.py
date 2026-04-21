"""shadow flag on actions + latency_ms on decisions

Shadow mode: evaluate the call, record the decision, but don't enforce
on the caller. Used to measure what the supervisor would block before
flipping enforcement on in production.

latency_ms: how long the evaluate endpoint took end-to-end. Reported in
/v1/metrics/enforcement so operators can see the friction cost.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("actions") as batch:
        batch.add_column(sa.Column("shadow", sa.Boolean, nullable=False, server_default=sa.false()))
    with op.batch_alter_table("decisions") as batch:
        batch.add_column(sa.Column("latency_ms", sa.Integer, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("decisions") as batch:
        batch.drop_column("latency_ms")
    with op.batch_alter_table("actions") as batch:
        batch.drop_column("shadow")
