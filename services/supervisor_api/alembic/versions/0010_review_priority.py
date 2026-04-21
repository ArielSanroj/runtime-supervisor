"""priority + assigned_to on review_items for SLA + escalation

Reviewer UX needs: (a) sort/filter by priority, (b) escalate a pending case
to a higher bucket (normal → high). `assigned_to` holds an optional role
name so escalation can route to a different queue (e.g. compliance).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("review_items") as batch:
        batch.add_column(sa.Column("priority", sa.String(length=16), nullable=False, server_default="normal"))
        batch.add_column(sa.Column("assigned_to", sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("review_items") as batch:
        batch.drop_column("assigned_to")
        batch.drop_column("priority")
