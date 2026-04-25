"""client_id on actions for anonymous shadow integrations

Anonymous shadow mode: SDK users can post evaluate requests with a
self-generated client_id (UUID stored in their .env / .runtime-supervisor)
without an integration. The client_id groups their shadow events so
they can later be `claimed` (linked to a tenant via email signup) and
appear in their personal dashboard.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("actions") as batch:
        batch.add_column(sa.Column("client_id", sa.String(64), nullable=True))
        batch.create_index("ix_actions_client_id", ["client_id"])


def downgrade() -> None:
    with op.batch_alter_table("actions") as batch:
        batch.drop_index("ix_actions_client_id")
        batch.drop_column("client_id")
