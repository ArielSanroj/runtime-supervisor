"""metadata JSON column on magic_link_tokens

Lets us attach arbitrary context to a single-use token (e.g. the
client_id being claimed from anonymous shadow events). Avoids growing
the table once per new flow that wants to ride the magic-link
delivery + exchange machinery.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("magic_link_tokens") as batch:
        batch.add_column(sa.Column("token_metadata", sa.JSON, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("magic_link_tokens") as batch:
        batch.drop_column("token_metadata")
