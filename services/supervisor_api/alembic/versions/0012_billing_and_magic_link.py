"""billing fields on users + magic_link_tokens table

Extends `users` with subscription tier + Stripe customer/subscription IDs,
makes `password_hash` nullable (Stripe-onboarded users have no password,
they use magic links), and creates `magic_link_tokens` for passwordless
single-use auth.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.alter_column("password_hash", existing_type=sa.String(length=256), nullable=True)
        batch.add_column(sa.Column("tier", sa.String(length=16), nullable=False, server_default="free"))
        batch.add_column(sa.Column("stripe_customer_id", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("stripe_subscription_id", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("stripe_subscription_status", sa.String(length=32), nullable=True))

    op.create_index(
        "ix_users_stripe_customer_id",
        "users",
        ["stripe_customer_id"],
        unique=False,
    )

    op.create_table(
        "magic_link_tokens",
        sa.Column("token", sa.String(length=64), primary_key=True),
        sa.Column("email", sa.String(length=256), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_magic_link_tokens_email",
        "magic_link_tokens",
        ["email"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_magic_link_tokens_email", table_name="magic_link_tokens")
    op.drop_table("magic_link_tokens")

    op.drop_index("ix_users_stripe_customer_id", table_name="users")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("stripe_subscription_status")
        batch.drop_column("stripe_subscription_id")
        batch.drop_column("stripe_customer_id")
        batch.drop_column("tier")
        batch.alter_column("password_hash", existing_type=sa.String(length=256), nullable=False)
