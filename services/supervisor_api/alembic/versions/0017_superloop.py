"""superloop tables — Registro Canónico, Decision Ledger, cycle history

Backs the closed-loop business agent (SUPERLOOP.md). `superloop_products` is the
single source of truth per business unit (R4); `superloop_decisions` is the
append-only Decision Ledger (R8) and links Level >= 3 decisions to the existing
review queue via `review_item_id` (R1); `superloop_cycles` is per-turn run history.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "superloop_products",
        sa.Column("producto_id", sa.String(length=128), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("kind", sa.String(length=16), nullable=False, server_default="repo"),
        sa.Column("nombre", sa.String(length=512), nullable=False),
        sa.Column("source_ref", sa.String(length=512), nullable=True),
        sa.Column("estado_operativo", sa.String(length=24), nullable=True),
        sa.Column("estado_comercial", sa.String(length=24), nullable=True),
        sa.Column("confianza_estado", sa.Float, nullable=True),
        sa.Column("metrica_principal", sa.String(length=64), nullable=True),
        sa.Column("kpis", sa.JSON, nullable=False),
        sa.Column("afirmaciones", sa.JSON, nullable=False),
        sa.Column("hipotesis_vigente", sa.String(length=1000), nullable=True),
        sa.Column("decision_recomendada_ref", sa.String(length=36), nullable=True),
        sa.Column("estado_aprobacion", sa.String(length=24), nullable=False, server_default="pendiente"),
        sa.Column("proxima_mejor_accion", sa.String(length=1000), nullable=True),
        sa.Column("ultimo_ciclo", sa.JSON, nullable=False),
        sa.Column("historial", sa.JSON, nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_superloop_products_tenant_id", "superloop_products", ["tenant_id"])

    op.create_table(
        "superloop_decisions",
        sa.Column("decision_id", sa.String(length=36), primary_key=True),
        sa.Column("producto_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("ciclo_id", sa.String(length=36), nullable=True),
        sa.Column("fase_origen", sa.String(length=16), nullable=False, server_default="decide"),
        sa.Column("decision_recomendada", sa.String(length=2000), nullable=False),
        sa.Column("accion_tipo", sa.String(length=32), nullable=False, server_default="observe"),
        sa.Column("hipotesis", sa.String(length=2000), nullable=True),
        sa.Column("metrica_objetivo", sa.String(length=64), nullable=True),
        sa.Column("criterio_exito", sa.String(length=1000), nullable=True),
        sa.Column("ventana_medicion", sa.String(length=64), nullable=True),
        sa.Column("nivel_autonomia", sa.Integer, nullable=False, server_default="0"),
        sa.Column("riesgo", sa.String(length=16), nullable=True),
        sa.Column("razonamiento", sa.String(length=4000), nullable=True),
        sa.Column("opciones_consideradas", sa.JSON, nullable=False),
        sa.Column("datos_usados", sa.JSON, nullable=False),
        sa.Column("afirmaciones", sa.JSON, nullable=False),
        sa.Column("estado_aprobacion", sa.String(length=24), nullable=False, server_default="pendiente"),
        sa.Column("aprobador", sa.String(length=128), nullable=True),
        sa.Column("review_item_id", sa.String(length=36), nullable=True),
        sa.Column("accion_ejecutada", sa.String(length=2000), nullable=True),
        sa.Column("resultado", sa.String(length=2000), nullable=True),
        sa.Column("aprendizaje", sa.String(length=2000), nullable=True),
        sa.Column("siguiente_movimiento", sa.String(length=16), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_superloop_decisions_producto_id", "superloop_decisions", ["producto_id"])
    op.create_index("ix_superloop_decisions_tenant_id", "superloop_decisions", ["tenant_id"])
    op.create_index("ix_superloop_decisions_ciclo_id", "superloop_decisions", ["ciclo_id"])
    op.create_index("ix_superloop_decisions_estado_aprobacion", "superloop_decisions", ["estado_aprobacion"])
    op.create_index("ix_superloop_decisions_review_item_id", "superloop_decisions", ["review_item_id"])
    op.create_index("ix_superloop_decisions_created_at", "superloop_decisions", ["created_at"])

    op.create_table(
        "superloop_cycles",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("producto_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("scope", sa.String(length=16), nullable=False, server_default="all"),
        sa.Column("fase_alcanzada", sa.String(length=16), nullable=False),
        sa.Column("detenido_en", sa.String(length=16), nullable=True),
        sa.Column("business_card", sa.JSON, nullable=False),
        sa.Column("evidence_pack", sa.JSON, nullable=False),
        sa.Column("error", sa.String(length=1000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_superloop_cycles_run_id", "superloop_cycles", ["run_id"])
    op.create_index("ix_superloop_cycles_producto_id", "superloop_cycles", ["producto_id"])
    op.create_index("ix_superloop_cycles_tenant_id", "superloop_cycles", ["tenant_id"])
    op.create_index("ix_superloop_cycles_created_at", "superloop_cycles", ["created_at"])


def downgrade() -> None:
    op.drop_table("superloop_cycles")
    op.drop_table("superloop_decisions")
    op.drop_table("superloop_products")
