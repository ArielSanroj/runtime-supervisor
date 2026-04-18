from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .bootstrap import seed_policies_from_yaml
from .routes import actions, catalog, integrations, metrics, policies, review, threats, webhooks
from .telemetry import setup_telemetry

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Startup: seed DB policies from YAML if the DB has none for each live action_type.
    # Opt out with SUPERVISOR_SKIP_SEED=true (used by tests that want an empty DB).
    if os.environ.get("SUPERVISOR_SKIP_SEED", "").lower() not in ("1", "true", "yes"):
        try:
            seed_policies_from_yaml()
        except Exception as e:  # defensive: never block startup on seed failure
            log.warning("policy seed skipped: %s", e)
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Agentic Internal Controls — Supervisor API",
        version="0.1.0",
        description="Gate agent actions against declarative policies + risk scoring, with tamper-evident evidence.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(actions.router)
    app.include_router(review.router)
    app.include_router(catalog.router)
    app.include_router(integrations.router)
    app.include_router(policies.router)
    app.include_router(webhooks.router)
    app.include_router(threats.router)
    app.include_router(metrics.router)

    setup_telemetry(app)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
