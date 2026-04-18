from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes import actions, catalog, integrations, policies, review, threats, webhooks


def create_app() -> FastAPI:
    app = FastAPI(
        title="Agentic Internal Controls — Supervisor API",
        version="0.1.0",
        description="Gate agent actions against declarative policies + risk scoring, with tamper-evident evidence.",
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

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
