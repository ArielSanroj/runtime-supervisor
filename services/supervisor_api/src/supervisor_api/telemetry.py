"""OpenTelemetry setup.

Enabled only when OTEL_EXPORTER_OTLP_ENDPOINT is set. In tests / dev
without that env var, setup_telemetry is a no-op and get_tracer returns
a no-op tracer so manual spans in the code are zero-overhead.

To see traces locally, run a collector (e.g. Jaeger all-in-one:
`docker run -p 4318:4318 -p 16686:16686 jaegertracing/all-in-one`) and set
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 when running uvicorn.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from opentelemetry import trace

log = logging.getLogger(__name__)

_SERVICE_NAME = "supervisor-api"
_configured = False


def setup_telemetry(app: Any | None = None) -> None:
    """Idempotent. Instrument FastAPI + SQLAlchemy if OTEL env is present."""
    global _configured
    if _configured:
        return
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        _configured = True
        return
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create(
            {
                "service.name": os.environ.get("OTEL_SERVICE_NAME", _SERVICE_NAME),
                "service.version": os.environ.get("APP_VERSION", "0.1.0"),
                "deployment.environment": os.environ.get("APP_ENV", "dev"),
            }
        )
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces")
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        if app is not None:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            FastAPIInstrumentor.instrument_app(app)

        try:
            from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

            from .db import engine
            SQLAlchemyInstrumentor().instrument(engine=engine)
        except Exception as e:
            log.warning("SQLAlchemy instrumentation skipped: %s", e)

        log.info("OTEL tracing enabled → %s (service=%s)", endpoint, _SERVICE_NAME)
    except Exception as e:
        log.warning("OTEL setup failed, traces disabled: %s", e)
    finally:
        _configured = True


def get_tracer(name: str = _SERVICE_NAME):
    """Always returns a tracer — no-op when OTEL isn't configured."""
    return trace.get_tracer(name)
