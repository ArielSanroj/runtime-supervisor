"""Structured JSON logging with OpenTelemetry trace_id correlation.

When stdout/stderr is piped to a log shipper (Datadog, Loki, Splunk),
every log line is machine-parseable JSON and links back to the
distributed trace via `trace_id` and `span_id`.
"""
from __future__ import annotations

import logging
import os

from opentelemetry import trace
from pythonjsonlogger import jsonlogger


class TraceIdFilter(logging.Filter):
    """Injects trace_id/span_id from the active OTEL span into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        span = trace.get_current_span()
        ctx = span.get_span_context() if span else None
        if ctx is not None and ctx.trace_id != 0:
            record.trace_id = format(ctx.trace_id, "032x")
            record.span_id = format(ctx.span_id, "016x")
        else:
            record.trace_id = None
            record.span_id = None
        record.service = os.environ.get("OTEL_SERVICE_NAME", "supervisor-api")
        return True


def configure_logging() -> None:
    if os.environ.get("LOG_JSON", "true").lower() in ("0", "false", "no"):
        logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
        return
    handler = logging.StreamHandler()
    handler.setFormatter(
        jsonlogger.JsonFormatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s %(trace_id)s %(span_id)s %(service)s",
            timestamp=True,
        )
    )
    handler.addFilter(TraceIdFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
