"""Standalone webhook retry worker.

Runs as a long-lived loop. Every WORKER_INTERVAL_SECONDS (default 5),
calls retry_due_deliveries() which drains one batch of due retries.

Usage:
  uv run python -m supervisor_api.retry_worker

Configure via env:
  WEBHOOK_RETRY_INTERVAL=5        # seconds between polls
  WEBHOOK_RETRY_BATCH_SIZE=50     # max deliveries per cycle
"""
from __future__ import annotations

import logging
import os
import signal
import time

from .webhooks import retry_due_deliveries

log = logging.getLogger(__name__)

_shutting_down = False


def _handle_signal(*_args: object) -> None:
    global _shutting_down
    _shutting_down = True
    log.info("shutdown signal received")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="[retry-worker] %(asctime)s %(levelname)s %(message)s")
    interval = float(os.environ.get("WEBHOOK_RETRY_INTERVAL", "5"))
    batch = int(os.environ.get("WEBHOOK_RETRY_BATCH_SIZE", "50"))
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    log.info("started (interval=%.1fs batch=%d)", interval, batch)
    while not _shutting_down:
        try:
            counts = retry_due_deliveries(batch_size=batch)
            if counts["retried"] > 0:
                log.info(
                    "cycle: retried=%d succeeded=%d still_pending=%d dead=%d",
                    counts["retried"], counts["succeeded"], counts["pending"], counts["dead"],
                )
        except Exception as e:
            log.warning("cycle error: %s", e)
        # Sleep in small chunks so we respond quickly to shutdown signals.
        end = time.monotonic() + interval
        while time.monotonic() < end and not _shutting_down:
            time.sleep(min(0.5, end - time.monotonic()))
    log.info("stopped")


if __name__ == "__main__":
    main()
