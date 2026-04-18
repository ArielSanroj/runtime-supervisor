"""Critical alert fanout.

Emits `critical.alert` webhooks when:
  - A threat of level=critical is detected (from actions.py)
  - A webhook delivery state becomes `dead` (from webhooks.py)
  - An action_proxy execution state becomes `failed` at final attempt

All firings go through the existing outbound-webhook system so
subscribers opt in via /v1/integrations/{id}/webhooks with
events=["critical.alert"].
"""
from __future__ import annotations

from typing import Any

from .webhooks import dispatch


def emit(source: str, details: dict[str, Any]) -> None:
    """Best-effort: never raise."""
    try:
        dispatch("critical.alert", {"source": source, **details})
    except Exception:
        pass
