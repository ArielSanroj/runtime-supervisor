"""Common finding shape."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Confidence = Literal["low", "medium", "high"]


@dataclass
class Finding:
    scanner: str          # "http-routes" | "llm-calls" | "payment-calls" | "db-mutations" | "cron-schedules"
    file: str             # absolute path
    line: int             # 1-indexed
    snippet: str          # short code fragment
    suggested_action_type: str  # "refund" | "payment" | "account_change" | "data_access" | "tool_use" | "compliance" | "other"
    confidence: Confidence
    rationale: str
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
