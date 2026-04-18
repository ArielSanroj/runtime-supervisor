"""Registry of action types the supervisor intercepts.

Single source of truth consumed by:
  - Supervisor runtime (validation of incoming actions)
  - Control-center UI (what's configurable)
  - Public landing (what's live vs planned — grows as we ship)

Adding a new supervisor:
  1. Append an ActionTypeSpec here with status="live".
  2. Add a policy YAML under packages/policies/.
  3. Extend engines/risk.py if the risk signals differ from refund.
  4. Add e2e fixtures in tests/e2e/.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Status = Literal["live", "planned"]


@dataclass(frozen=True)
class ActionTypeSpec:
    id: str
    title: str
    one_liner: str
    status: Status
    intercepted_signals: list[str]
    sample_payload: dict[str, Any] | None = field(default=None)
    policy_ref: str | None = None


REGISTRY: list[ActionTypeSpec] = [
    ActionTypeSpec(
        id="refund",
        title="Refund supervision",
        one_liner="Stop risky refunds before money leaves the system.",
        status="live",
        intercepted_signals=["amount", "customer_age_days", "refund_velocity_24h", "reason"],
        sample_payload={
            "amount": 1200,
            "currency": "USD",
            "customer_id": "c_demo",
            "customer_age_days": 18,
            "refund_velocity_24h": 2,
            "reason": "changed_mind",
        },
        policy_ref="refund.base@v1",
    ),
    ActionTypeSpec(
        id="payment",
        title="Payment approvals",
        one_liner="Enforce thresholds, approval chains, sanctions screening, and anomaly detection on outgoing payments.",
        status="live",
        intercepted_signals=["amount", "vendor_id", "vendor_first_seen_days", "approval_chain", "bank_account_changed", "beneficiary_country"],
        sample_payload={
            "amount": 12000,
            "currency": "USD",
            "vendor_id": "v_demo",
            "vendor_first_seen_days": 14,
            "approval_chain": ["finance_manager"],
            "bank_account_changed": False,
            "beneficiary_country": "US",
        },
        policy_ref="payment.base@v1",
    ),
    ActionTypeSpec(
        id="account_change",
        title="Account changes",
        one_liner="Prevent unsafe updates to customer identity and profile data.",
        status="planned",
        intercepted_signals=["field_changed", "new_value_fingerprint", "actor_role", "session_risk"],
    ),
    ActionTypeSpec(
        id="data_access",
        title="Restricted data access",
        one_liner="Block unauthorized use of sensitive data by agents and the tools they call.",
        status="planned",
        intercepted_signals=["dataset", "columns", "actor", "purpose", "row_count"],
    ),
    ActionTypeSpec(
        id="tool_use",
        title="Tool-use abuse detection",
        one_liner="Detect out-of-scope or abusive tool calls — rate spikes, argument anomalies, scope drift.",
        status="planned",
        intercepted_signals=["tool_name", "arg_hash", "call_rate_60s", "scope_match"],
    ),
    ActionTypeSpec(
        id="compliance",
        title="Compliance decisions",
        one_liner="Supervise AML/KYC alert closures and other regulated-workflow outcomes.",
        status="planned",
        intercepted_signals=["alert_id", "evidence_ids", "reviewer_confidence", "rule_hits"],
    ),
]


LIVE_ACTION_TYPES: set[str] = {a.id for a in REGISTRY if a.status == "live"}


def get(action_type: str) -> ActionTypeSpec | None:
    return next((a for a in REGISTRY if a.id == action_type), None)


def as_dict(spec: ActionTypeSpec) -> dict[str, Any]:
    return {
        "id": spec.id,
        "title": spec.title,
        "one_liner": spec.one_liner,
        "status": spec.status,
        "intercepted_signals": list(spec.intercepted_signals),
        "sample_payload": spec.sample_payload,
        "policy_ref": spec.policy_ref,
    }
