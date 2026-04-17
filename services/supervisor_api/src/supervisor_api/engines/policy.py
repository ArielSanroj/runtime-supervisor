from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from asteval import Interpreter


@dataclass(frozen=True)
class PolicyHit:
    rule_id: str
    action: str  # allow|deny|review
    reason: str


@dataclass(frozen=True)
class Policy:
    name: str
    version: int
    rules: list[dict[str, Any]]

    @property
    def version_tag(self) -> str:
        return f"{self.name}@v{self.version}"


def load_policy(path: str | Path) -> Policy:
    data = yaml.safe_load(Path(path).read_text())
    if not isinstance(data, dict):
        raise ValueError(f"policy {path} must be a YAML mapping")
    name = str(data["name"])
    version = int(data["version"])
    rules = data.get("rules") or []
    for r in rules:
        for k in ("id", "when", "action", "reason"):
            if k not in r:
                raise ValueError(f"rule missing key '{k}': {r}")
        if r["action"] not in {"allow", "deny", "review"}:
            raise ValueError(f"invalid rule action: {r['action']}")
    return Policy(name=name, version=version, rules=rules)


def evaluate(policy: Policy, payload: dict[str, Any]) -> list[PolicyHit]:
    hits: list[PolicyHit] = []
    for rule in policy.rules:
        interp = Interpreter(minimal=True, use_numpy=False)
        interp.symtable["payload"] = payload
        try:
            result = interp(rule["when"])
        except Exception as e:  # defensive: malformed rule should not crash
            raise ValueError(f"rule {rule['id']} eval error: {e}") from e
        if interp.error:
            msgs = "; ".join(str(err.get_error()) for err in interp.error)
            raise ValueError(f"rule {rule['id']} eval error: {msgs}")
        if bool(result):
            hits.append(PolicyHit(rule_id=rule["id"], action=rule["action"], reason=rule["reason"]))
    return hits


def worst_action(hits: list[PolicyHit]) -> str | None:
    """deny > review > allow. Returns None if no hits."""
    order = {"deny": 2, "review": 1, "allow": 0}
    if not hits:
        return None
    return max(hits, key=lambda h: order[h.action]).action
