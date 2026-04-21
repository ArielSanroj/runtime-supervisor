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
    # Optional plain-language explanation authored in the policy YAML. Used
    # by the review UI so operators don't have to interpret rule_ids.
    explanation: str | None = None


@dataclass(frozen=True)
class Policy:
    name: str
    version: int
    rules: list[dict[str, Any]]

    @property
    def version_tag(self) -> str:
        return f"{self.name}@v{self.version}"


def _compile_yaml(source: str | bytes, origin: str = "<inline>") -> Policy:
    data = yaml.safe_load(source)
    if not isinstance(data, dict):
        raise ValueError(f"policy {origin} must be a YAML mapping")
    if "name" not in data or "version" not in data:
        raise ValueError(f"policy {origin} missing name or version")
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


def load_policy(path: str | Path) -> Policy:
    return _compile_yaml(Path(path).read_text(), origin=str(path))


def compile_policy_yaml(source: str) -> Policy:
    """Parse + validate a YAML string; raises ValueError if not a valid policy.

    Syntax-checks each rule's `when` expression with ast.parse so policies
    can't be promoted with typos. Runtime errors on specific payloads (KeyError,
    TypeError) are not caught here — those surface at evaluate time.
    """
    import ast

    policy = _compile_yaml(source)
    for rule in policy.rules:
        try:
            ast.parse(rule["when"], mode="eval")
        except SyntaxError as e:
            raise ValueError(f"rule {rule['id']} has invalid `when` (syntax): {e}") from e
    return policy


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
            hits.append(PolicyHit(
                rule_id=rule["id"],
                action=rule["action"],
                reason=rule["reason"],
                explanation=rule.get("explanation"),
            ))
    return hits


def worst_action(hits: list[PolicyHit]) -> str | None:
    """deny > review > allow. Returns None if no hits."""
    order = {"deny": 2, "review": 1, "allow": 0}
    if not hits:
        return None
    return max(hits, key=lambda h: order[h.action]).action


def resolve_policy_path(action_type: str, repo_root: Path) -> Path:
    """Locate the policy file for a given action_type under packages/policies/.

    Looks for `<action_type>.base.v1.yaml` — the naming convention used by
    every live supervisor. Bumping versions would use a manifest later.
    """
    return repo_root / "packages/policies" / f"{action_type}.base.v1.yaml"


def load_for_action_type(action_type: str, repo_root: Path) -> Policy:
    return load_policy(resolve_policy_path(action_type, repo_root))


def load_for_action_type_with_db(action_type: str, db, repo_root: Path) -> Policy:
    """Prefer the DB-managed active policy for this action_type; fall back to
    the checked-in YAML under packages/policies/."""
    from sqlalchemy import select

    from ..models import PolicyRecord

    row = db.execute(
        select(PolicyRecord)
        .where(PolicyRecord.action_type == action_type, PolicyRecord.is_active.is_(True))
        .order_by(PolicyRecord.version.desc())
        .limit(1)
    ).scalar_one_or_none()
    if row is not None:
        return _compile_yaml(row.yaml_source, origin=f"db:{row.id}")
    return load_for_action_type(action_type, repo_root)
