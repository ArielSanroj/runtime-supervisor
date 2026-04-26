"""Cross-file agent call-graph: detect parent → child instantiation.

The reviewer flagged on supervincent that `BudgetSupervisorAgent` and
`BudgetExtractorAgent` were both surfaced as wrap targets. They're
distinct classes — the dev couldn't tell which to wrap, or whether
wrapping one covered the other. In fact `BudgetSupervisorAgent.__init__`
instantiates `BudgetExtractorAgent` (`self._extractor = BudgetExtractorAgent(...)`)
and dispatches through it. Wrapping the supervisor covers the extractor
transitively.

This module:

  1. Builds a `{child: parent}` map from the set of agent-class findings
     by parsing each parent's file, finding the class body, and looking
     for `ChildClassName(...)` constructor calls inside it.
  2. Annotates each child finding with `extra["parent_agent"]` so the
     renderer can mark it as "covered by parent — wrap parent first".

The match is by class NAME — not by import resolution — because we want
the cheapest possible cross-file detection. False positives (a class
with the same name in another module instantiated incidentally) are
bounded: the candidate parent must itself be an agent-class chokepoint.
"""
from __future__ import annotations

import ast
from pathlib import Path

from .findings import Finding
from .scanners._utils import parse_python, safe_read


def _agent_class_findings(findings: list[Finding]) -> list[Finding]:
    return [
        f for f in findings
        if f.scanner == "agent-orchestrators"
        and (f.extra or {}).get("kind") == "agent-class"
    ]


def _class_name_of(f: Finding) -> str | None:
    return (f.extra or {}).get("class_name")


def _instantiated_class_names(class_node: ast.ClassDef) -> set[str]:
    """Return the set of class names this class's methods construct.

    A constructor call is `ast.Call` whose `func` is `ast.Name` (bare
    `ChildClass(...)`) or `ast.Attribute` (`mod.ChildClass(...)`). We
    take the rightmost identifier in either case so `from .x import
    ChildClass; ChildClass(...)` and `import .x; x.ChildClass(...)`
    both count.
    """
    names: set[str] = set()
    for node in ast.walk(class_node):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            names.add(func.id)
        elif isinstance(func, ast.Attribute):
            names.add(func.attr)
    return names


def build_parent_graph(findings: list[Finding]) -> dict[str, str]:
    """Return `{child_class_name: parent_class_name}` for the agent-class
    chokepoints in `findings`.

    Single-pass: each finding's file is parsed once, the matching ClassDef
    is walked, and any constructor call to another agent-class name is
    recorded. First parent wins (deterministic on file ordering — caller
    can pre-sort `findings` by `finding_wrap_rank` to prefer factory-file
    parents). Pure name-matching: no import resolution.
    """
    classes = _agent_class_findings(findings)
    by_name: dict[str, Finding] = {}
    for f in classes:
        name = _class_name_of(f)
        if name and name not in by_name:
            by_name[name] = f
    if not by_name:
        return {}

    parent_of: dict[str, str] = {}
    parsed_files: dict[str, ast.Module | None] = {}

    for parent_finding in classes:
        parent_name = _class_name_of(parent_finding)
        if not parent_name:
            continue
        path_str = parent_finding.file
        if path_str not in parsed_files:
            text = safe_read(Path(path_str))
            parsed_files[path_str] = parse_python(text) if text is not None else None
        tree = parsed_files[path_str]
        if tree is None:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if node.name != parent_name:
                continue
            for child_name in _instantiated_class_names(node):
                if child_name == parent_name:
                    continue
                if child_name in by_name and child_name not in parent_of:
                    parent_of[child_name] = parent_name
            break  # one matching class per file

    return parent_of


def annotate_findings(findings: list[Finding]) -> dict[str, str]:
    """Walk findings, build the parent graph, write `extra.parent_agent`
    onto every child agent-class finding. Returns the parent map for
    callers that want to render it directly.

    Idempotent — calling twice with the same findings produces the same
    annotations.
    """
    parent_map = build_parent_graph(findings)
    if not parent_map:
        return parent_map
    for f in findings:
        if f.scanner != "agent-orchestrators":
            continue
        if (f.extra or {}).get("kind") != "agent-class":
            continue
        name = _class_name_of(f)
        if not name:
            continue
        parent = parent_map.get(name)
        if parent and (f.extra or {}).get("parent_agent") != parent:
            f.extra = {**(f.extra or {}), "parent_agent": parent}
    return parent_map
