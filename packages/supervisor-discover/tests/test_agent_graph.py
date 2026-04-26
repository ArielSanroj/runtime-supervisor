"""Tests for the cross-file agent call-graph (parent → child detection).

The reviewer's specific complaint on supervincent: START_HERE.md said
"wrap BudgetSupervisorAgent" while combos/agent-orchestrator.md said
"wrap BudgetExtractorAgent" — but `BudgetSupervisorAgent.__init__`
instantiates `BudgetExtractorAgent`, so wrapping the supervisor covers
the extractor transitively. This module catches that pattern across
files (the two classes live in `budget_supervisor_agent.py` and
`budget_extractor_agent.py`) and tags children so the renderer can
demote them.
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.agent_graph import annotate_findings, build_parent_graph
from supervisor_discover.findings import Finding


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body.lstrip("\n"))
    return p


def _agent_finding(file: str, line: int, class_name: str) -> Finding:
    """Build the kind of agent-class finding the scanner emits."""
    return Finding(
        scanner="agent-orchestrators",
        file=file, line=line, snippet=f"class {class_name}",
        suggested_action_type="tool_use", confidence="high",
        rationale="...",
        extra={"kind": "agent-class", "class_name": class_name},
    )


# ─── Cross-file detection ───────────────────────────────────────────


def test_parent_in_one_file_instantiates_child_in_another(tmp_path: Path):
    """The exact supervincent shape: supervisor and extractor live in
    separate files; supervisor's __init__ constructs the extractor."""
    parent_file = _write(tmp_path, "agents/budget_supervisor_agent.py", """
from .budget_extractor_agent import BudgetExtractorAgent

class BudgetSupervisorAgent:
    def __init__(self, repo, ollama_service):
        self._extractor = BudgetExtractorAgent(repo, ollama_service)

    def run(self):
        return self._extractor.handle()
""")
    child_file = _write(tmp_path, "agents/budget_extractor_agent.py", """
class BudgetExtractorAgent:
    def __init__(self, repo, ollama_service):
        self.repo = repo
        self.ollama_service = ollama_service

    def handle(self):
        return None
""")
    findings = [
        _agent_finding(str(parent_file), 4, "BudgetSupervisorAgent"),
        _agent_finding(str(child_file), 1, "BudgetExtractorAgent"),
    ]
    parent_map = build_parent_graph(findings)
    assert parent_map == {"BudgetExtractorAgent": "BudgetSupervisorAgent"}


def test_parent_in_same_file_still_detected(tmp_path: Path):
    """Single-file case: both parent and child in one module."""
    src = _write(tmp_path, "agents/orchestrator.py", """
class HelperAgent:
    def run(self):
        return 1

class OrchestratorAgent:
    def __init__(self):
        self._helper = HelperAgent()
""")
    findings = [
        _agent_finding(str(src), 5, "OrchestratorAgent"),
        _agent_finding(str(src), 1, "HelperAgent"),
    ]
    parent_map = build_parent_graph(findings)
    assert parent_map == {"HelperAgent": "OrchestratorAgent"}


def test_attribute_access_constructor_call_detected(tmp_path: Path):
    """`mod.HelperAgent()` (attribute call) — we match on the rightmost
    identifier so this counts the same as `HelperAgent()`."""
    src = _write(tmp_path, "agents/orchestrator.py", """
import agents.helper as helper_mod

class HelperAgent:
    pass

class OrchestratorAgent:
    def __init__(self):
        self._helper = helper_mod.HelperAgent()
""")
    findings = [
        _agent_finding(str(src), 6, "OrchestratorAgent"),
        _agent_finding(str(src), 3, "HelperAgent"),
    ]
    parent_map = build_parent_graph(findings)
    assert parent_map.get("HelperAgent") == "OrchestratorAgent"


# ─── No parent ────────────────────────────────────────────────────


def test_sibling_classes_no_instantiation_returns_empty(tmp_path: Path):
    src = _write(tmp_path, "agents/two.py", """
class FirstAgent:
    def run(self): return 1

class SecondAgent:
    def run(self): return 2
""")
    findings = [
        _agent_finding(str(src), 1, "FirstAgent"),
        _agent_finding(str(src), 4, "SecondAgent"),
    ]
    assert build_parent_graph(findings) == {}


def test_self_reference_not_a_parent(tmp_path: Path):
    """A class that constructs itself (factory method, recursive shape)
    must not be marked as its own parent."""
    src = _write(tmp_path, "agents/clone.py", """
class CloningAgent:
    def __init__(self, depth):
        self.depth = depth

    @classmethod
    def make(cls, depth):
        return CloningAgent(depth)
""")
    findings = [_agent_finding(str(src), 1, "CloningAgent")]
    assert build_parent_graph(findings) == {}


def test_class_outside_chokepoint_set_ignored(tmp_path: Path):
    """`OrchestratorAgent` instantiates `Database` — but `Database` isn't
    an agent-class chokepoint, so it doesn't show up in the parent map."""
    src = _write(tmp_path, "agents/orch.py", """
class Database:
    pass

class OrchestratorAgent:
    def __init__(self):
        self.db = Database()
""")
    findings = [_agent_finding(str(src), 4, "OrchestratorAgent")]
    parent_map = build_parent_graph(findings)
    assert parent_map == {}


# ─── Multi-child, cycle, idempotency ────────────────────────────────


def test_multiple_children_under_one_parent(tmp_path: Path):
    """A parent that constructs three children should map all three."""
    parent_file = _write(tmp_path, "agents/orch.py", """
from .a import AlphaAgent
from .b import BetaAgent
from .g import GammaAgent

class OrchestratorAgent:
    def __init__(self):
        self.a = AlphaAgent()
        self.b = BetaAgent()
        self.g = GammaAgent()
""")
    a = _write(tmp_path, "agents/a.py", "class AlphaAgent: pass\n")
    b = _write(tmp_path, "agents/b.py", "class BetaAgent: pass\n")
    g = _write(tmp_path, "agents/g.py", "class GammaAgent: pass\n")
    findings = [
        _agent_finding(str(parent_file), 5, "OrchestratorAgent"),
        _agent_finding(str(a), 1, "AlphaAgent"),
        _agent_finding(str(b), 1, "BetaAgent"),
        _agent_finding(str(g), 1, "GammaAgent"),
    ]
    parent_map = build_parent_graph(findings)
    assert parent_map == {
        "AlphaAgent": "OrchestratorAgent",
        "BetaAgent": "OrchestratorAgent",
        "GammaAgent": "OrchestratorAgent",
    }


def test_cycle_first_parent_wins(tmp_path: Path):
    """A cycle (A constructs B, B constructs A) — first parent assigned
    wins. We don't need to be smart about cycles; any deterministic
    behavior is fine."""
    a_file = _write(tmp_path, "agents/a.py", """
from .b import BAgent

class AAgent:
    def __init__(self):
        self.b = BAgent()
""")
    b_file = _write(tmp_path, "agents/b.py", """
from .a import AAgent

class BAgent:
    def __init__(self):
        self.a = AAgent()
""")
    findings = [
        _agent_finding(str(a_file), 3, "AAgent"),
        _agent_finding(str(b_file), 3, "BAgent"),
    ]
    parent_map = build_parent_graph(findings)
    # Both edges exist in the source; the algorithm picks the first one
    # it encounters (deterministic on findings order).
    assert parent_map.get("BAgent") == "AAgent" or parent_map.get("AAgent") == "BAgent"
    assert len(parent_map) >= 1


# ─── annotate_findings ──────────────────────────────────────────────


def test_annotate_writes_parent_agent_to_extra(tmp_path: Path):
    parent_file = _write(tmp_path, "agents/orch.py", """
from .child import ChildAgent

class OrchestratorAgent:
    def __init__(self):
        self.child = ChildAgent()
""")
    child_file = _write(tmp_path, "agents/child.py", "class ChildAgent: pass\n")
    findings = [
        _agent_finding(str(parent_file), 3, "OrchestratorAgent"),
        _agent_finding(str(child_file), 1, "ChildAgent"),
    ]
    annotate_findings(findings)
    parent_finding = findings[0]
    child_finding = findings[1]
    assert (parent_finding.extra or {}).get("parent_agent") is None
    assert child_finding.extra["parent_agent"] == "OrchestratorAgent"


def test_annotate_is_idempotent(tmp_path: Path):
    parent_file = _write(tmp_path, "agents/orch.py", """
from .c import C

class P:
    def __init__(self):
        self.c = C()
""")
    child_file = _write(tmp_path, "agents/c.py", "class C: pass\n")
    findings = [
        _agent_finding(str(parent_file), 3, "P"),
        _agent_finding(str(child_file), 1, "C"),
    ]
    annotate_findings(findings)
    first = findings[1].extra["parent_agent"]
    annotate_findings(findings)
    assert findings[1].extra["parent_agent"] == first


def test_no_agent_classes_returns_empty():
    findings: list[Finding] = []
    assert build_parent_graph(findings) == {}
    assert annotate_findings(findings) == {}
