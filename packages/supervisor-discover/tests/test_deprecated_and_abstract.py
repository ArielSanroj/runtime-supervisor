"""Filter `@deprecated` classes and `@abstractmethod` / pure-stub methods
out of agent-orchestrator chokepoint findings.

Background: scanning langchain (the framework repo) lit up `XMLAgent`,
`SelfAskWithSearchAgent`, and `ConversationalAgent` as top wrap targets,
but each is decorated `@deprecated("0.1.0", removal="1.0")` and slated
for removal. The same scan emitted `def plan(...)` chokepoints on
`agents/agent.py:68`, which is `@abstractmethod` — wrapping it does
nothing because subclasses don't inherit decorators applied to abstracts.

The fix is AST-side: read `decorator_list`, recognize the contract
markers, drop the finding before it's emitted. Regex on source text would
have caught `@deprecated` in a comment by mistake (defense layer 3).
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.findings import Finding
from supervisor_discover.scanners import agent_orchestrators


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def _scan(tmp: Path) -> list[Finding]:
    return agent_orchestrators.scan(tmp)


def _classes(findings: list[Finding]) -> dict[str, Finding]:
    return {
        (f.extra or {}).get("class_name"): f
        for f in findings
        if (f.extra or {}).get("kind") == "agent-class"
    }


def _methods(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if (f.extra or {}).get("kind") == "agent-method"]


# ─── @deprecated classes ───────────────────────────────────────────


def test_deprecated_class_skipped(tmp_path: Path):
    """The XMLAgent shape: an agent-shaped class name decorated with
    `@deprecated(...)`. Should not appear in chokepoint output at all."""
    _write(tmp_path, "agents/xml/base.py", """
import openai
from langchain._api import deprecated

@deprecated("0.1.0", removal="1.0")
class XMLAgent:
    def plan(self, intermediate_steps, **kwargs):
        return openai.chat.completions.create(messages=[])
""")
    findings = _scan(tmp_path)
    classes = _classes(findings)
    assert "XMLAgent" not in classes


def test_deprecated_class_with_bare_decorator(tmp_path: Path):
    """`@deprecated` without arguments (call-less form) also skipped."""
    _write(tmp_path, "agents/legacy/base.py", """
import openai
from typing import deprecated

@deprecated
class LegacyAgent:
    def plan(self):
        return openai.chat.completions.create(messages=[])
""")
    findings = _scan(tmp_path)
    classes = _classes(findings)
    assert "LegacyAgent" not in classes


def test_deprecated_class_method_also_skipped(tmp_path: Path):
    """Methods nested inside a `@deprecated` class shouldn't be emitted as
    chokepoints either — the whole class is on its way out."""
    _write(tmp_path, "agents/zombie/base.py", """
import openai
from warnings import deprecated

@deprecated("removed in 2.0")
class ZombieAgent:
    def plan(self):
        return openai.chat.completions.create(messages=[])
    def execute(self):
        return openai.chat.completions.create(messages=[])
""")
    findings = _scan(tmp_path)
    method_findings = _methods(findings)
    method_names = {(f.extra or {}).get("method_name") for f in method_findings}
    assert "plan" not in method_names
    assert "execute" not in method_names


def test_non_deprecated_class_still_emitted(tmp_path: Path):
    """Regression guard: a normal agent class with no `@deprecated` decorator
    must still be detected as a chokepoint."""
    _write(tmp_path, "agents/real_agent.py", """
import openai

class RealAgent:
    def plan(self, msgs):
        return openai.chat.completions.create(messages=msgs)
""")
    findings = _scan(tmp_path)
    classes = _classes(findings)
    assert "RealAgent" in classes
    assert classes["RealAgent"].confidence == "high"


def test_at_deprecated_in_comment_does_not_trigger_filter(tmp_path: Path):
    """Defense layer 3: AST-only. A class with `# @deprecated` in a comment
    near it is NOT actually deprecated — the regex-tempted bug would skip
    it. AST sees through that."""
    _write(tmp_path, "agents/commented.py", """
import openai

# @deprecated in old version, kept for compatibility
class CommentedAgent:
    def plan(self):
        return openai.chat.completions.create(messages=[])
""")
    findings = _scan(tmp_path)
    classes = _classes(findings)
    assert "CommentedAgent" in classes


# ─── @abstractmethod and pure-stub methods ────────────────────────


def test_abstractmethod_skipped(tmp_path: Path):
    """`def plan(...)` decorated `@abstractmethod` shouldn't be a
    chokepoint — subclasses don't inherit decorators on abstracts."""
    _write(tmp_path, "agents/base.py", """
import openai
from abc import abstractmethod

class BaseAgentInterface:
    @abstractmethod
    def plan(self, msgs):
        '''subclasses must implement.'''
""")
    findings = _scan(tmp_path)
    method_names = {(f.extra or {}).get("method_name") for f in _methods(findings)}
    assert "plan" not in method_names


def test_abc_qualified_abstractmethod_skipped(tmp_path: Path):
    """Qualified form `@abc.abstractmethod` recognised the same way."""
    _write(tmp_path, "agents/iface.py", """
import abc
import openai

class IfaceAgent(abc.ABC):
    @abc.abstractmethod
    def execute(self):
        ...
""")
    findings = _scan(tmp_path)
    method_names = {(f.extra or {}).get("method_name") for f in _methods(findings)}
    assert "execute" not in method_names


def test_docstring_only_method_skipped(tmp_path: Path):
    """A method whose body is only a docstring is a stub — wrapping it
    has no effect at runtime. Common in interface classes that omit
    `@abstractmethod` but still don't implement."""
    _write(tmp_path, "agents/proto.py", """
import openai

class ProtoAgent:
    def plan(self, msgs):
        '''Return a tool call to invoke. Subclasses override.'''
""")
    findings = _scan(tmp_path)
    method_names = {(f.extra or {}).get("method_name") for f in _methods(findings)}
    assert "plan" not in method_names


def test_raise_notimplemented_method_skipped(tmp_path: Path):
    """Body == `raise NotImplementedError(...)` → not a real chokepoint."""
    _write(tmp_path, "agents/stub.py", """
import openai

class StubAgent:
    def plan(self, msgs):
        raise NotImplementedError("override in subclass")
""")
    findings = _scan(tmp_path)
    method_names = {(f.extra or {}).get("method_name") for f in _methods(findings)}
    assert "plan" not in method_names


def test_concrete_method_still_emitted(tmp_path: Path):
    """Regression guard: a real `def plan(...)` with a body that does work
    must surface as a chokepoint somewhere — either the enclosing class or
    the method itself, depending on the existing _near_class_hit dedup."""
    _write(tmp_path, "agents/concrete.py", """
import openai

class ConcreteAgent:
    def plan(self, msgs):
        result = self._dispatch(msgs)
        return openai.chat.completions.create(messages=result)
    def _dispatch(self, msgs):
        return msgs
""")
    findings = _scan(tmp_path)
    classes = _classes(findings)
    method_names = {(f.extra or {}).get("method_name") for f in _methods(findings)}
    # Either the class lands as a chokepoint (the standard outcome — the
    # nearby class hit dedups the method) OR the method is emitted on its
    # own. Both prove the concrete impl is reachable in the report.
    assert "ConcreteAgent" in classes or "plan" in method_names


def test_concrete_method_outside_class_still_emitted(tmp_path: Path):
    """Concrete top-level `plan(...)` (rare but possible) must still surface
    as an agent-method finding — there's no class to anchor the dedup."""
    _write(tmp_path, "agents/loose.py", """
import openai

def plan(msgs):
    return openai.chat.completions.create(messages=msgs)
""")
    findings = _scan(tmp_path)
    method_names = {(f.extra or {}).get("method_name") for f in _methods(findings)}
    assert "plan" in method_names
