"""Tests for the Claude Code skills / plugins / agents detector."""
from __future__ import annotations

import json
from pathlib import Path

from supervisor_discover.scanners import scan_all
from supervisor_discover.scanners.skills import scan
from supervisor_discover.summary import build_summary


def test_skill_md_in_official_dir(tmp_path: Path):
    """`.claude/skills/foo/SKILL.md` is the canonical layout — must fire."""
    (tmp_path / ".claude" / "skills" / "foo").mkdir(parents=True)
    (tmp_path / ".claude" / "skills" / "foo" / "SKILL.md").write_text(
        "---\nname: foo\n---\n# Foo skill body"
    )
    findings = scan(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "skills"
    assert f.extra["kind"] == "skill"
    assert f.extra["skill_name"] == "foo"
    assert f.confidence == "high"


def test_plugin_manifest_at_root_or_dotfolder(tmp_path: Path):
    """Both `claude-code-plugin.json` at root and `.claude-plugin/plugin.json`
    are the recognized manifest locations."""
    (tmp_path / "claude-code-plugin.json").write_text("{}")
    findings = scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].extra["kind"] == "plugin-manifest"

    # Now add the .claude-plugin variant — should add another finding.
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text('{"name":"x"}')
    findings = scan(tmp_path)
    kinds = [f.extra["kind"] for f in findings]
    assert kinds.count("plugin-manifest") == 2


def test_skill_only_repo_resolves_to_claude_skill_repo_type(tmp_path: Path):
    """A repo with just SKILL.md / CLAUDE.md / no Python or TS code should
    classify as `repo_type=claude-skill` so the UI can show the skill-specific
    guidance instead of the generic one-liner."""
    (tmp_path / "CLAUDE.md").write_text("# repo-wide instructions")
    (tmp_path / ".claude" / "skills" / "test-skill").mkdir(parents=True)
    (tmp_path / ".claude" / "skills" / "test-skill" / "SKILL.md").write_text("# Test skill")
    findings = scan_all(tmp_path)
    summary = build_summary(findings)
    assert summary.repo_type == "claude-skill"
    # The one_liner should reframe — no "real-world actions" filler.
    assert "Claude Code skill" in summary.one_liner or "skill" in summary.one_liner.lower()


def test_skill_repo_with_real_app_surface_keeps_app_classification(tmp_path: Path):
    """If a repo has BOTH a CLAUDE.md AND real LLM/payment code, it's an app
    with skill docs — not a skill package. repo_type should NOT be claude-skill."""
    (tmp_path / "CLAUDE.md").write_text("# instructions")
    (tmp_path / "app.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "client.chat.completions.create(model='gpt-4', messages=[])\n"
    )
    findings = scan_all(tmp_path)
    summary = build_summary(findings)
    # Has app surface → repo_type should be None or langchain/mcp, not claude-skill.
    assert summary.repo_type != "claude-skill"
