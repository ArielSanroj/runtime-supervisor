"""Detect Claude Code skill / agent / plugin distribution repos.

A growing share of trending repos aren't *apps* — they're *prompt packages*:
SKILL.md files, agent personas, slash commands, or plugin manifests that
Claude Code reads to extend its behavior. The traditional scanners (looking
for `subprocess.run` and `stripe.Refund.create`) miss these entirely
because the "code" is markdown the LLM consumes, not Python the runtime
executes.

What this scanner detects:

  HIGH-confidence (the file IS a skill artifact):
    - **/SKILL.md                                 Claude Code skill marker
    - **/.claude/skills/<name>/SKILL.md           official skills directory
    - **/.claude/skills/<name>/<other>.md         supporting skill files
    - **/.claude/agents/<name>.md                 agent personas
    - **/.claude/commands/<name>.md               slash commands
    - claude-code-plugin.json                     plugin manifest (root or
    .claude-plugin/plugin.json                    .claude-plugin/)

  MEDIUM-confidence (the file may be docs, may be instructions):
    - top-level CLAUDE.md only — Claude Code reads it before every session

Why care: third-party skills/plugins are unsanitized prompts. Anything here
runs at the same trust level as Claude itself. The dev pulling a skill from
GitHub needs to know exactly what's in those instructions before activating.
"""
from __future__ import annotations

from pathlib import Path

from ..findings import Finding
from ._utils import _SKIP_DIRS

SCANNER = "skills"


_RATIONALES: dict[str, str] = {
    "skill": (
        "This is a Claude Code skill — Claude reads these instructions every "
        "time it activates. If anyone can submit a PR to this repo, they can "
        "change Claude's behavior in your dev environment. Audit the file "
        "before pulling third-party skills, and pin the commit you trust."
    ),
    "agent-md": (
        "An agent persona Claude can adopt. The instructions here decide what "
        "tools the agent uses and how aggressively. If you didn't write it, "
        "audit before activating."
    ),
    "command-md": (
        "A slash command — Claude runs this on /command. Look for shell-out "
        "steps and how it handles user-supplied parameters before installing."
    ),
    "plugin-manifest": (
        "Claude Code plugin manifest. Plugins can register tools, hooks, and "
        "slash commands that run inside your Claude Code session. Check the "
        "declared scopes (which files it can read, which commands it can "
        "shell out to) before installing."
    ),
    "claude-md": (
        "Repo-wide CLAUDE.md — every Claude Code session in this repo reads "
        "it first. Anything in here can grant tools, change shell defaults, "
        "or skip confirmations. Treat edits like a security review."
    ),
}


def _is_skipped(path: Path, root: Path) -> bool:
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in _SKIP_DIRS for part in rel_parts)


def _skill_name(path: Path, root: Path) -> str:
    """Derive a friendly name from the path. For .claude/skills/foo/SKILL.md
    that's "foo"; for top-level CLAUDE.md that's the repo name; etc."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        return path.stem
    parts = rel.parts
    # .claude/skills/<name>/...  → <name>
    if len(parts) >= 3 and parts[0] == ".claude" and parts[1] == "skills":
        return parts[2]
    # .claude/agents/<name>.md   → <name>
    if len(parts) >= 3 and parts[0] == ".claude" and parts[1] in ("agents", "commands"):
        return parts[2].rsplit(".", 1)[0]
    # plugin manifests           → repo dirname
    if path.name == "claude-code-plugin.json" or path.name == "plugin.json":
        return root.name
    # top-level CLAUDE.md        → repo dirname
    if len(parts) == 1 and parts[0].lower() == "claude.md":
        return root.name
    # arbitrary SKILL.md         → parent dir name
    return path.parent.name


def _emit(path: Path, root: Path, kind: str, confidence: str = "medium") -> Finding:
    return Finding(
        scanner=SCANNER,
        file=str(path),
        line=1,
        snippet=path.name,
        suggested_action_type="tool_use",
        confidence=confidence,  # type: ignore[arg-type]
        rationale=_RATIONALES[kind],
        extra={"kind": kind, "skill_name": _skill_name(path, root)},
    )


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[Path] = set()

    # 1. .claude/skills/<name>/<file>.md — official skills tree
    for path in root.glob(".claude/skills/*/*.md"):
        if not path.is_file() or _is_skipped(path, root):
            continue
        kind = "skill" if path.name.upper() == "SKILL.MD" else "skill"
        findings.append(_emit(path, root, kind, confidence="high"))
        seen.add(path)

    # 2. .claude/agents/<name>.md
    for path in root.glob(".claude/agents/*.md"):
        if not path.is_file() or _is_skipped(path, root):
            continue
        findings.append(_emit(path, root, "agent-md", confidence="high"))
        seen.add(path)

    # 3. .claude/commands/<name>.md
    for path in root.glob(".claude/commands/*.md"):
        if not path.is_file() or _is_skipped(path, root):
            continue
        findings.append(_emit(path, root, "command-md", confidence="high"))
        seen.add(path)

    # 4. Any other SKILL.md anywhere in the repo (catches non-standard layouts)
    for path in root.glob("**/SKILL.md"):
        if not path.is_file() or path in seen or _is_skipped(path, root):
            continue
        findings.append(_emit(path, root, "skill", confidence="high"))
        seen.add(path)

    # 5. Plugin manifest — root or .claude-plugin/
    for candidate in (
        root / "claude-code-plugin.json",
        root / ".claude-plugin" / "plugin.json",
    ):
        if candidate.is_file() and candidate not in seen:
            findings.append(_emit(candidate, root, "plugin-manifest", confidence="high"))
            seen.add(candidate)

    # 6. Top-level CLAUDE.md (don't recurse — sub-CLAUDE.md files are usually
    #    just docs for sub-packages, not skill artifacts)
    top_claude = root / "CLAUDE.md"
    if top_claude.is_file() and top_claude not in seen:
        findings.append(_emit(top_claude, root, "claude-md", confidence="medium"))

    return findings
