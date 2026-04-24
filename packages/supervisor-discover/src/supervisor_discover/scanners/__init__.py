from __future__ import annotations

from pathlib import Path

from ..findings import Finding
from . import (
    agent_orchestrators,
    calendar_actions,
    cron_schedules,
    db_mutations,
    email_sends,
    fs_shell,
    http_routes,
    llm_calls,
    mcp_tools,
    media_gen,
    messaging,
    payment_calls,
    skills,
    voice_actions,
)
from ._utils import _extract_notebook_python


def scan_all(root: Path) -> list[Finding]:
    """Run every scanner against the repo rooted at `root`."""
    findings: list[Finding] = []
    for module in (
        http_routes,
        llm_calls,
        payment_calls,
        db_mutations,
        cron_schedules,
        # real-world-actions tier — what agents actually DO in prod
        voice_actions,
        messaging,
        email_sends,
        calendar_actions,
        fs_shell,
        media_gen,
        # agent orchestration chokepoints — where ALL agent actions flow through
        agent_orchestrators,
        mcp_tools,
        # skill / plugin / agent-md surface — repos that distribute prompts
        # Claude Code ingests, not Python the runtime executes
        skills,
    ):
        findings.extend(module.scan(root))
    findings = _downgrade_eval_paths(findings, root)
    return _self_check(findings)


# Paths that imply "this is research / benchmark / test code, not the agent's
# runtime surface". A finding here is real but lower priority — bump confidence
# down one notch so the free-tier high-confidence gate naturally hides eval
# noise. Keeps the signal:noise ratio high without dropping findings.
_EVAL_PATH_HINTS = (
    "/evaluation/", "/evaluations/", "/eval/", "/evals/",
    "/tests/", "/__tests__/", "/test/", "/spec/", "/specs/", "/__mocks__/",
    "/examples/", "/example/", "/demo/", "/demos/", "/samples/", "/sample/",
    "/benchmarks/", "/benchmark/", "/bench/",
    "/scripts/", "/script/",
    "/docs/", "/doc/",
    "/fixtures/", "/fixture/",
    # Research / training / experimentation surfaces — bursts of subprocess
    # and fs activity that aren't the agent's runtime path.
    "/training/", "/datasets/", "/runs/", "/experiments/",
    "/notebooks/", "/research/",
)

_EVAL_FILENAME_HINTS = (
    ".test.", ".spec.", ".stories.",
    "_test.py", "_spec.py", "_tests.py",
)

_DOWNGRADE: dict[str, str] = {"high": "medium", "medium": "low", "low": "low"}


def _is_eval_path(file: str, root: Path | None = None) -> bool:
    """True if the file lives under an eval/test/example/script directory
    *relative to the scan root*. Using the relative path matters because:
    when we scan our own repo, fixtures may live at `tests/fixtures/foo` —
    we don't want to downgrade findings inside the fixture (the fixture IS
    the scanned project, not a tests/ inside it). Using only the absolute
    path would match `/tests/` from our own filesystem layout.
    """
    if root is not None:
        try:
            rel = Path(file).resolve().relative_to(Path(root).resolve())
            target = "/" + str(rel).lower().replace("\\", "/").lstrip("/")
        except ValueError:
            target = "/" + file.lower().replace("\\", "/").lstrip("/")
    else:
        target = "/" + file.lower().replace("\\", "/").lstrip("/")
    if any(seg in target for seg in _EVAL_PATH_HINTS):
        return True
    name = target.rsplit("/", 1)[-1]
    return any(tok in name for tok in _EVAL_FILENAME_HINTS)


def _downgrade_eval_paths(findings: list[Finding], root: Path | None = None) -> list[Finding]:
    """Lower confidence one step for findings under eval / test / example paths.

    Why: a `subprocess.run` in a benchmarking script is not a runtime risk
    in production — but the scanner can't know that from the call alone.
    The path is the cheap signal that distinguishes "agent runtime code" from
    "research harness". We downgrade rather than drop so Builder users still
    see them; the free-tier gate hides them naturally."""
    for f in findings:
        if _is_eval_path(f.file, root):
            new_conf = _DOWNGRADE.get(f.confidence, f.confidence)
            if new_conf != f.confidence:
                f.confidence = new_conf  # type: ignore[assignment]
                f.extra = {**f.extra, "downgraded_eval_path": True}
    return findings


def _snippet_matches_line(snippet: str, text: str) -> bool:
    """True when the reported `snippet` really appears on the target `text`.

    Self-check invariant: if a detector says "finding at file:L with snippet
    X", then the identifier prefix of X must be on the actual content of
    line L. Catches off-by-one bugs, stale snippets, and files that shifted
    between scan and report — regardless of which detector was wrong.

    Snippet conventions across detectors:
    - Literal:              `subprocess.run(`  →  probe `subprocess.run`
    - With ellipsis:        `stripe.Refund.create(...)`  →  probe `stripe.Refund.create`
    - With synthetic note:  `@app.route  # refund`  →  probe `@app.route`
    - Alias-resolved:       `openai.OpenAI(...)` for real `_OpenAI()`  →
      primary probe fails, fall back to last identifier (`OpenAI`).

    Tolerates whitespace differences (both sides collapsed). Rejects findings
    whose snippet is absent from the line entirely — the classic symptom of
    a line-offset bug.
    """
    if not snippet:
        return True
    # Strip synthetic ` # note` suffix and call-site arguments.
    probe_raw = snippet.split("#", 1)[0].split("(", 1)[0].strip()
    if not probe_raw:
        return True
    probe = "".join(probe_raw.split())
    target = "".join(text.split())
    if probe in target:
        return True
    # Alias-resolved snippets: the scanner may have normalized `_OpenAI(...)`
    # to `openai.OpenAI(...)`. The leading module is fictitious; only the
    # last identifier is real. Require at least 4 chars to avoid false
    # acceptance on trivial names like `run`.
    if "." in probe_raw:
        last = probe_raw.rsplit(".", 1)[-1].strip()
        if len(last) >= 4 and last in target:
            return True
    return False


def _self_check(findings: list[Finding]) -> list[Finding]:
    """Drop findings whose snippet doesn't appear on the reported line.

    This runs regardless of which detector emitted the finding, so even a
    regex with an unintended permissive group can't leak into public output.
    The scanner would rather under-report than tell a visitor
    `plan_tool.py:8 is an AGENT CHOKEPOINT` when line 8 is a comment.

    For .ipynb files we re-extract the synthetic Python that scanners saw,
    not the raw JSON — otherwise every notebook finding would fail the
    snippet check and get dropped.

    The `skills` scanner emits whole-file markers (line=1, snippet=path.name);
    those don't follow the usual "snippet appears on line" contract and we
    pass them through unchanged.
    """
    from .skills import SCANNER as _SKILLS_SCANNER

    clean: list[Finding] = []
    cache: dict[str, list[str] | None] = {}
    for f in findings:
        if f.scanner == _SKILLS_SCANNER:
            clean.append(f)
            continue
        if f.file not in cache:
            try:
                path = Path(f.file)
                if path.suffix == ".ipynb":
                    text = _extract_notebook_python(path)
                else:
                    text = path.read_text(errors="replace")
                cache[f.file] = text.splitlines()
            except (OSError, json.JSONDecodeError):
                cache[f.file] = None
        lines = cache[f.file]
        if lines is None or not (0 <= f.line - 1 < len(lines)):
            continue
        if _snippet_matches_line(f.snippet, lines[f.line - 1]):
            clean.append(f)
    return clean
