"""Detect scheduled jobs. Informational only — enforcement for cron/scheduled
tasks is deferred (user must wrap by hand for now). The point of this scanner
is to surface them in the report so the operator knows what's out of scope."""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Finding
from ._utils import config_files, python_files, safe_read, ts_js_files

_PY_CELERY_BEAT = re.compile(r"beat_schedule\s*=|@periodic_task|@shared_task")
_PY_APSCHEDULER = re.compile(r"BackgroundScheduler\(|add_job\s*\(")
_TS_NODE_CRON = re.compile(r"""\b(?:cron|node-cron)\b|cron\.schedule\s*\(""")
_CRONTAB_LINE = re.compile(r"^\s*[*\d/,\-]+\s+[*\d/,\-]+\s+[*\d/,\-]+\s+[*\d/,\-]+\s+[*\d/,\-]+\s+\S+")
_GHA_SCHEDULE = re.compile(r"^\s*-?\s*cron:\s*['\"]")

# Path fragments that indicate a CI/CD pipeline definition rather than a
# production-deployed scheduler. A `cron:` entry under `.github/workflows/`
# fires on GitHub Actions runners, not on the repo's deployed agent — the
# operator can't wrap a `@supervised` decorator around a YAML step. Keep the
# finding (still useful for inventory) but downgrade confidence so it doesn't
# headline as a wrap target. The `config_files` walker only yields paths
# under `.github/workflows/` plus root-level `crontab*` and
# `docker-compose*`, so the prod regression case is the root crontab.
_CI_PATH_FRAGMENTS = (
    "/.github/workflows/", "/.github/actions/",
)


def _is_ci_path(file: str) -> bool:
    lower = "/" + file.lower().replace("\\", "/").lstrip("/")
    return any(frag in lower for frag in _CI_PATH_FRAGMENTS)


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in python_files(root):
        text = safe_read(path)
        if text is None:
            continue
        for pattern, label in ((_PY_CELERY_BEAT, "celery-beat"), (_PY_APSCHEDULER, "apscheduler")):
            for m in pattern.finditer(text):
                line = text[: m.start()].count("\n") + 1
                findings.append(Finding(
                    scanner="cron-schedules",
                    file=str(path),
                    line=line,
                    snippet=m.group(0),
                    suggested_action_type="other",
                    confidence="medium",
                    rationale=f"{label} scheduled task. Enforcement for scheduled tasks is deferred — "
                              "wrap each scheduled callable manually with @supervised.",
                    extra={"scheduler": label},
                ))
    for path in ts_js_files(root):
        text = safe_read(path)
        if text is None:
            continue
        for m in _TS_NODE_CRON.finditer(text):
            line = text[: m.start()].count("\n") + 1
            findings.append(Finding(
                scanner="cron-schedules",
                file=str(path),
                line=line,
                snippet=m.group(0),
                suggested_action_type="other",
                confidence="low",
                rationale="node-cron reference. Wrap scheduled handlers manually with supervised().",
                extra={"scheduler": "node-cron"},
            ))
    for path in config_files(root):
        text = safe_read(path)
        if text is None:
            continue
        is_ci = _is_ci_path(str(path))
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _CRONTAB_LINE.match(line) or _GHA_SCHEDULE.match(line):
                if is_ci:
                    rationale = (
                        "CI cron — runs on GitHub Actions / CircleCI / GitLab "
                        "runners, not on the deployed agent. No wrap needed; "
                        "kept here for inventory."
                    )
                    extra = {"kind": "crontab-or-gha", "is_ci": True}
                    confidence = "low"
                else:
                    rationale = (
                        "Scheduled job in config — supervise the target "
                        "script/handler manually."
                    )
                    extra = {"kind": "crontab-or-gha"}
                    confidence = "high"
                findings.append(Finding(
                    scanner="cron-schedules",
                    file=str(path),
                    line=lineno,
                    snippet=line.strip()[:120],
                    suggested_action_type="other",
                    confidence=confidence,
                    rationale=rationale,
                    extra=extra,
                ))
    return findings
