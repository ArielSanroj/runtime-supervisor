"""Detect scheduled jobs. Informational only — enforcement for cron/scheduled
tasks is deferred (user must wrap by hand for now). The point of this scanner
is to surface them in the report so the operator knows what's out of scope."""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Finding
from ._utils import config_files, python_files, ts_js_files

_PY_CELERY_BEAT = re.compile(r"beat_schedule\s*=|@periodic_task|@shared_task")
_PY_APSCHEDULER = re.compile(r"BackgroundScheduler\(|add_job\s*\(")
_TS_NODE_CRON = re.compile(r"""\b(?:cron|node-cron)\b|cron\.schedule\s*\(""")
_CRONTAB_LINE = re.compile(r"^\s*[*\d/,\-]+\s+[*\d/,\-]+\s+[*\d/,\-]+\s+[*\d/,\-]+\s+[*\d/,\-]+\s+\S+")
_GHA_SCHEDULE = re.compile(r"^\s*-?\s*cron:\s*['\"]")


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in python_files(root):
        text = path.read_text(errors="ignore")
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
        text = path.read_text(errors="ignore")
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
        text = path.read_text(errors="ignore")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _CRONTAB_LINE.match(line) or _GHA_SCHEDULE.match(line):
                findings.append(Finding(
                    scanner="cron-schedules",
                    file=str(path),
                    line=lineno,
                    snippet=line.strip()[:120],
                    suggested_action_type="other",
                    confidence="high",
                    rationale="Scheduled job in config — supervise the target script/handler manually.",
                    extra={"kind": "crontab-or-gha"},
                ))
    return findings
