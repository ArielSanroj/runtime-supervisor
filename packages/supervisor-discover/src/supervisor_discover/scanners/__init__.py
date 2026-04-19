from __future__ import annotations

from pathlib import Path

from ..findings import Finding
from . import cron_schedules, db_mutations, http_routes, llm_calls, payment_calls


def scan_all(root: Path) -> list[Finding]:
    """Run every scanner against the repo rooted at `root`."""
    findings: list[Finding] = []
    for module in (http_routes, llm_calls, payment_calls, db_mutations, cron_schedules):
        findings.extend(module.scan(root))
    return findings
