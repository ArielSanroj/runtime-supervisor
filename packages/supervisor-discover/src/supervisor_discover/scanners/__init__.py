from __future__ import annotations

from pathlib import Path

from ..findings import Finding
from . import (
    calendar_actions,
    cron_schedules,
    db_mutations,
    email_sends,
    fs_shell,
    http_routes,
    llm_calls,
    media_gen,
    messaging,
    payment_calls,
    voice_actions,
)


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
    ):
        findings.extend(module.scan(root))
    return findings
