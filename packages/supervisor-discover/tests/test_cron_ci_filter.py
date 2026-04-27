"""CI cron entries (GitHub Actions, CircleCI, GitLab CI) downgrade to
`confidence=low` so they don't headline as wrap targets.

Background: scanning the langchain repo emitted GitHub Actions schedules
(`.github/workflows/refresh_model_profiles.yml:12`,
`integration_tests.yml:51`) as `confidence=high` cron findings. Those
runners fire on GitHub's infra and execute checks/build steps — there
is no deployed agent to gate. Reporting them as wrap targets is noise.

The fix keeps the finding (still useful for inventory) but flags
`extra.is_ci=True` and downgrades to `low` so the public UI's confidence
gate filters it out of "Best place to wrap first".
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.findings import Finding
from supervisor_discover.scanners import cron_schedules


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def test_github_actions_cron_marked_ci(tmp_path: Path):
    _write(tmp_path, ".github/workflows/integration_tests.yml", """
on:
  schedule:
    - cron: "0 13 * * *"
""")
    findings = cron_schedules.scan(tmp_path)
    assert findings, "should still emit the cron finding for inventory"
    f = findings[0]
    assert f.confidence == "low"
    assert (f.extra or {}).get("is_ci") is True


def test_root_crontab_stays_high(tmp_path: Path):
    """Regression guard: a literal crontab at the repo root is a real
    production schedule and must keep `confidence=high`."""
    _write(tmp_path, "crontab", "0 8 * * * /opt/agent/run.sh\n")
    findings = cron_schedules.scan(tmp_path)
    assert findings
    f = findings[0]
    assert f.confidence == "high"
    assert not (f.extra or {}).get("is_ci")
