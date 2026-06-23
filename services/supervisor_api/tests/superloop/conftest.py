from __future__ import annotations

from datetime import UTC, datetime

import pytest

DEV_TENANT = "default-dev-tenant"  # what auth.require_tenant_id returns in REQUIRE_AUTH=false


def _seed_repo(repo_url: str, priority_now: int, priority_prev: int) -> None:
    """Two scans for one repo so the source can compute a trend."""
    from supervisor_api.db import SessionLocal
    from supervisor_api.models import Scan

    with SessionLocal() as s:
        s.add(Scan(
            repo_url=repo_url, tenant_id=DEV_TENANT, status="done",
            repo_summary={}, findings=[], total_findings=priority_prev + 2,
            priority_count=priority_prev,
            created_at=datetime(2026, 6, 1, tzinfo=UTC),
        ))
        s.add(Scan(
            repo_url=repo_url, tenant_id=DEV_TENANT, status="done",
            repo_summary={}, findings=[], total_findings=priority_now + 2,
            priority_count=priority_now,
            created_at=datetime(2026, 6, 20, tzinfo=UTC),
        ))
        s.commit()


def _seed_supervisor(action_type: str, n_review_shadow: int, with_inactive_policy: bool) -> None:
    """Shadow review decisions (would-block) + an inactive policy to promote."""
    from supervisor_api.db import SessionLocal
    from supervisor_api.models import Action, Decision, PolicyRecord

    with SessionLocal() as s:
        for _ in range(n_review_shadow):
            a = Action(action_type=action_type, status="received", payload={},
                       shadow=True, tenant_id=DEV_TENANT)
            s.add(a)
            s.flush()
            s.add(Decision(action_id=a.id, decision="review", policy_hits=[],
                           risk_score=60, risk_breakdown=[], policy_version="x@v1",
                           tenant_id=DEV_TENANT))
        if with_inactive_policy:
            s.add(PolicyRecord(action_type=action_type, name=f"{action_type} base",
                               version=1, yaml_source="rules: []", is_active=False,
                               tenant_id=DEV_TENANT))
        s.commit()


@pytest.fixture()
def seed(client):
    """Returns a callable to seed fixtures; depends on `client` so the schema +
    default tenant already exist."""
    class _Seeder:
        seed_repo = staticmethod(_seed_repo)
        seed_supervisor = staticmethod(_seed_supervisor)
    return _Seeder()
