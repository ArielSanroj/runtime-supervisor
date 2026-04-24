"""`/v1/repos` — aggregation endpoints over the `scans` table keyed by
github_url.

There is no `Repo` table: a repo is just every `Scan` row that shares the same
normalized `github_url`. `repo_id = sha256(normalize(url))[:16]` is derivable
without a migration. Once auth lands, the same shape extends to tenant-scoped
repos by adding `tenant_id` to the lookup — additive, no schema break.

Endpoints:
    GET /v1/repos/by-url?github_url=... → overview keyed by URL (no hash math on the client)
    GET /v1/repos/{repo_id}             → overview keyed by id
    GET /v1/repos/{repo_id}/findings    → latest scan's findings, optional filters
    GET /v1/repos/{repo_id}/combos      → detect_combos() over latest scan
    GET /v1/repos/{repo_id}/scans       → history with delta counts
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Scan
from ..schemas import ScanCombo, ScanFinding, UTCDateTime

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/repos", tags=["repos"])


# ---- id derivation ----------------------------------------------------------

def _normalize_github_url(url: str) -> str:
    """Lowercase, strip trailing slash and `.git`. Keeps two URLs that point
    at the same repo (with/without .git, trailing slash, different case)
    collapsing into a single repo_id."""
    u = url.strip().lower()
    if u.endswith("/"):
        u = u[:-1]
    if u.endswith(".git"):
        u = u[:-4]
    return u


def repo_id_for_url(github_url: str) -> str:
    """16-char prefix of sha256(normalized_url). 2^64 space — collisions
    aren't a concern until we're past a trillion repos."""
    norm = _normalize_github_url(github_url)
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]


# ---- response shapes --------------------------------------------------------

class RepoModeCounts(BaseModel):
    """How many high-confidence findings sit in each priority tier for the
    latest scan. Drives the 'risk shape' section in the dashboard overview."""

    money: int = 0
    real_world_actions: int = 0
    customer_data: int = 0
    business_data: int = 0
    llm: int = 0
    general: int = 0


class RepoOverview(BaseModel):
    repo_id: str
    github_url: str
    latest_scan_id: str | None = None
    latest_scan_at: UTCDateTime | None = None
    latest_scan_seconds: float | None = None
    scan_count: int = 0
    total_findings: int = 0
    high_findings: int = 0
    priority_count: int = 0
    critical_combos: int = 0
    risk_shape: RepoModeCounts = Field(default_factory=RepoModeCounts)
    repo_summary: dict[str, Any] | None = None
    # shadow / sample / enforce. Not derivable yet — we don't tag actions
    # with repo_id. Returns `None` until Fase C.
    mode: Literal["shadow", "sample", "enforce"] | None = None


class RepoScanHistoryItem(BaseModel):
    scan_id: str
    ref: str | None
    status: str
    total_findings: int
    priority_count: int
    high_findings: int
    completed_at: UTCDateTime
    # Delta vs the scan that precedes this one (None for the oldest row).
    new_high: int | None = None
    fixed: int | None = None


# ---- helpers ----------------------------------------------------------------

def _scans_for_repo(db: Session, repo_id: str) -> list[Scan]:
    """All scans that map to this repo_id, newest first. We match by
    comparing the hash of every stored repo_url; the DB index on repo_url
    keeps the scan count small per repo so the N hashes are cheap."""
    rows = db.execute(select(Scan).order_by(Scan.created_at.desc())).scalars().all()
    return [r for r in rows if repo_id_for_url(r.repo_url) == repo_id]


def _count_high(findings: list[dict[str, Any]]) -> int:
    return sum(1 for f in findings if f.get("confidence") == "high")


def _count_priority(findings: list[dict[str, Any]]) -> int:
    return sum(1 for f in findings if f.get("tier") and f["tier"] != "general")


def _risk_shape(findings: list[dict[str, Any]]) -> RepoModeCounts:
    """High-confidence finding count by tier."""
    counts: dict[str, int] = {}
    for f in findings:
        if f.get("confidence") != "high":
            continue
        tier = f.get("tier") or "general"
        counts[tier] = counts.get(tier, 0) + 1
    return RepoModeCounts(
        money=counts.get("money", 0),
        real_world_actions=counts.get("real_world_actions", 0),
        customer_data=counts.get("customer_data", 0),
        business_data=counts.get("business_data", 0),
        llm=counts.get("llm", 0),
        general=counts.get("general", 0),
    )


def _build_combos_from_findings(findings: list[dict[str, Any]]) -> list[ScanCombo]:
    """Reconstruct Finding dataclasses from stored JSON and run detect_combos.
    Dict layout matches Finding.to_dict() plus a scanner-added `tier`.
    """
    try:
        from supervisor_discover.combos import detect_combos
        from supervisor_discover.findings import Finding
    except ImportError:
        log.warning("supervisor-discover not available; combos empty")
        return []
    rebuilt: list[Finding] = []
    for raw in findings:
        payload = {k: v for k, v in raw.items() if k in {
            "scanner", "file", "line", "snippet",
            "suggested_action_type", "confidence", "rationale", "extra",
        }}
        try:
            rebuilt.append(Finding(**payload))
        except TypeError:
            continue
    return [
        ScanCombo(
            id=c.id,
            title=c.title,
            severity=c.severity,  # type: ignore[arg-type]
            narrative=c.narrative,
            evidence=list(c.evidence),
            mitigation=c.mitigation,
        )
        for c in detect_combos(rebuilt)
    ]


def _overview_from_scans(repo_id: str, scans: list[Scan]) -> RepoOverview:
    """All scans for a repo (already newest-first). If empty, raise 404 upstream."""
    latest = scans[0]
    findings = latest.findings or []
    combos = _build_combos_from_findings(findings)
    critical_combos = sum(1 for c in combos if c.severity == "critical")
    return RepoOverview(
        repo_id=repo_id,
        github_url=latest.repo_url,
        latest_scan_id=latest.id,
        latest_scan_at=latest.created_at,
        latest_scan_seconds=latest.scan_seconds,
        scan_count=len(scans),
        total_findings=latest.total_findings,
        high_findings=_count_high(findings),
        priority_count=latest.priority_count,
        critical_combos=critical_combos,
        risk_shape=_risk_shape(findings),
        repo_summary=latest.repo_summary or None,
        mode=None,
    )


# ---- routes -----------------------------------------------------------------


@router.get("/by-url", response_model=RepoOverview)
def get_repo_by_url(
    github_url: str = Query(..., min_length=1, max_length=512),
    db: Session = Depends(get_db),
) -> RepoOverview:
    repo_id = repo_id_for_url(github_url)
    scans = _scans_for_repo(db, repo_id)
    if not scans:
        raise HTTPException(status_code=404, detail="no scans found for this repo")
    return _overview_from_scans(repo_id, scans)


@router.get("/{repo_id}", response_model=RepoOverview)
def get_repo(
    repo_id: str,
    db: Session = Depends(get_db),
) -> RepoOverview:
    scans = _scans_for_repo(db, repo_id)
    if not scans:
        raise HTTPException(status_code=404, detail="repo not found")
    return _overview_from_scans(repo_id, scans)


@router.get("/{repo_id}/findings", response_model=list[ScanFinding])
def get_repo_findings(
    repo_id: str,
    tier: str | None = Query(default=None),
    confidence: Literal["low", "medium", "high"] | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
) -> list[ScanFinding]:
    scans = _scans_for_repo(db, repo_id)
    if not scans:
        raise HTTPException(status_code=404, detail="repo not found")
    latest = scans[0]
    out: list[ScanFinding] = []
    for raw in (latest.findings or []):
        if tier is not None and raw.get("tier") != tier:
            continue
        if confidence is not None and raw.get("confidence") != confidence:
            continue
        try:
            out.append(ScanFinding(**raw))
        except Exception:
            continue
        if len(out) >= limit:
            break
    return out


@router.get("/{repo_id}/combos", response_model=list[ScanCombo])
def get_repo_combos(
    repo_id: str,
    db: Session = Depends(get_db),
) -> list[ScanCombo]:
    scans = _scans_for_repo(db, repo_id)
    if not scans:
        raise HTTPException(status_code=404, detail="repo not found")
    return _build_combos_from_findings(scans[0].findings or [])


@router.get("/{repo_id}/scans", response_model=list[RepoScanHistoryItem])
def get_repo_scans(
    repo_id: str,
    db: Session = Depends(get_db),
) -> list[RepoScanHistoryItem]:
    scans = _scans_for_repo(db, repo_id)
    if not scans:
        raise HTTPException(status_code=404, detail="repo not found")
    # Sorted newest-first. Deltas are computed vs the next-older scan.
    history: list[RepoScanHistoryItem] = []
    prev_high_keys: set[tuple[str, int]] | None = None
    for scan in reversed(scans):
        findings = scan.findings or []
        high = _count_high(findings)
        high_keys = {(str(f.get("file")), int(f.get("line", 0))) for f in findings if f.get("confidence") == "high"}
        new_high = None
        fixed = None
        if prev_high_keys is not None:
            new_high = len(high_keys - prev_high_keys)
            fixed = len(prev_high_keys - high_keys)
        history.append(
            RepoScanHistoryItem(
                scan_id=scan.id,
                ref=scan.ref,
                status=scan.status,
                total_findings=scan.total_findings,
                priority_count=scan.priority_count,
                high_findings=high,
                completed_at=scan.created_at,
                new_high=new_high,
                fixed=fixed,
            )
        )
        prev_high_keys = high_keys
    history.reverse()  # newest first
    return history
