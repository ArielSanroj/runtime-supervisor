"""Product discovery (SUPERLOOP.md §2) — enumerate the business units to loop over.

Two kinds:
  - repos       → one per distinct scanned repo_url (the unit OBSERVE reads from Scan)
  - supervisors → one per live action type in the registry (refund, payment, ...)
"""
from __future__ import annotations

import hashlib

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..models import Scan
from ..registry import REGISTRY
from .domain.entities import Producto


def _repo_id(repo_url: str) -> str:
    return "repo:" + hashlib.sha256(repo_url.encode()).hexdigest()[:16]


def _repo_name(repo_url: str) -> str:
    cleaned = repo_url.rstrip("/").removesuffix(".git")
    parts = cleaned.split("/")
    return "/".join(parts[-2:]) if len(parts) >= 2 else cleaned


def discover_repos(db: Session, tenant_id: str | None) -> list[Producto]:
    rows = db.execute(
        select(Scan.repo_url)
        .where(or_(Scan.tenant_id == tenant_id, Scan.tenant_id.is_(None)))
        .where(Scan.status == "done")
        .group_by(Scan.repo_url)
    ).scalars().all()
    return [
        Producto(
            producto_id=_repo_id(url),
            nombre=_repo_name(url),
            kind="repo",
            source_ref=url,
            tenant_id=tenant_id,
            expected_business_outcome={"tipo": "risk_reduction", "metrica_norte": "priority_findings"},
        )
        for url in rows
    ]


def discover_supervisors(db: Session, tenant_id: str | None) -> list[Producto]:
    return [
        Producto(
            producto_id=f"supervisor:{spec.id}",
            nombre=spec.title,
            kind="supervisor",
            source_ref=spec.id,
            tenant_id=tenant_id,
            expected_business_outcome={"tipo": "risk_reduction", "metrica_norte": "review_backlog"},
        )
        for spec in REGISTRY
        if spec.status == "live"
    ]


def discover(db: Session, tenant_id: str | None, scope: str = "all") -> list[Producto]:
    out: list[Producto] = []
    if scope in ("all", "repos"):
        out += discover_repos(db, tenant_id)
    if scope in ("all", "supervisors"):
        out += discover_supervisors(db, tenant_id)
    return out
