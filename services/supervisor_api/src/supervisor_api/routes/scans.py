"""Public `/v1/scans` endpoint: clone a GitHub repo, run supervisor-discover,
return findings. Powers the vibe-coder-facing scan webpage.

No JWT — the endpoint is intentionally public so visitors can self-serve.
Guards: regex-restricted URLs (github.com only), per-IP rate limit,
concurrency cap, shallow clone with timeout, ephemeral tmpdir, findings
truncation, persisted to LocalStorage-style blob (not DB) since scans are
throwaway.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import subprocess
import tempfile
import time
from collections import defaultdict, deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import storage
from ..db import SessionLocal, get_db
from ..models import Scan
from ..schemas import ScanRequest, ScanResponse

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["scans"])

# ---- tunables ----------------------------------------------------------------

_GITHUB_RE = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+(?:\.git)?/?$")
_RATE_WINDOW_SECONDS = 60.0
_RATE_MAX_PER_WINDOW = 3
_CLONE_TIMEOUT_SECONDS = 90
_MAX_CONCURRENT_SCANS = 3
_MAX_FINDINGS_RETURNED = 500
_MAX_REPO_BYTES = 500 * 1024 * 1024  # 500 MB

_TIER_RANK = {
    "money": 0,
    "real_world_actions": 1,
    "customer_data": 2,
    "business_data": 3,
    "llm": 4,
    "general": 5,
}
_CONF_RANK = {"high": 0, "medium": 1, "low": 2}

# ---- in-memory state (per-process, OK for single-worker dev/MVP) -------------

_rate_buckets: dict[str, deque[float]] = defaultdict(
    lambda: deque(maxlen=_RATE_MAX_PER_WINDOW)
)
_scan_sem = asyncio.Semaphore(_MAX_CONCURRENT_SCANS)


def _rate_limit(ip: str) -> None:
    now = time.monotonic()
    bucket = _rate_buckets[ip]
    while bucket and now - bucket[0] > _RATE_WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= _RATE_MAX_PER_WINDOW:
        raise HTTPException(status_code=429, detail="rate limit exceeded (3 scans/min per IP)")
    bucket.append(now)


def _key(scan_id: str) -> str:
    return f"scans/{scan_id}.json"


def _persist(scan_id: str, payload: dict[str, Any]) -> None:
    storage.get_backend().put(_key(scan_id), json.dumps(payload, default=str).encode())


def _load(scan_id: str) -> dict[str, Any] | None:
    try:
        body = storage.get_backend().get(_key(scan_id))
    except (FileNotFoundError, KeyError):
        return None
    return json.loads(body)


def _priority_count(findings: list[dict[str, Any]]) -> int:
    """Findings in any tier other than `general` count as priority."""
    return sum(1 for f in findings if f.get("tier") and f["tier"] != "general")


def _save_scan_row(
    scan_id: str,
    repo_url: str,
    ref: str | None,
    repo_summary: dict[str, Any],
    findings: list[dict[str, Any]],
    elapsed_ms: int,
    *,
    tenant_id: str | None = None,
    status: str = "done",
    error: str | None = None,
) -> None:
    """Persist the scan to the `scans` table.

    Background task — creates its own Session because the request's Session
    is long gone by the time _run_scan_sync runs. Failure here is best-effort:
    the blob copy still exists and the user sees their result.
    """
    db: Session = SessionLocal()
    try:
        row = Scan(
            id=scan_id,
            tenant_id=tenant_id,
            repo_url=repo_url,
            ref=ref,
            repo_summary=repo_summary,
            findings=findings,
            total_findings=len(findings),
            priority_count=_priority_count(findings),
            scan_seconds=elapsed_ms / 1000.0,
            status=status,
            error=error,
        )
        db.add(row)
        db.commit()
    except Exception:
        db.rollback()
        log.exception("scan.persist_failed scan_id=%s", scan_id)
    finally:
        db.close()


def _directory_bytes(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        if p.is_file() and not p.is_symlink():
            with contextlib.suppress(OSError):
                total += p.stat().st_size
    return total


def _preview_rank(finding: Any, tier: str) -> tuple[int, int, int, str, int]:
    """Sort public preview worst-first before truncating.

    Large repos can have hundreds of informational HTTP routes. If we slice in
    scanner order, the web preview hides the exact findings users pay to fix:
    money, real-world actions, customer data, LLM calls, and high-confidence
    chokepoints.
    """
    non_other = 0 if finding.suggested_action_type != "other" else 1
    return (
        _TIER_RANK.get(tier, 99),
        non_other,
        _CONF_RANK.get(finding.confidence, 9),
        finding.file,
        finding.line,
    )


# ---- routes ------------------------------------------------------------------


@router.post("/scans", response_model=ScanResponse, status_code=202)
async def create_scan(
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
) -> ScanResponse:
    ip = request.client.host if request.client else "anon"
    _rate_limit(ip)

    url = body.github_url.strip()
    if not _GITHUB_RE.match(url):
        raise HTTPException(
            status_code=400,
            detail="only public https://github.com/owner/repo URLs supported in MVP",
        )

    scan_id = str(uuid4())
    now = datetime.now(UTC).isoformat()
    ref = body.ref or None

    _persist(scan_id, {
        "scan_id": scan_id,
        "status": "queued",
        "github_url": url,
        "ref": ref,
        "created_at": now,
    })

    log.info("scan.queued scan_id=%s url=%s ip=%s", scan_id, url, ip)
    background_tasks.add_task(_run_scan, scan_id, url, ref)

    return ScanResponse(
        scan_id=scan_id,
        status="queued",
        github_url=url,
        ref=ref,
        created_at=datetime.now(UTC),
    )


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str) -> ScanResponse:
    data = _load(scan_id)
    if data is None:
        raise HTTPException(status_code=404, detail="scan not found")
    # Dates round-trip as ISO strings — Pydantic re-parses via UTCDateTime.
    return ScanResponse(**data)


class ScanSummary(BaseModel):
    """Lightweight row for the dashboard `/findings` list. No full findings
    payload — the detail page fetches that separately via /v1/scans/{id}."""

    id: str
    repo_url: str
    ref: str | None
    total_findings: int
    priority_count: int
    scan_seconds: float | None
    status: str
    created_at: datetime


@router.get("/scans", response_model=list[ScanSummary])
def list_scans(
    tenant_id: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> list[ScanSummary]:
    """List past scans, newest first. Optional `tenant_id` filter so the
    dashboard only shows the logged-in user's runs. Anonymous landing
    scans (`tenant_id IS NULL`) are never returned unless the caller
    explicitly asks for them (omit the filter → all scans). MVP is
    permissive; once the dashboard is strictly tenant-gated we'll tighten."""
    stmt = select(Scan).order_by(Scan.created_at.desc()).limit(limit)
    if tenant_id is not None:
        stmt = stmt.where(Scan.tenant_id == tenant_id)
    rows = db.execute(stmt).scalars().all()
    return [
        ScanSummary(
            id=r.id,
            repo_url=r.repo_url,
            ref=r.ref,
            total_findings=r.total_findings,
            priority_count=r.priority_count,
            scan_seconds=r.scan_seconds,
            status=r.status,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.get("/scans/{scan_id}/bundle.zip")
def download_scan_bundle(scan_id: str, db: Session = Depends(get_db)):
    """Download the full `runtime-supervisor/` bundle as a ZIP.

    The Builder export: SUMMARY.md + report.md + ROLLOUT.md + combos/ +
    policies/ + stubs/ + findings.json. Same shape the CLI emits.

    Reuses `supervisor_discover.generator.generate()` so the bundle stays
    in lockstep with what `pipx install supervisor-discover` produces —
    no drift between web export and local CLI.
    """
    import io
    import tempfile
    import zipfile
    from pathlib import Path as _Path

    from fastapi.responses import StreamingResponse

    from supervisor_discover.findings import Finding
    from supervisor_discover.generator import generate

    row = db.get(Scan, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if row.status != "done":
        raise HTTPException(
            status_code=409,
            detail=f"scan is {row.status}, bundle only available for status=done",
        )

    # Rehydrate Finding dataclasses from the persisted JSON list. Use the
    # canonical fields the dataclass takes; ignore extras the storage may
    # have folded in.
    findings_objs: list[Finding] = []
    for f in row.findings or []:
        try:
            findings_objs.append(
                Finding(
                    scanner=f.get("scanner", "unknown"),
                    file=f.get("file", ""),
                    line=int(f.get("line", 0)),
                    snippet=f.get("snippet", ""),
                    suggested_action_type=f.get("suggested_action_type", "general"),
                    confidence=f.get("confidence", "low"),
                    rationale=f.get("rationale", ""),
                    extra=f.get("extra") or {},
                )
            )
        except Exception:
            log.exception("scan.bundle: skipping malformed finding")

    # Use a tempdir as working surface; generate writes the canonical
    # tree, we zip the result in-memory and stream back.
    with tempfile.TemporaryDirectory(prefix=f"bundle-{scan_id}-") as tmp:
        out = _Path(tmp) / "runtime-supervisor"
        try:
            generate(findings_objs, out, repo_root=None)
        except Exception as e:
            log.exception("scan.bundle: generate() failed for %s", scan_id)
            raise HTTPException(status_code=500, detail=f"bundle generation failed: {e}") from e

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in out.rglob("*"):
                if path.is_file():
                    zf.write(path, arcname=path.relative_to(_Path(tmp)))
        buf.seek(0)

    repo_slug = (row.repo_url or "").rstrip("/").split("/")[-1] or "repo"
    filename = f"runtime-supervisor-{repo_slug}-{scan_id[:8]}.zip"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="application/zip",
        headers={"content-disposition": f'attachment; filename="{filename}"'},
    )


# ---- worker ------------------------------------------------------------------


async def _run_scan(scan_id: str, url: str, ref: str | None) -> None:
    """BackgroundTask entry. Runs under a concurrency semaphore so we never
    have more than N shallow clones in flight at once."""
    try:
        async with _scan_sem:
            await asyncio.to_thread(_run_scan_sync, scan_id, url, ref)
    except Exception as e:  # last-ditch: persist the failure, don't swallow it
        log.exception("scan.crash scan_id=%s", scan_id)
        _persist(scan_id, {
            "scan_id": scan_id,
            "status": "error",
            "github_url": url,
            "ref": ref,
            "error": f"worker crashed: {type(e).__name__}: {e}"[:500],
            "completed_at": datetime.now(UTC).isoformat(),
        })


def _resolve_clone_url(public_url: str) -> str:
    """If the repo lives under a Vibefixing GitHub App install, swap in
    an installation token so private repos clone successfully. Falls
    back to the original public URL otherwise (anonymous git clone).

    URL pattern: https://github.com/{owner}/{repo}{.git?}
    Match logic: any active GitHubInstallation whose repo_full_names
    contains "{owner}/{repo}" or "*" (= "All repositories").
    """
    import re

    from .. import github_api
    from ..db import SessionLocal
    from ..models import GitHubInstallation

    m = re.match(r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", public_url)
    if not m:
        return public_url

    full_name = f"{m.group(1)}/{m.group(2)}"

    try:
        with SessionLocal() as db:
            row = (
                db.query(GitHubInstallation)
                .filter(GitHubInstallation.active.is_(True))
                .all()
            )
            installation_id: int | None = None
            for r in row:
                names = r.repo_full_names or []
                if full_name in names or "*" in names:
                    installation_id = r.installation_id
                    break

        if installation_id is None:
            return public_url

        # Mint installation-scoped token (1h lifetime, fresh per scan).
        token = github_api.get_installation_token(installation_id)
        return f"https://x-access-token:{token.token}@github.com/{full_name}.git"
    except Exception:
        # If anything fails (App not configured, GitHub API hiccup),
        # fall back to public URL — better to fail at clone with a
        # honest error than to fail here silently.
        log.exception("could not resolve install token for %s; falling back to public URL", full_name)
        return public_url


def _run_scan_sync(scan_id: str, url: str, ref: str | None) -> None:
    started = time.perf_counter()
    base = _load(scan_id) or {}
    base.update({"status": "scanning"})
    _persist(scan_id, base)

    with tempfile.TemporaryDirectory(prefix=f"scan-{scan_id}-") as tmp:
        tmp_path = Path(tmp)

        clone_url = _resolve_clone_url(url)

        clone_cmd = [
            "git", "clone",
            "--depth", "1",
            "--single-branch",
            "--no-tags",
        ]
        if ref:
            clone_cmd += ["-b", ref]
        clone_cmd += [clone_url, str(tmp_path)]

        try:
            subprocess.run(
                clone_cmd,
                timeout=_CLONE_TIMEOUT_SECONDS,
                check=True,
                capture_output=True,
            )
        except subprocess.TimeoutExpired:
            _finalize_error(scan_id, base, f"clone timeout (>{_CLONE_TIMEOUT_SECONDS}s) — repo too large or network issue", started)
            return
        except subprocess.CalledProcessError as e:
            stderr = (e.stderr or b"").decode(errors="replace").strip()[:300]
            _finalize_error(scan_id, base, f"git clone failed: {stderr or 'unknown error'}", started)
            return
        except FileNotFoundError:
            _finalize_error(scan_id, base, "git binary not found on server", started)
            return

        repo_bytes = _directory_bytes(tmp_path)
        if repo_bytes > _MAX_REPO_BYTES:
            _finalize_error(
                scan_id,
                base,
                f"repo too large ({repo_bytes // 1024 // 1024} MB > {_MAX_REPO_BYTES // 1024 // 1024} MB cap)",
                started,
            )
            return

        try:
            from dataclasses import replace as dc_replace

            from supervisor_discover.classifier import tier_of, validate
            from supervisor_discover.combos import detect_combos
            from supervisor_discover.scanners import apply_default_hidden, scan_all
            from supervisor_discover.start_here import build_start_here
            from supervisor_discover.summary import build_summary
        except ImportError as e:
            _finalize_error(scan_id, base, f"supervisor-discover not installed on server: {e}", started)
            return

        try:
            all_findings = validate(scan_all(tmp_path))
            findings, hidden_counts = apply_default_hidden(all_findings, tmp_path)
            summary = build_summary(findings, hidden_counts=hidden_counts)
            start_here = build_start_here(summary, findings)
            summary = dc_replace(summary, start_here=start_here)
            repo_summary = summary.to_dict()
            detected_combos = detect_combos(findings)
        except Exception as e:
            log.exception("scan.scanner_crash scan_id=%s", scan_id)
            _finalize_error(scan_id, base, f"scanner error: {type(e).__name__}: {e}"[:500], started)
            return

    # File paths are absolute to the temp dir — strip so the UI shows relative paths.
    tmp_prefix = str(tmp_path) + "/"
    # Python's start_here._short_path keeps the last 3 path segments — for a
    # file under the tmp clone that emits `<tmp_basename>/<dir>/<file>`, e.g.
    # `scan-XXX-rpfvqf3h/python/ts_executor.py`. The full prefix strip below
    # misses this because `_short_path` already removed the `/tmp/` head, so
    # we ALSO strip the tmp basename + slash to clean those embedded strings.
    tmp_basename_prefix = tmp_path.name + "/"

    def _clean(s: str) -> str:
        return s.replace(tmp_prefix, "").replace(tmp_basename_prefix, "")

    # Also strip from start_here.top_wrap_targets so the UI doesn't leak
    # `/tmp/.../<repo>/...` into the "open this file" links.
    sh_dict = repo_summary.get("start_here") or {}
    for tgt in sh_dict.get("top_wrap_targets") or []:
        if isinstance(tgt.get("file"), str):
            tgt["file"] = _clean(tgt["file"])
    # Also strip absolute tmp paths from the Risk cards' confirmed_in_code text.
    for risk in sh_dict.get("top_risks") or []:
        if isinstance(risk.get("confirmed_in_code"), str):
            risk["confirmed_in_code"] = _clean(risk["confirmed_in_code"])
    if isinstance(sh_dict.get("do_this_now"), str):
        sh_dict["do_this_now"] = _clean(sh_dict["do_this_now"])
    # And the agent_chokepoints we expose at summary level.
    for cp in repo_summary.get("agent_chokepoints") or []:
        if isinstance(cp.get("file"), str):
            cp["file"] = _clean(cp["file"])

    ranked_findings = sorted(
        ((f, tier_of(f)) for f in findings),
        key=lambda item: _preview_rank(item[0], item[1]),
    )

    out_findings: list[dict[str, Any]] = []
    for f, tier in ranked_findings[:_MAX_FINDINGS_RETURNED]:
        d = f.to_dict()
        if d["file"].startswith(tmp_prefix):
            d["file"] = d["file"][len(tmp_prefix):]
        d["tier"] = tier
        out_findings.append(d)

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    out_combos = [
        {
            "id": c.id,
            "title": c.title,
            "severity": c.severity,
            "narrative": c.narrative,
            "evidence": list(c.evidence),
            "mitigation": c.mitigation,
        }
        for c in detected_combos
    ]
    base.update({
        "status": "done",
        "repo_summary": repo_summary,
        "findings": out_findings,
        "findings_truncated": len(findings) > _MAX_FINDINGS_RETURNED,
        "combos": out_combos,
        "elapsed_ms": elapsed_ms,
        "completed_at": datetime.now(UTC).isoformat(),
    })
    _persist(scan_id, base)
    _save_scan_row(
        scan_id=scan_id,
        repo_url=base.get("github_url", ""),
        ref=base.get("ref"),
        repo_summary=repo_summary,
        findings=out_findings,
        elapsed_ms=elapsed_ms,
        status="done",
    )
    log.info(
        "scan.done scan_id=%s findings=%d truncated=%s elapsed_ms=%d",
        scan_id, len(out_findings), len(findings) > _MAX_FINDINGS_RETURNED, elapsed_ms,
    )


def _finalize_error(scan_id: str, base: dict[str, Any], reason: str, started: float) -> None:
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    base.update({
        "status": "error",
        "error": reason,
        "elapsed_ms": elapsed_ms,
        "completed_at": datetime.now(UTC).isoformat(),
    })
    _persist(scan_id, base)
    _save_scan_row(
        scan_id=scan_id,
        repo_url=base.get("github_url", ""),
        ref=base.get("ref"),
        repo_summary={},
        findings=[],
        elapsed_ms=elapsed_ms,
        status="error",
        error=reason[:1000],
    )
    log.warning("scan.error scan_id=%s reason=%s", scan_id, reason)
