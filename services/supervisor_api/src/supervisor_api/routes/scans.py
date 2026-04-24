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

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request

from .. import storage
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


def _run_scan_sync(scan_id: str, url: str, ref: str | None) -> None:
    started = time.perf_counter()
    base = _load(scan_id) or {}
    base.update({"status": "scanning"})
    _persist(scan_id, base)

    with tempfile.TemporaryDirectory(prefix=f"scan-{scan_id}-") as tmp:
        tmp_path = Path(tmp)

        clone_cmd = [
            "git", "clone",
            "--depth", "1",
            "--single-branch",
            "--no-tags",
        ]
        if ref:
            clone_cmd += ["-b", ref]
        clone_cmd += [url, str(tmp_path)]

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
            from supervisor_discover.classifier import tier_of, validate
            from supervisor_discover.scanners import scan_all
            from supervisor_discover.summary import build_summary
        except ImportError as e:
            _finalize_error(scan_id, base, f"supervisor-discover not installed on server: {e}", started)
            return

        try:
            findings = validate(scan_all(tmp_path))
            repo_summary = build_summary(findings).to_dict()
        except Exception as e:
            log.exception("scan.scanner_crash scan_id=%s", scan_id)
            _finalize_error(scan_id, base, f"scanner error: {type(e).__name__}: {e}"[:500], started)
            return

    # File paths are absolute to the temp dir — strip so the UI shows relative paths.
    tmp_prefix = str(tmp_path) + "/"
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
    base.update({
        "status": "done",
        "repo_summary": repo_summary,
        "findings": out_findings,
        "findings_truncated": len(findings) > _MAX_FINDINGS_RETURNED,
        "elapsed_ms": elapsed_ms,
        "completed_at": datetime.now(UTC).isoformat(),
    })
    _persist(scan_id, base)
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
    log.warning("scan.error scan_id=%s reason=%s", scan_id, reason)
