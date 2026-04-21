from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

# `datetime.UTC` is Python 3.11+. Alias for 3.10 compatibility so the
# client can run from user repos on older Pythons (Clio is on 3.10).
UTC = timezone.utc
from typing import Any


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sign_hs256(claims: dict[str, Any], secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(claims, separators=(",", ":"), default=str).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def build_token(app_id: str, scopes: list[str], secret: str, ttl_seconds: int = 300) -> str:
    now = datetime.now(UTC)
    return sign_hs256(
        {
            "sub": app_id,
            "scopes": scopes,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        },
        secret,
    )
