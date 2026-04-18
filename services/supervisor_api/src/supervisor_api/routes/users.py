"""User accounts + basic login (Phase X scaffold).

Password auth for the control-center UI, roles (admin/compliance/ops/auditor)
returned in a session JWT. Full SSO (Clerk/Auth0/OIDC) and per-role UI
gating are deferred — this scaffold gives backend the shape so future PRs
can swap auth backends behind the same User/role model.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth
from ..db import get_db
from ..models import User

router = APIRouter(prefix="/v1", tags=["users"])


def _hash_password(password: str, *, salt: str | None = None) -> str:
    """PBKDF2-SHA256 with a random salt. Format: salt$hex_hash."""
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}${h.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, expected_hex = stored.split("$", 1)
    except ValueError:
        return False
    candidate = _hash_password(password, salt=salt).split("$", 1)[1]
    return hmac.compare_digest(candidate, expected_hex)


_VALID_ROLES = {"admin", "compliance", "ops", "auditor"}


class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=256)
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(default="ops")
    tenant_id: str | None = None


class UserOut(BaseModel):
    id: str
    email: str
    role: str
    tenant_id: str | None
    active: bool
    created_at: datetime


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    token: str
    user: UserOut


# ---- Admin: manage users -----------------------------------------------------

@router.post("/users", response_model=UserOut, status_code=201, dependencies=[Depends(auth.require_admin)])
def create_user(body: UserCreate, db: Session = Depends(get_db)) -> UserOut:
    if body.role not in _VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {sorted(_VALID_ROLES)}")
    u = User(
        email=body.email,
        password_hash=_hash_password(body.password),
        role=body.role,
        tenant_id=body.tenant_id,
        active=True,
    )
    db.add(u)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"user conflict: {e}") from e
    db.refresh(u)
    return UserOut(id=u.id, email=u.email, role=u.role, tenant_id=u.tenant_id,
                   active=u.active, created_at=u.created_at)


@router.get("/users", response_model=list[UserOut], dependencies=[Depends(auth.require_admin)])
def list_users(db: Session = Depends(get_db)) -> list[UserOut]:
    rows = db.execute(select(User).order_by(User.created_at.desc())).scalars().all()
    return [
        UserOut(id=u.id, email=u.email, role=u.role, tenant_id=u.tenant_id,
                active=u.active, created_at=u.created_at)
        for u in rows
    ]


# ---- Public: login -----------------------------------------------------------

@router.post("/auth/login", response_model=LoginResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    u = db.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
    if u is None or not u.active or not _verify_password(body.password, u.password_hash):
        raise HTTPException(status_code=401, detail="invalid email or password")

    # Signed session JWT; the same HS256 signer used for integrations.
    # `kind=session` distinguishes from integration tokens.
    claims = {
        "sub": u.id,
        "email": u.email,
        "role": u.role,
        "kind": "session",
        "tenant_id": u.tenant_id,
        "exp": int((datetime.now(UTC) + timedelta(hours=8)).timestamp()),
    }
    # Sign with the app-wide webhook secret for simplicity; a dedicated session
    # secret is recommended for prod.
    from ..config import get_settings

    token = auth.sign_jwt(claims, get_settings().webhook_secret)
    return LoginResponse(
        token=token,
        user=UserOut(id=u.id, email=u.email, role=u.role, tenant_id=u.tenant_id,
                     active=u.active, created_at=u.created_at),
    )
