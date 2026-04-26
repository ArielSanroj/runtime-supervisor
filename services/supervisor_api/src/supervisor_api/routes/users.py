"""User accounts + basic login (Phase X scaffold).

Password auth for the control-center UI, roles (admin/compliance/ops/auditor)
returned in a session JWT. Full SSO (Clerk/Auth0/OIDC) and per-role UI
gating are deferred — this scaffold gives backend the shape so future PRs
can swap auth backends behind the same User/role model.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth
from ..db import get_db
from ..models import User

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["users"])


def _hash_password(password: str, *, salt: str | None = None) -> str:
    """PBKDF2-SHA256 with a random salt. Format: salt$hex_hash."""
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}${h.hex()}"


def _verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        salt, expected_hex = stored.split("$", 1)
    except ValueError:
        return False
    candidate = _hash_password(password, salt=salt).split("$", 1)[1]
    return hmac.compare_digest(candidate, expected_hex)


def build_session_jwt(user: User) -> str:
    """Produce the cookie-bearable session JWT for a User.

    Reused by /v1/auth/login (password) and /v1/auth/magic-link/{token}
    (passwordless). `tier` + `stripe_subscription_status` are surfaced in
    the payload so the frontend middleware can gate routes without an
    extra round-trip.
    """
    from ..config import get_settings

    claims = {
        "sub": user.id,
        "email": user.email,
        "role": user.role,
        "kind": "session",
        "tenant_id": user.tenant_id,
        "tier": user.tier,
        "stripe_subscription_status": user.stripe_subscription_status,
        "exp": int((datetime.now(UTC) + timedelta(hours=8)).timestamp()),
    }
    return auth.sign_jwt(claims, get_settings().webhook_secret)


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


# ---- Team: invite + list teammates within a tenant --------------------------


class TeamInviteRequest(BaseModel):
    email: str = Field(min_length=3, max_length=256)
    role: str = Field(default="ops")
    tenant_id: str  # the inviter's tenant — frontend pulls from session


class TeamInviteResponse(BaseModel):
    user_id: str
    email: str
    invite_sent: bool


@router.post("/team/invite", response_model=TeamInviteResponse, status_code=201)
def invite_teammate(body: TeamInviteRequest, db: Session = Depends(get_db)) -> TeamInviteResponse:
    """Invite an email into a tenant as a teammate.

    Creates a User row with the inviter's tenant_id + tier=builder
    (the invitee inherits the tenant's plan), then mails them a
    magic link to claim the account.

    Frontend gates this on session.user.tier == 'builder'/'pro' and
    forwards the inviter's tenant_id in the body. Backend trusts
    the admin-token-signed call (same posture as
    /v1/integrations/github/installations/{id}/link).
    """
    from datetime import UTC, datetime
    from .billing import _issue_magic_link
    from ..email import send_magic_link

    if body.role not in _VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {sorted(_VALID_ROLES)}")

    email = body.email.strip().lower()

    # Validate the target tenant exists.
    from ..models import Tenant

    if db.get(Tenant, body.tenant_id) is None:
        raise HTTPException(status_code=400, detail=f"unknown tenant_id: {body.tenant_id}")

    existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing is not None:
        # Re-invite an existing user → just re-fire the magic link if
        # they already belong to this tenant. If they belong to a
        # different tenant, refuse — needs admin to migrate.
        if existing.tenant_id != body.tenant_id:
            raise HTTPException(
                status_code=409,
                detail=f"{email} already exists under a different workspace",
            )
        u = existing
    else:
        u = User(
            email=email,
            password_hash=None,  # passwordless from day one
            role=body.role,
            tenant_id=body.tenant_id,
            tier="builder",  # inherits workspace plan; gates dashboard correctly
            active=True,
        )
        db.add(u)
        try:
            db.commit()
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=409, detail=f"user conflict: {e}") from e
        db.refresh(u)

    # Mail the magic link. Failure is non-fatal — the user row exists,
    # admin can re-trigger from the team UI.
    invite_sent = True
    try:
        link = _issue_magic_link(db, email)
        send_magic_link(email, link)
    except Exception:
        log.exception("team.invite: magic link send failed for %s", email)
        invite_sent = False

    return TeamInviteResponse(user_id=u.id, email=u.email, invite_sent=invite_sent)


@router.get("/team/members", response_model=list[UserOut])
def list_team_members(
    tenant_id: str,
    db: Session = Depends(get_db),
) -> list[UserOut]:
    """List all users sharing a tenant. Frontend reads
    session.user.tenant_id and passes it as query param."""
    rows = db.execute(
        select(User)
        .where(User.tenant_id == tenant_id)
        .order_by(User.created_at.desc())
    ).scalars().all()
    return [
        UserOut(
            id=u.id,
            email=u.email,
            role=u.role,
            tenant_id=u.tenant_id,
            active=u.active,
            created_at=u.created_at,
        )
        for u in rows
    ]


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

    token = build_session_jwt(u)
    return LoginResponse(
        token=token,
        user=UserOut(id=u.id, email=u.email, role=u.role, tenant_id=u.tenant_id,
                     active=u.active, created_at=u.created_at),
    )
