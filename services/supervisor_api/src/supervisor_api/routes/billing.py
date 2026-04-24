"""Stripe Checkout subscription flow.

Two endpoints:
  POST /v1/billing/checkout         — public; build a Stripe Checkout Session
                                       and return its URL.
  POST /v1/billing/webhook/stripe   — public; Stripe-signature-verified;
                                       handle subscription lifecycle events
                                       (create user + send magic link on
                                       checkout.session.completed).
"""
from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta

import stripe
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..email import send_magic_link
from ..models import MagicLinkToken, User

log = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/billing", tags=["billing"])

# Magic link tokens are single-use, expire fast (15 min) — narrow the blast
# radius of an email leak or shoulder-surf.
_MAGIC_TTL_MINUTES = 15


class CheckoutRequest(BaseModel):
    email: EmailStr
    return_url: str = Field(..., description="Absolute URL Stripe redirects to after success/cancel.")


class CheckoutResponse(BaseModel):
    url: str


def _stripe_client() -> None:
    settings = get_settings()
    if not settings.billing_enabled:
        raise HTTPException(
            status_code=503,
            detail="billing not configured (STRIPE_SECRET_KEY / STRIPE_PRICE_ID missing)",
        )
    stripe.api_key = settings.stripe_secret_key


@router.post("/checkout", response_model=CheckoutResponse)
def create_checkout(body: CheckoutRequest) -> CheckoutResponse:
    _stripe_client()
    settings = get_settings()
    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            payment_method_types=["card"],
            line_items=[{"price": settings.stripe_price_id, "quantity": 1}],
            customer_email=body.email,
            success_url=f"{body.return_url}?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{body.return_url}?canceled=true",
            allow_promotion_codes=True,
            # Carry the email forward so the webhook can correlate even if
            # Stripe doesn't echo customer_email back.
            metadata={"signup_email": body.email},
            subscription_data={"metadata": {"signup_email": body.email}},
        )
    except stripe.error.StripeError as e:  # type: ignore[attr-defined]
        log.exception("stripe checkout.create failed")
        raise HTTPException(status_code=502, detail=f"stripe error: {e}") from e
    if session.url is None:
        raise HTTPException(status_code=502, detail="stripe returned no checkout URL")
    return CheckoutResponse(url=session.url)


def _issue_magic_link(db: Session, email: str) -> str:
    """Insert a fresh single-use token, return the URL the user clicks."""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + timedelta(minutes=_MAGIC_TTL_MINUTES)
    db.add(MagicLinkToken(token=token, email=email.lower(), expires_at=expires_at))
    db.commit()
    site = get_settings().site_url.rstrip("/")
    return f"{site}/auth/magic-link/{token}"


def _upsert_builder_user(
    db: Session,
    email: str,
    *,
    stripe_customer_id: str,
    stripe_subscription_id: str,
    stripe_subscription_status: str,
) -> User:
    """Create or update a Builder-tier user from a Stripe webhook event."""
    email = email.lower()
    u = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if u is None:
        u = User(
            email=email,
            password_hash=None,  # passwordless — magic link only
            role="ops",
            tier="builder",
            stripe_customer_id=stripe_customer_id,
            stripe_subscription_id=stripe_subscription_id,
            stripe_subscription_status=stripe_subscription_status,
            active=True,
        )
        db.add(u)
    else:
        u.tier = "builder"
        u.stripe_customer_id = stripe_customer_id
        u.stripe_subscription_id = stripe_subscription_id
        u.stripe_subscription_status = stripe_subscription_status
        u.active = True
    db.commit()
    db.refresh(u)
    return u


def _downgrade_user_by_subscription(db: Session, subscription_id: str, status: str) -> None:
    u = db.execute(
        select(User).where(User.stripe_subscription_id == subscription_id)
    ).scalar_one_or_none()
    if u is None:
        log.warning("stripe webhook: subscription %s not linked to any user", subscription_id)
        return
    u.stripe_subscription_status = status
    if status in ("canceled", "incomplete_expired", "unpaid"):
        u.tier = "free"
    db.commit()


@router.post("/webhook/stripe")
async def stripe_webhook(
    request: Request,
    stripe_signature: str | None = Header(default=None, alias="Stripe-Signature"),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    settings = get_settings()
    if not settings.stripe_webhook_secret:
        raise HTTPException(status_code=503, detail="STRIPE_WEBHOOK_SECRET not configured")
    if not stripe_signature:
        raise HTTPException(status_code=400, detail="missing Stripe-Signature header")
    raw = await request.body()
    try:
        event = stripe.Webhook.construct_event(
            payload=raw,
            sig_header=stripe_signature,
            secret=settings.stripe_webhook_secret,
        )
    except (ValueError, stripe.error.SignatureVerificationError) as e:  # type: ignore[attr-defined]
        log.warning("stripe webhook signature failed: %s", e)
        raise HTTPException(status_code=400, detail="invalid stripe signature") from e

    event_type = event["type"]
    data = event["data"]["object"]

    if event_type == "checkout.session.completed":
        email = (data.get("customer_email") or data.get("metadata", {}).get("signup_email") or "").lower()
        if not email:
            log.warning("checkout.session.completed without email — skipping")
            return {"status": "skipped"}
        u = _upsert_builder_user(
            db,
            email,
            stripe_customer_id=data.get("customer") or "",
            stripe_subscription_id=data.get("subscription") or "",
            stripe_subscription_status="active",
        )
        link_url = _issue_magic_link(db, u.email)
        try:
            send_magic_link(u.email, link_url)
        except Exception:
            # Don't 500 to Stripe — they'll retry. The link is in the DB; user
            # can re-request from /auth/magic-link/send.
            log.exception("magic link send failed for %s", u.email)
        return {"status": "ok"}

    if event_type in ("customer.subscription.updated", "customer.subscription.deleted"):
        subscription_id = data.get("id") or ""
        status = data.get("status") or ""
        _downgrade_user_by_subscription(db, subscription_id, status)
        return {"status": "ok"}

    # Unhandled event types ack 200 so Stripe doesn't retry forever.
    log.info("stripe webhook: unhandled event type %s", event_type)
    return {"status": "ignored", "event_type": event_type}
