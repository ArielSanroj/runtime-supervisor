from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth
from ..db import get_db
from ..models import Integration, WebhookDelivery, WebhookSubscription
from ..schemas import (
    WebhookDeliveryOut,
    WebhookSubscriptionCreate,
    WebhookSubscriptionOut,
)

router = APIRouter(
    prefix="/v1/integrations/{integration_id}/webhooks",
    tags=["webhooks"],
    dependencies=[Depends(auth.require_admin)],
)


def _to_out(s: WebhookSubscription) -> WebhookSubscriptionOut:
    return WebhookSubscriptionOut(
        id=s.id, integration_id=s.integration_id, url=s.url,
        events=s.events or [], active=s.active, created_at=s.created_at,
    )


def _guard_integration(db: Session, integration_id: str) -> Integration:
    i = db.get(Integration, integration_id)
    if i is None:
        raise HTTPException(status_code=404, detail="integration not found")
    return i


@router.post("", response_model=WebhookSubscriptionOut, status_code=201)
def create_subscription(
    integration_id: str,
    body: WebhookSubscriptionCreate,
    db: Session = Depends(get_db),
) -> WebhookSubscriptionOut:
    _guard_integration(db, integration_id)
    sub = WebhookSubscription(integration_id=integration_id, url=body.url, events=list(body.events), active=True)
    db.add(sub)
    db.commit()
    db.refresh(sub)
    return _to_out(sub)


@router.get("", response_model=list[WebhookSubscriptionOut])
def list_subscriptions(integration_id: str, db: Session = Depends(get_db)) -> list[WebhookSubscriptionOut]:
    _guard_integration(db, integration_id)
    subs = db.execute(
        select(WebhookSubscription).where(WebhookSubscription.integration_id == integration_id)
    ).scalars().all()
    return [_to_out(s) for s in subs]


@router.delete("/{subscription_id}", status_code=204)
def delete_subscription(integration_id: str, subscription_id: str, db: Session = Depends(get_db)) -> None:
    _guard_integration(db, integration_id)
    sub = db.get(WebhookSubscription, subscription_id)
    if sub is None or sub.integration_id != integration_id:
        raise HTTPException(status_code=404, detail="subscription not found")
    db.delete(sub)
    db.commit()


@router.get("/{subscription_id}/deliveries", response_model=list[WebhookDeliveryOut])
def list_deliveries(
    integration_id: str,
    subscription_id: str,
    db: Session = Depends(get_db),
) -> list[WebhookDeliveryOut]:
    _guard_integration(db, integration_id)
    items = db.execute(
        select(WebhookDelivery)
        .where(WebhookDelivery.subscription_id == subscription_id)
        .order_by(WebhookDelivery.created_at.desc())
        .limit(50)
    ).scalars().all()
    return [
        WebhookDeliveryOut(
            id=d.id, subscription_id=d.subscription_id, event_type=d.event_type,
            status_code=d.status_code, error=d.error, attempts=d.attempts,
            delivered_at=d.delivered_at, created_at=d.created_at,
        )
        for d in items
    ]
