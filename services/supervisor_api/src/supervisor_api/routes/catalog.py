from __future__ import annotations

from fastapi import APIRouter, HTTPException

from .. import registry

router = APIRouter(prefix="/v1", tags=["catalog"])


@router.get("/action-types")
def list_action_types() -> dict[str, list[dict]]:
    return {"action_types": [registry.as_dict(a) for a in registry.REGISTRY]}


@router.get("/action-types/{action_type}")
def get_action_type(action_type: str) -> dict:
    spec = registry.get(action_type)
    if spec is None:
        raise HTTPException(status_code=404, detail=f"unknown action_type: {action_type}")
    return registry.as_dict(spec)
