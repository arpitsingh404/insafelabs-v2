from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import ai
from db import db

router = APIRouter(prefix="/ai", tags=["ai"])


class ModelBody(BaseModel):
    model: str


@router.get("/status")
async def status():
    usage = await db.ai_usage.find_one({"_id": "totals"}) or {}
    return {
        "backend": ai.backend(),
        "model": ai.current_model(),
        "models": ai.ALLOWED_MODELS,
        "key_present": ai.key_present(),
        "usage": {
            "total_cost": round(float(usage.get("total_cost", 0.0)), 4),
            "input_tokens": int(usage.get("total_input", 0)),
            "output_tokens": int(usage.get("total_output", 0)),
            "calls": int(usage.get("calls", 0)),
        },
    }


@router.post("/model")
async def set_model(body: ModelBody):
    if body.model not in ai.ALLOWED_MODELS:
        raise HTTPException(status_code=400, detail="Unsupported model")
    ai.set_model_override(body.model)
    await db.ai_state.update_one({"_id": "model"}, {"$set": {"value": body.model}}, upsert=True)
    return {"model": body.model}


@router.post("/usage/reset")
async def reset_usage():
    await db.ai_usage.delete_one({"_id": "totals"})
    return {"ok": True}
