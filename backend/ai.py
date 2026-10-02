import os
import json
import re

import httpx
from db import db

# Models available through AI gateway / Anthropic (Claude + Qwen use the /v1/messages endpoint)
ALLOWED_MODELS = [
    "claude-sonnet-5", "claude-opus-5", "claude-haiku-4-5",
    "claude-sonnet-4-6", "claude-opus-4-8", "qwen3.7-max", "qwen3.7-plus",
]
# Approx USD per 1M tokens (input, output) — used only to ESTIMATE spend in-app.
PRICING = {
    "claude-sonnet-5": (2.0, 10.0),
    "claude-opus-5": (5.0, 25.0),
    "claude-haiku-4-5": (1.0, 5.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-opus-4-8": (5.0, 25.0),
    "qwen3.7-max": (1.2, 6.0),
    "qwen3.7-plus": (0.4, 1.6),
}

_MODEL_OVERRIDE = None


def backend() -> str:
    """LLM backend: 'gateway' (default), 'anthropic'/'claude', or 'ollama'."""
    b = os.environ.get("LLM_BACKEND", "gateway").strip().lower()
    return "anthropic" if b == "claude" else b


def set_model_override(m):
    global _MODEL_OVERRIDE
    _MODEL_OVERRIDE = m or None


def current_model() -> str:
    if _MODEL_OVERRIDE:
        return _MODEL_OVERRIDE
    b = backend()
    if b == "gateway":
        return os.environ.get("LLM_MODEL", "claude-sonnet-5")
    if b == "ollama":
        return os.environ.get("OLLAMA_MODEL", "llama3.1")
    return os.environ.get("CLAUDE_MODEL", "claude-sonnet-5")


def key_present() -> bool:
    b = backend()
    if b == "gateway":
        return bool(os.environ.get("LLM_API_KEY"))
    if b == "anthropic":
        return bool(os.environ.get("ANTHROPIC_API_KEY"))
    return True  # ollama needs no key


# ---------------------------------------------------------------- Anthropic-compatible client
_anthropic = None


def _anthropic_client():
    global _anthropic
    if _anthropic is None:
        from anthropic import AsyncAnthropic  # lazy
        if backend() == "gateway":
            key = os.environ.get("LLM_API_KEY", "")
            if not key:
                raise RuntimeError("LLM_API_KEY is not set (required when LLM_BACKEND=gateway)")
            base = os.environ.get("LLM_BASE_URL", "https://api.deepseek.com/anthropic")
            _anthropic = AsyncAnthropic(api_key=key, base_url=base)
        else:
            key = os.environ.get("ANTHROPIC_API_KEY", "")
            if not key:
                raise RuntimeError("ANTHROPIC_API_KEY is not set (required when LLM_BACKEND=anthropic)")
            _anthropic = AsyncAnthropic(api_key=key)
    return _anthropic


async def _record_usage(model, usage):
    try:
        pin, pout = PRICING.get(model, (0.0, 0.0))
        ti = getattr(usage, "input_tokens", 0) or 0
        to = getattr(usage, "output_tokens", 0) or 0
        cost = ti / 1e6 * pin + to / 1e6 * pout
        await db.ai_usage.update_one({"_id": "totals"},
                                     {"$inc": {"total_input": ti, "total_output": to, "total_cost": cost, "calls": 1}},
                                     upsert=True)
        return cost
    except Exception:
        return 0.0


def _guess_media(b64: str) -> str:
    if b64.startswith("/9j/"):
        return "image/jpeg"
    if b64.startswith("iVBOR"):
        return "image/png"
    if b64.startswith("R0lGOD"):
        return "image/gif"
    if b64.startswith("UklGR"):
        return "image/webp"
    return "image/jpeg"


def _claude_text(message) -> str:
    return "".join(getattr(b, "text", "") for b in message.content if getattr(b, "type", "") == "text")


async def _claude_complete_ex(system_message: str, user_text: str, images=None):
    client = _anthropic_client()
    model = current_model()
    if images:
        content = [
            {"type": "image", "source": {"type": "base64", "media_type": _guess_media(images[0]), "data": images[0]}},
            {"type": "text", "text": user_text},
        ]
    else:
        content = user_text
    msg = await client.messages.create(model=model, max_tokens=4096, system=system_message,
                                       messages=[{"role": "user", "content": content}])
    cost = await _record_usage(model, msg.usage)
    return _claude_text(msg), (cost or 0.0)


async def _claude_complete(system_message: str, user_text: str, images=None) -> str:
    text, _ = await _claude_complete_ex(system_message, user_text, images=images)
    return text


async def _claude_stream(system_message: str, user_text: str):
    client = _anthropic_client()
    model = current_model()
    async with client.messages.stream(model=model, max_tokens=4096, system=system_message,
                                       messages=[{"role": "user", "content": user_text}]) as s:
        async for text in s.text_stream:
            yield text
        final = await s.get_final_message()
    await _record_usage(model, final.usage)


# ---------------------------------------------------------------- Ollama (local)
def _ollama_url() -> str:
    return os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")


def _ollama_model() -> str:
    return os.environ.get("OLLAMA_MODEL", "llama3.1")


def _ollama_vision_model() -> str:
    return os.environ.get("OLLAMA_VISION_MODEL", "llava")


async def _ollama_chat(system_message: str, user_text: str, model: str, images=None) -> str:
    user_msg = {"role": "user", "content": user_text}
    if images:
        user_msg["images"] = images
    payload = {"model": model, "stream": False,
               "messages": [{"role": "system", "content": system_message}, user_msg]}
    async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=10.0)) as client:
        r = await client.post(f"{_ollama_url()}/api/chat", json=payload)
        r.raise_for_status()
        return (r.json().get("message") or {}).get("content", "") or ""


async def _ollama_stream(system_message: str, user_text: str, model: str):
    payload = {"model": model, "stream": True,
               "messages": [{"role": "system", "content": system_message},
                            {"role": "user", "content": user_text}]}
    async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=10.0)) as client:
        async with client.stream("POST", f"{_ollama_url()}/api/chat", json=payload) as r:
            r.raise_for_status()
            async for line in r.aiter_lines():
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                chunk = (obj.get("message") or {}).get("content")
                if chunk:
                    yield chunk
                if obj.get("done"):
                    break


# ---------------------------------------------------------------- unified API
async def complete(session_id: str, system_message: str, user_text: str) -> str:
    b = backend()
    if b in ("anthropic", "gateway"):
        return await _claude_complete(system_message, user_text)
    if b == "ollama":
        return await _ollama_chat(system_message, user_text, _ollama_model())
    raise RuntimeError(f"Unknown LLM_BACKEND '{b}'")


async def complete_ex(session_id: str, system_message: str, user_text: str):
    """Like complete() but returns (text, estimated_cost_usd)."""
    b = backend()
    if b in ("anthropic", "gateway"):
        return await _claude_complete_ex(system_message, user_text)
    if b == "ollama":
        txt = await _ollama_chat(system_message, user_text, _ollama_model())
        return txt, 0.0
    raise RuntimeError(f"Unknown LLM_BACKEND '{b}'")


async def stream(session_id: str, system_message: str, user_text: str):
    b = backend()
    if b in ("anthropic", "gateway"):
        async for chunk in _claude_stream(system_message, user_text):
            yield chunk
        return
    if b == "ollama":
        async for chunk in _ollama_stream(system_message, user_text, _ollama_model()):
            yield chunk
        return
    raise RuntimeError(f"Unknown LLM_BACKEND '{b}'")


async def analyze_image(session_id: str, system_message: str, user_text: str, image_base64: str) -> str:
    b = backend()
    if b in ("anthropic", "gateway"):
        return await _claude_complete(system_message, user_text, images=[image_base64])
    if b == "ollama":
        return await _ollama_chat(system_message, user_text, _ollama_vision_model(), images=[image_base64])
    raise RuntimeError(f"Unknown LLM_BACKEND '{b}'")


def parse_json(text: str):
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1:
        text = text[start:end + 1]
    return json.loads(text)
