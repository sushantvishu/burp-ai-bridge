from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from server.knowledge_base import MEMORY_DIR, ensure_storage
from server.settings import OLLAMA_MODEL

RUNTIME_MODEL_OVERRIDE_PATH = MEMORY_DIR / "runtime_model_override.json"


def get_active_ollama_model() -> str:
    override = read_runtime_model_override()
    candidate = str((override or {}).get("active_model") or "").strip()
    return candidate or OLLAMA_MODEL


def read_runtime_model_override() -> dict[str, Any]:
    ensure_storage()
    if not RUNTIME_MODEL_OVERRIDE_PATH.exists():
        return {}
    try:
        payload = json.loads(RUNTIME_MODEL_OVERRIDE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def set_active_ollama_model(model_name: str, *, source: str = "api", actor: str = "") -> dict[str, Any]:
    normalized = (model_name or "").strip()
    if not normalized:
        raise ValueError("A non-empty Ollama model name is required.")

    ensure_storage()
    payload = {
        "active_model": normalized,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "source": (source or "api").strip(),
        "actor": (actor or "").strip(),
    }
    RUNTIME_MODEL_OVERRIDE_PATH.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
    return payload


def clear_active_ollama_model_override() -> None:
    ensure_storage()
    if RUNTIME_MODEL_OVERRIDE_PATH.exists():
        RUNTIME_MODEL_OVERRIDE_PATH.unlink()


def get_runtime_model_override_path() -> Path:
    ensure_storage()
    return RUNTIME_MODEL_OVERRIDE_PATH
