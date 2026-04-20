from __future__ import annotations

from typing import Any

from server.core.runtime_model_override_service import get_active_ollama_model
from server.settings import OLLAMA_CODE_MODEL, OLLAMA_DEEP_MODEL, OLLAMA_FAST_MODEL, OLLAMA_MODEL


def build_model_strategy(profile: dict | None = None) -> dict[str, Any]:
    selected_profile = profile or {}
    profile_name = str(selected_profile.get("name") or "mcp-grounded-llama32")
    recommended_model = str(selected_profile.get("recommended_model") or OLLAMA_MODEL)
    best_for = str(selected_profile.get("best_for") or "MCP-grounded local Burp triage")
    active_model = get_active_ollama_model()

    notes = [
        f"Active model: {active_model}.",
        f"Profile recommendation: {recommended_model} for {best_for}.",
        f"Fast triage option: {OLLAMA_FAST_MODEL}.",
        f"Deep escalation/reporting option: {OLLAMA_DEEP_MODEL}.",
        f"Code/config maintenance option: {OLLAMA_CODE_MODEL}.",
    ]
    if ":7b" in active_model.lower():
        notes.append("The active model is in the deeper local tier, so it should be used for stronger escalation wording and final reporting passes.")
    elif active_model == OLLAMA_FAST_MODEL:
        notes.append("The active model is in the fast triage tier, so rely more heavily on MCP, KB, guidance DB, and local review examples for discipline.")
    else:
        notes.append("Use Burp MCP, local guidance DB, review dataset, and response-history learning to compensate for small-model limits.")

    return {
        "profile": profile_name,
        "active_model": active_model,
        "recommended_model": recommended_model,
        "fast_model": OLLAMA_FAST_MODEL,
        "deep_model": OLLAMA_DEEP_MODEL,
        "code_model": OLLAMA_CODE_MODEL,
        "best_for": best_for,
        "notes": notes[:6],
    }
