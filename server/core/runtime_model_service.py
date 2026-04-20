from __future__ import annotations

import re
import subprocess
from typing import Any

import requests

from server.core.model_routing_service import choose_ollama_model_for_request
from server.profiles import list_profiles
from server.core.runtime_model_override_service import (
    clear_active_ollama_model_override,
    get_active_ollama_model,
    read_runtime_model_override,
    set_active_ollama_model,
)
from server.providers.model_execution_service import candidate_ollama_text_urls
from server.settings import (
    MODEL_PROVIDER_ORDER,
    MODEL_ROUTING_DEEP_MIN_SIGNAL_COUNT,
    MODEL_ROUTING_DEEP_SCORE_THRESHOLD,
    MODEL_ROUTING_FAST_SCORE_THRESHOLD,
    MODEL_SCHEDULER_SEQUENTIAL_ONLY,
    OLLAMA_CODE_MODEL,
    OLLAMA_DEEP_MODEL,
    OLLAMA_FAST_MODEL,
    OLLAMA_TIMEOUT_SECONDS,
    OLLAMA_URL,
)


def get_runtime_model_options() -> dict[str, Any]:
    active_model = get_active_ollama_model()
    override = read_runtime_model_override()
    installed_models = discover_installed_ollama_models()
    installed_names = [item["name"] for item in installed_models]
    switch_targets = {
        "active": active_model,
        "fast": _resolve_configured_or_fallback(OLLAMA_FAST_MODEL, installed_names, role="fast"),
        "deep": _resolve_configured_or_fallback(OLLAMA_DEEP_MODEL, installed_names, role="deep"),
        "code": _resolve_configured_or_fallback(OLLAMA_CODE_MODEL, installed_names, role="code"),
    }
    notes = [
        "Use the exact model tag shown here when switching the AI Bridge model in Burp or the local env file.",
        "The bridge executes Ollama requests with the active model shown here. Use the runtime model selection endpoint or the Burp settings panel to switch it without restarting the server.",
        "Model scheduling is sequential-only by default: one provider path and one local model per request.",
        "Prefer the active MCP-first provider order and switch models only when you want a deeper or faster local pass.",
    ]
    return {
        "configured_url": OLLAMA_URL,
        "current_model": active_model,
        "installed_models": installed_models,
        "detected_model_names": installed_names,
        "switch_targets": switch_targets,
        "manual_override": {
            "active": bool(str((override or {}).get("active_model") or "").strip()),
            "model": str((override or {}).get("active_model") or "").strip(),
            "source": str((override or {}).get("source") or "").strip(),
            "actor": str((override or {}).get("actor") or "").strip(),
            "updated_at": str((override or {}).get("updated_at") or "").strip(),
        },
        "scheduler_policy": scheduler_policy_snapshot(),
        "notes": notes,
    }


def list_runtime_profiles(*, installed_names: list[str] | None = None) -> list[dict[str, Any]]:
    names = list(installed_names or [item["name"] for item in discover_installed_ollama_models()])
    profiles = []
    for profile in list_profiles():
        resolved_model, available, reason = _resolve_profile_model(profile, names)
        enriched = dict(profile)
        enriched["resolved_model"] = resolved_model
        enriched["model_available"] = available
        enriched["switch_value"] = resolved_model
        enriched["availability_reason"] = reason
        profiles.append(enriched)
    return profiles


def select_runtime_model(model_name: str, *, source: str = "api", actor: str = "") -> dict[str, Any]:
    normalized = (model_name or "").strip()
    if not normalized:
        raise ValueError("A non-empty Ollama model name is required.")
    installed = discover_installed_ollama_models()
    installed_names = [item["name"] for item in installed]
    if normalized not in installed_names:
        available = ", ".join(installed_names[:12]) or "<none detected>"
        raise ValueError(f"The model '{normalized}' is not in the current Ollama model list. Available: {available}")
    set_active_ollama_model(normalized, source=source, actor=actor)
    return get_runtime_model_options()


def clear_runtime_model_selection() -> dict[str, Any]:
    clear_active_ollama_model_override()
    return get_runtime_model_options()


def scheduler_policy_snapshot() -> dict[str, Any]:
    return {
        "sequential_only": bool(MODEL_SCHEDULER_SEQUENTIAL_ONLY),
        "provider_order": list(MODEL_PROVIDER_ORDER),
        "routing": {
            "fast_score_threshold": int(MODEL_ROUTING_FAST_SCORE_THRESHOLD or 0),
            "deep_score_threshold": int(MODEL_ROUTING_DEEP_SCORE_THRESHOLD or 1),
            "deep_min_signals": int(MODEL_ROUTING_DEEP_MIN_SIGNAL_COUNT or 1),
            "deep_requires_scanner_context": True,
            "deep_requires_observed_evidence": True,
            "deep_allows_scanner_followup_context": True,
            "deep_allows_investigation_notebook_context": True,
            "fast_request_types": ["proxy", "repeater", "intruder", "unknown"],
        },
    }


def preview_route_for_payload(payload, *, profile_name: str = "", rule_context: dict | None = None, fallback: dict | None = None) -> dict[str, Any]:
    return choose_ollama_model_for_request(
        payload,
        profile_name=profile_name,
        rule_context=rule_context or {},
        fallback=fallback or {},
    )


def discover_installed_ollama_models() -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for item in _discover_from_ollama_tags():
        _merge_model_entry(merged, item)
    for item in _discover_from_ollama_list():
        _merge_model_entry(merged, item)

    for entry in merged.values():
        entry["current"] = entry["name"] == get_active_ollama_model()
        entry["role_hints"] = _model_role_hints(entry["name"])
        entry["profile_matches"] = _profile_matches(entry["name"])

    items = list(merged.values())
    items.sort(key=_model_sort_key)
    return items


def _discover_from_ollama_tags() -> list[dict[str, Any]]:
    candidate_urls = candidate_ollama_text_urls()
    tag_urls = _ollama_tag_probe_urls(candidate_urls)
    discovered: list[dict[str, Any]] = []
    for tag_url in tag_urls:
        try:
            response = requests.get(tag_url, timeout=min(max(1, OLLAMA_TIMEOUT_SECONDS), 5))
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, ValueError):
            continue
        for item in payload.get("models") or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            size_value = item.get("size")
            size_display = _format_size_bytes(size_value)
            discovered.append(
                {
                    "name": name,
                    "size": size_display,
                    "source": "ollama-tags",
                    "family": _model_family(name),
                }
            )
    return discovered


def _discover_from_ollama_list() -> list[dict[str, Any]]:
    try:
        completed = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    if completed.returncode != 0:
        return []

    discovered: list[dict[str, Any]] = []
    lines = [line.rstrip() for line in completed.stdout.splitlines() if line.strip()]
    for line in lines[1:]:
        parts = re.split(r"\s{2,}", line.strip())
        if not parts:
            continue
        name = parts[0].strip()
        if not name or name.lower() == "name":
            continue
        discovered.append(
            {
                "name": name,
                "size": parts[2].strip() if len(parts) > 2 else "",
                "source": "ollama-list",
                "family": _model_family(name),
            }
        )
    return discovered


def _merge_model_entry(merged: dict[str, dict[str, Any]], item: dict[str, Any]) -> None:
    name = str(item.get("name") or "").strip()
    if not name:
        return
    existing = merged.get(name)
    if not existing:
        merged[name] = {
            "name": name,
            "size": str(item.get("size") or "").strip(),
            "source": str(item.get("source") or "").strip(),
            "family": str(item.get("family") or _model_family(name)).strip(),
        }
        return
    if item.get("size") and not existing.get("size"):
        existing["size"] = str(item.get("size") or "").strip()
    sources = {source for source in [existing.get("source"), item.get("source")] if source}
    existing["source"] = "+".join(sorted(sources))


def _resolve_profile_model(profile: dict[str, Any], installed_names: list[str]) -> tuple[str, bool, str]:
    recommended = str(profile.get("recommended_model") or "").strip()
    if recommended and recommended in installed_names:
        return recommended, True, "The profile's preferred model is installed locally."

    fallback = _fallback_for_profile(profile, installed_names)
    if fallback:
        wanted = recommended or "a matching local model"
        return fallback, True, f"{wanted} is not installed, so the bridge recommends the closest available local match."
    return recommended or get_active_ollama_model(), False, "No closer installed model was detected, so this profile remains advisory until you switch Ollama models."


def _fallback_for_profile(profile: dict[str, Any], installed_names: list[str]) -> str:
    name = str(profile.get("name") or "").strip().lower()
    best_for = str(profile.get("best_for") or "").strip().lower()
    if "coder" in name or "code" in best_for:
        return _first_matching(installed_names, lambda value: "coder" in value.lower()) or get_active_ollama_model()
    if "low-resource" in name or "fast triage" in best_for:
        return _smallest_model(installed_names) or get_active_ollama_model()
    if "deep" in name or "deeper" in best_for:
        return _largest_reasonable_model(installed_names) or get_active_ollama_model()
    if "mcp-grounded" in name:
        return _first_matching(installed_names, lambda value: value.lower().startswith("llama")) or get_active_ollama_model()
    return get_active_ollama_model()


def _resolve_configured_or_fallback(configured: str, installed_names: list[str], *, role: str) -> str:
    candidate = (configured or "").strip()
    if candidate and candidate in installed_names:
        return candidate
    if role == "fast":
        return _smallest_model(installed_names) or get_active_ollama_model()
    if role == "deep":
        return _largest_reasonable_model(installed_names) or get_active_ollama_model()
    if role == "code":
        return _first_matching(installed_names, lambda value: "coder" in value.lower()) or get_active_ollama_model()
    return get_active_ollama_model()


def _profile_matches(model_name: str) -> list[str]:
    lowered = model_name.lower()
    matches = []
    params = _extract_param_count(model_name)
    if params and params <= 3.5:
        matches.append("low-resource-local")
    if lowered.startswith("llama"):
        matches.append("mcp-grounded-llama32")
    if (params or 0) >= 6.5 or "latest" in lowered:
        matches.append("deep-escalation-local-8b")
    if not matches:
        matches.append("mcp-grounded-llama32")
    return matches


def _model_role_hints(model_name: str) -> list[str]:
    lowered = model_name.lower()
    hints = ["general triage"]
    if "coder" in lowered:
        hints.append("bridge/code maintenance")
    params = _extract_param_count(model_name)
    if params and params <= 3.5:
        hints.append("fast CPU-bound analysis")
    if (params and params >= 6.5) or "latest" in lowered:
        hints.append("deeper escalation/reporting")
    if lowered.startswith("llama"):
        hints.append("balanced reasoning with MCP grounding")
    return hints[:4]


def _first_matching(items: list[str], predicate) -> str:
    for item in items:
        if predicate(item):
            return item
    return ""


def _smallest_model(items: list[str]) -> str:
    ranked = sorted(items, key=lambda item: (_extract_param_count(item) or 999.0, item))
    return ranked[0] if ranked else ""


def _largest_reasonable_model(items: list[str]) -> str:
    ranked = sorted(items, key=lambda item: (_extract_param_count(item) or (8.0 if "latest" in item.lower() else -1.0), item), reverse=True)
    return ranked[0] if ranked else ""


def _extract_param_count(model_name: str) -> float | None:
    match = re.search(r":(\d+(?:\.\d+)?)b$", model_name.strip().lower())
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def _model_family(model_name: str) -> str:
    name = (model_name or "").strip()
    if ":" in name:
        return name.split(":", 1)[0]
    return name


def _format_size_bytes(size_value: Any) -> str:
    try:
        size_number = int(size_value)
    except (TypeError, ValueError):
        return ""
    gib = size_number / (1024 ** 3)
    if gib >= 1:
        return f"{gib:.1f} GB"
    mib = size_number / (1024 ** 2)
    return f"{mib:.0f} MB"


def _ollama_tag_probe_urls(candidate_urls: list[str]) -> list[str]:
    probe_urls: list[str] = []
    for url in candidate_urls:
        normalized = (url or "").rstrip("/")
        if normalized.endswith("/api/generate"):
            base = normalized[:-len("/api/generate")]
        elif normalized.endswith("/api/chat"):
            base = normalized[:-len("/api/chat")]
        else:
            base = normalized
        probe_url = f"{base}/api/tags" if base else ""
        if probe_url and probe_url not in probe_urls:
            probe_urls.append(probe_url)
    return probe_urls


def _model_sort_key(item: dict[str, Any]) -> tuple[int, float, str]:
    params = _extract_param_count(item.get("name") or "") or (8.0 if "latest" in str(item.get("name") or "").lower() else 0.0)
    return (0 if item.get("current") else 1, -params, item.get("name") or "")
