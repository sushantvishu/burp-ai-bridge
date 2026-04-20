import json

import requests

from server.core.model_routing_service import choose_ollama_model_for_request
from server.mcp_client import MCPCallResult, MCPError, MCPServerConfig, call_mcp_tool
from server.core.runtime_model_override_service import get_active_ollama_model
from server.settings import (
    MCP_ENABLED,
    MCP_PROTOCOL_VERSION,
    MCP_SERVER_COMMAND,
    MCP_SERVER_URL,
    MCP_TIMEOUT_SECONDS,
    MCP_TOOL_NAME,
    MCP_TRANSPORT,
    MCP_WORKING_DIRECTORY,
    MODEL_PROVIDER_ORDER,
    OLLAMA_NUM_CTX,
    OLLAMA_NUM_PREDICT,
    OLLAMA_TIMEOUT_SECONDS,
    OLLAMA_URL,
)

MODEL_RESPONSE_FIELDS = (
    "analysis",
    "primary_next_action",
    "request_plan",
    "potential_vulnerabilities",
    "planner",
    "nuclei_tags",
    "seclists_path",
    "questions_for_user",
    "source_links",
)
MODEL_REQUIRED_FIELDS = ("analysis", "primary_next_action", "request_plan", "potential_vulnerabilities", "questions_for_user")
PLANNER_REQUIRED_FIELDS = ("vuln_type", "confidence", "parameters", "attack_plan", "next_action", "priority")
PLANNER_PRIORITY_VALUES = {"low", "medium", "high", "critical"}
def candidate_ollama_text_urls() -> list[str]:
    configured = (OLLAMA_URL or "").strip()
    if not configured:
        return []

    candidates = [configured]
    trimmed = configured.rstrip("/")
    if trimmed.endswith("/api/generate"):
        base = trimmed[:-len("/api/generate")]
        candidates.append(base + "/api/chat")
    elif trimmed.endswith("/api/chat"):
        base = trimmed[:-len("/api/chat")]
        candidates.append(base + "/api/generate")
    elif trimmed.startswith("http://") or trimmed.startswith("https://"):
        candidates.append(trimmed + "/api/generate")
        candidates.append(trimmed + "/api/chat")

    deduped: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in deduped:
            deduped.append(candidate)
    return deduped


def ollama_text_response(prompt: str, response_format: str | None = None, model_name: str = "") -> tuple[str, str]:
    active_model = (model_name or "").strip() or get_active_ollama_model()
    options: dict[str, int] = {}
    if OLLAMA_NUM_CTX > 0:
        options["num_ctx"] = OLLAMA_NUM_CTX
    if OLLAMA_NUM_PREDICT > 0:
        options["num_predict"] = OLLAMA_NUM_PREDICT
    last_http_error: requests.exceptions.HTTPError | None = None
    for url in candidate_ollama_text_urls():
        try:
            if url.endswith("/api/chat"):
                payload = {
                    "model": active_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                }
            else:
                payload = {
                    "model": active_model,
                    "prompt": prompt,
                    "stream": False,
                }
            if response_format:
                payload["format"] = response_format
            if options:
                payload["options"] = options

            response = requests.post(url, json=payload, timeout=OLLAMA_TIMEOUT_SECONDS)
            response.raise_for_status()
            result = response.json()
            if url.endswith("/api/chat"):
                content = ((result.get("message") or {}).get("content") or "").strip()
            else:
                content = (result.get("response") or "").strip()
            return content, url
        except requests.exceptions.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                last_http_error = exc
                continue
            raise
    if last_http_error is not None:
        raise last_http_error
    raise requests.exceptions.RequestException(f"No usable Ollama endpoint candidates were available from {OLLAMA_URL}.")


def format_ollama_request_error(exc: requests.exceptions.RequestException) -> str:
    if isinstance(exc, requests.exceptions.HTTPError) and exc.response is not None and exc.response.status_code == 404:
        return (
            "Ollama returned HTTP 404 for the configured API endpoint. "
            "Verify that Ollama is running and that OLLAMA_URL points to a valid endpoint such as "
            "`http://127.0.0.1:11434/api/generate` or `/api/chat`."
        )
    if exc.response is not None:
        return f"Ollama request failed with HTTP {exc.response.status_code}."
    return f"Ollama request failed: {exc}"


def configured_model_providers() -> list[str]:
    providers: list[str] = []
    for provider in MODEL_PROVIDER_ORDER or ("mcp",):
        normalized = (provider or "").strip().lower()
        if normalized == "mcp" and MCP_ENABLED:
            providers.append("mcp")
    if "mcp" not in providers and MCP_ENABLED:
        providers.append("mcp")
    return providers


def _clean_string_list(values, limit: int = 6) -> list[str]:
    if not isinstance(values, list):
        return []
    cleaned: list[str] = []
    for item in values:
        if item is None:
            continue
        text = str(item).strip()
        if not text:
            continue
        cleaned.append(text)
        if len(cleaned) >= limit:
            break
    return cleaned


def _coerce_confidence(value) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return None
    if numeric > 1.0 and numeric <= 100.0:
        numeric = numeric / 100.0
    if numeric < 0.0 or numeric > 1.0:
        return None
    return round(numeric, 2)


def _infer_vuln_type(candidate: dict) -> str:
    values = candidate.get("potential_vulnerabilities")
    if isinstance(values, list):
        for entry in values:
            text = str(entry or "").strip()
            if not text:
                continue
            if text.startswith("[") and "]" in text:
                return text[1:text.find("]")].strip().lower() or "general"
            first_token = text.split()[0].strip("[]():,.;").lower()
            if first_token:
                return first_token
    return "general"


def _extract_parameters_from_plan(request_plan: list[str]) -> list[str]:
    for step in request_plan:
        if ":" not in step:
            continue
        key, value = step.split(":", 1)
        if "target parameter" not in key.lower():
            continue
        chunk = value.strip()
        if " in " in chunk:
            chunk = chunk.split(" in ", 1)[0].strip()
        params = [part.strip(" `") for part in chunk.split(",") if part.strip()]
        return params[:4]
    return []


def _priority_for_vuln(vuln_type: str) -> str:
    mapping = {
        "access-control": "high",
        "idor": "high",
        "bola": "high",
        "ssrf": "high",
        "ssti": "high",
        "authentication": "high",
        "path-traversal": "high",
        "sqli": "high",
        "xss": "medium",
        "graphql": "medium",
    }
    return mapping.get((vuln_type or "").strip().lower(), "medium")


def derive_planner_candidate(candidate: dict) -> dict:
    if not isinstance(candidate, dict):
        return {}
    request_plan = _clean_string_list(candidate.get("request_plan"), limit=6)
    if not request_plan:
        return {}

    vuln_type = _infer_vuln_type(candidate)
    parameters = _extract_parameters_from_plan(request_plan)
    primary_next_action = str(candidate.get("primary_next_action") or "").strip()
    if not primary_next_action:
        primary_next_action = request_plan[0]
    confidence = _coerce_confidence(candidate.get("confidence"))
    if confidence is None:
        confidence = 0.61

    return {
        "vuln_type": vuln_type,
        "confidence": confidence,
        "parameters": parameters,
        "attack_plan": request_plan[:5],
        "next_action": primary_next_action,
        "priority": _priority_for_vuln(vuln_type),
    }


def validate_planner_candidate(planner) -> tuple[dict, str]:
    if not isinstance(planner, dict):
        return {}, "planner must be a JSON object."

    missing = [field for field in PLANNER_REQUIRED_FIELDS if field not in planner]
    if missing:
        return {}, f"planner is missing required field(s): {', '.join(missing)}."

    vuln_type = str(planner.get("vuln_type") or "").strip().lower()
    if not vuln_type:
        return {}, "planner.vuln_type must be a non-empty string."

    confidence = _coerce_confidence(planner.get("confidence"))
    if confidence is None:
        return {}, "planner.confidence must be a number between 0 and 1."

    parameters = _clean_string_list(planner.get("parameters"), limit=6)
    if not isinstance(planner.get("parameters"), list):
        return {}, "planner.parameters must be a list of strings."

    attack_plan = _clean_string_list(planner.get("attack_plan"), limit=8)
    if not isinstance(planner.get("attack_plan"), list) or not attack_plan:
        return {}, "planner.attack_plan must be a non-empty list of strings."

    next_action = str(planner.get("next_action") or "").strip()
    if not next_action:
        return {}, "planner.next_action must be a non-empty string."

    priority = str(planner.get("priority") or "").strip().lower()
    if priority not in PLANNER_PRIORITY_VALUES:
        return {}, "planner.priority must be one of: low, medium, high, critical."

    normalized = {
        "vuln_type": vuln_type,
        "confidence": confidence,
        "parameters": parameters,
        "attack_plan": attack_plan,
        "next_action": next_action,
        "priority": priority,
    }
    return normalized, ""


def enforce_candidate_planner_schema(candidate: dict | None) -> tuple[dict, str]:
    if not isinstance(candidate, dict):
        return {}, "The provider response is not a JSON object."

    working = dict(candidate)
    planner_source = working.get("planner")
    if planner_source is None:
        top_level_planner = {
            field: working.get(field)
            for field in PLANNER_REQUIRED_FIELDS
            if field in working
        }
        if top_level_planner:
            planner_source = top_level_planner
    if planner_source is None:
        derived = derive_planner_candidate(working)
        if derived:
            working["planner"] = derived
        return working, ""

    normalized_planner, error = validate_planner_candidate(planner_source)
    if error:
        return {}, f"Invalid planner schema: {error}"

    working["planner"] = normalized_planner

    if not is_populated_model_value(working.get("primary_next_action")):
        working["primary_next_action"] = normalized_planner["next_action"]
    if not is_populated_model_value(working.get("request_plan")):
        plan = list(normalized_planner["attack_plan"][:6])
        if normalized_planner["parameters"]:
            plan.insert(0, "Target parameter: " + ", ".join(normalized_planner["parameters"][:3]))
        working["request_plan"] = plan[:6]
    if not is_populated_model_value(working.get("potential_vulnerabilities")):
        working["potential_vulnerabilities"] = [
            f"[{normalized_planner['vuln_type']}] planner hypothesis at confidence {normalized_planner['confidence']:.2f}"
        ]
    if not is_populated_model_value(working.get("analysis")):
        working["analysis"] = (
            f"Planner selected {normalized_planner['vuln_type']} "
            f"at confidence {normalized_planner['confidence']:.2f}. "
            f"Next action: {normalized_planner['next_action']}"
        )
    if not is_populated_model_value(working.get("questions_for_user")):
        if normalized_planner["parameters"]:
            working["questions_for_user"] = [
                "Can you confirm expected behavior for: " + ", ".join(normalized_planner["parameters"][:3]) + "?"
            ]
        else:
            working["questions_for_user"] = [
                "Can you confirm the expected authorization or validation behavior for this endpoint?"
            ]
    return working, ""


def is_populated_model_value(value) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return any(is_populated_model_value(item) for item in value)
    if isinstance(value, dict):
        return any(is_populated_model_value(item) for item in value.values())
    return value is not None


def normalize_model_candidate(candidate: dict | None) -> dict:
    normalized: dict = {}
    if not isinstance(candidate, dict):
        return normalized

    for key in MODEL_RESPONSE_FIELDS:
        value = candidate.get(key)
        if not is_populated_model_value(value):
            continue
        normalized[key] = value
    return normalized


def missing_model_fields(candidate: dict) -> list[str]:
    return [field for field in MODEL_REQUIRED_FIELDS if not is_populated_model_value(candidate.get(field))]


def merge_model_candidates(current: dict, incoming: dict) -> tuple[dict, list[str]]:
    merged = dict(current)
    adopted_fields: list[str] = []
    for field in MODEL_RESPONSE_FIELDS:
        if is_populated_model_value(merged.get(field)):
            continue
        if not is_populated_model_value(incoming.get(field)):
            continue
        merged[field] = incoming[field]
        adopted_fields.append(field)
    return merged, adopted_fields


def format_model_trace_entry(provider: str, status: str, detail: str) -> str:
    normalized_provider = (provider or "model").upper()
    normalized_status = (status or "info").upper()
    return f"{normalized_provider} {normalized_status}: {detail}"


def build_model_execution_summary(
    backend: str,
    provider_trace: list[str],
    fallback_used: bool,
    successful_providers: list[str],
    missing_fields: list[str],
) -> str:
    attempted = ", ".join(configured_model_providers()) or "none"
    successful = ", ".join(successful_providers) or "none"
    summary = f"Provider order: {attempted}. Final backend: {backend}. Successful providers: {successful}."
    if fallback_used:
        summary += " Deterministic fallback fields were used."
    if missing_fields:
        summary += f" Missing provider fields backfilled from fallback: {', '.join(missing_fields)}."
    if provider_trace:
        summary += f" Last provider note: {provider_trace[-1]}"
    return summary


def build_provider_failover(
    provider_order: list[str],
    provider_outcomes: list[dict],
    backend: str,
    fallback_used: bool,
    missing_fields: list[str],
) -> dict:
    successful_providers = [
        item.get("provider", "")
        for item in provider_outcomes
        if (item.get("status") or "").strip().lower() in {"used", "partial"}
    ]
    mcp_failure = any(
        (item.get("provider") or "").strip().lower() == "mcp"
        and (item.get("status") or "").strip().lower() in {"failed", "skipped"}
        for item in provider_outcomes
    )
    downstream_success = any(
        (item.get("provider") or "").strip().lower() != "mcp"
        and (item.get("status") or "").strip().lower() in {"used", "partial"}
        for item in provider_outcomes
    )
    if not provider_outcomes:
        final_status = "deterministic-only"
    elif fallback_used:
        final_status = "partial-with-deterministic-backfill" if successful_providers else "deterministic-fallback"
    else:
        final_status = "complete"

    return {
        "provider_order": list(provider_order),
        "outcomes": [dict(item) for item in provider_outcomes[:8]],
        "successful_providers": successful_providers,
        "final_backend": backend,
        "final_status": final_status,
        "fallback_used": fallback_used,
        "deterministic_backfill_used": bool(missing_fields),
        "missing_fields": list(missing_fields),
        "mcp_fallback_triggered": mcp_failure and downstream_success,
    }


def append_model_execution_details(analysis: str, execution_summary: str, provider_trace: list[str], fallback_used: bool) -> str:
    if not execution_summary:
        return analysis
    if not fallback_used and not any("FAILED" in entry or "PARTIAL" in entry or "SKIPPED" in entry for entry in provider_trace):
        return analysis

    lines = [analysis, "", "Model execution:", f"- {execution_summary}"]
    for entry in provider_trace[:4]:
        lines.append(f"- {entry}")
    return "\n".join(lines)


def attach_execution_metadata(
    result: dict,
    backend: str,
    execution_summary: str,
    provider_trace: list[str],
    fallback_used: bool,
    provider_failover: dict | None = None,
    request_id: str = "",
) -> dict:
    enriched = dict(result)
    trace_entries = list(provider_trace[:8])
    if request_id and not any(request_id in entry for entry in trace_entries):
        trace_entries.insert(0, format_model_trace_entry("request", "info", f"request_id={request_id}"))
    enriched["analysis_backend"] = backend
    enriched["model_execution_summary"] = execution_summary
    enriched["model_execution_trace"] = trace_entries[:8]
    enriched["fallback_used"] = fallback_used
    enriched["provider_failover"] = dict(provider_failover or {})
    enriched["request_id"] = request_id
    enriched["analysis"] = append_model_execution_details(
        enriched.get("analysis", ""),
        execution_summary,
        trace_entries,
        fallback_used,
    )
    return enriched


def finalize_fallback_response(
    fallback: dict,
    history_correlation: list[str],
    confirmation_playbooks: list[str],
    backend: str,
    execution_summary: str,
    provider_trace: list[str],
    fallback_used: bool = True,
    provider_failover: dict | None = None,
    request_id: str = "",
) -> dict:
    result = dict(fallback)
    result["history_correlation"] = history_correlation[:6]
    result["confirmation_playbooks"] = confirmation_playbooks[:6]
    return attach_execution_metadata(
        result,
        backend,
        execution_summary,
        provider_trace,
        fallback_used,
        provider_failover=provider_failover,
        request_id=request_id,
    )


def extract_mcp_candidate(result: MCPCallResult) -> dict:
    structured = normalize_model_candidate(result.structured_content)
    if structured:
        return structured

    text_payload = (result.content_text or "").strip()
    if not text_payload:
        return {}
    try:
        parsed = json.loads(text_payload)
    except json.JSONDecodeError:
        return {"analysis": text_payload}
    return normalize_model_candidate(parsed)


def mcp_server_label(result: MCPCallResult) -> str:
    parts = [part for part in [result.server_name, result.server_version] if part]
    if parts:
        return " ".join(parts)
    return result.tool_name


def build_mcp_arguments(
    prompt: str,
    payload,
    profile_name: str,
    privacy_mode: str,
    fallback: dict,
    rule_context: dict,
) -> dict:
    return {
        "task": "burp_ai_bridge_analysis",
        "schema_name": "burp_ai_bridge_advisory_response_v1",
        "prompt": prompt,
        "target_url": getattr(payload, "target_url", "") or "",
        "http_method": getattr(payload, "http_method", "") or "",
        "source_tool": getattr(payload, "source_tool", "") or "",
        "annotations": list(getattr(payload, "annotations", []) or []),
        "selected_profile": profile_name,
        "privacy_mode": privacy_mode,
        "deterministic_baseline": {
            "analysis": fallback.get("analysis", ""),
            "primary_next_action": fallback.get("primary_next_action", ""),
            "request_plan": fallback.get("request_plan", [])[:6],
            "potential_vulnerabilities": fallback.get("potential_vulnerabilities", [])[:5],
            "questions_for_user": fallback.get("questions_for_user", [])[:3],
            "source_links": fallback.get("source_links", [])[:8],
        },
        "rule_observations": rule_context.get("features", {}).get("observations", [])[:20],
        "matched_playbooks": [item.get("title", "") for item in rule_context.get("matched_recipes", [])[:5]],
    }


def call_mcp_provider(
    prompt: str,
    payload,
    profile_name: str,
    privacy_mode: str,
    fallback: dict,
    rule_context: dict,
) -> tuple[dict, str]:
    config = MCPServerConfig(
        transport=MCP_TRANSPORT,
        tool_name=MCP_TOOL_NAME,
        timeout_seconds=MCP_TIMEOUT_SECONDS,
        protocol_version=MCP_PROTOCOL_VERSION,
        command=MCP_SERVER_COMMAND,
        url=MCP_SERVER_URL,
        working_directory=MCP_WORKING_DIRECTORY,
    )
    result = call_mcp_tool(
        config,
        build_mcp_arguments(prompt, payload, profile_name, privacy_mode, fallback, rule_context),
    )
    candidate = extract_mcp_candidate(result)
    if not candidate:
        raise MCPError(
            f"MCP tool '{result.tool_name}' returned no advisory fields in structuredContent or text output."
        )
    detail = (
        f"Tool '{result.tool_name}' on {mcp_server_label(result)} "
        f"returned fields: {', '.join(sorted(candidate.keys()))}."
    )
    return candidate, detail


def call_ollama_provider(prompt: str, payload, profile_name: str, fallback: dict, rule_context: dict) -> tuple[dict, str]:
    route = choose_ollama_model_for_request(
        payload,
        profile_name=profile_name,
        fallback=fallback,
        rule_context=rule_context,
    )
    routed_model = str(route.get("model") or get_active_ollama_model()).strip()
    result_text, used_url = ollama_text_response(prompt, "json", model_name=routed_model)
    parsed = json.loads(result_text)
    candidate = normalize_model_candidate(parsed)
    if not candidate:
        raise ValueError("Ollama returned JSON without any advisory fields.")
    reason_text = "; ".join(route.get("reasons") or []) or "No routing rationale recorded."
    return (
        candidate,
        f"Ollama returned fields: {', '.join(sorted(candidate.keys()))} via {used_url}. "
        f"Model route={route.get('route') or 'active-default'} model={routed_model} score={route.get('score', 0)}. {reason_text}",
    )

