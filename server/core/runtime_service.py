import requests
import json
import re
from urllib.parse import urlparse

from server.burp_mcp_context import inspect_burp_mcp_server
from server.core.analysis_service import coerce_payload
from server.core.runtime_model_override_service import get_active_ollama_model
from server.core.burp_context_service import (
    get_dashboard_issue_context,
    get_project_config_snapshot,
    summarize_burp_context,
)
from server.core.action_labels import label_actions
from server.mcp_client import MCPConfigurationError, MCPError, MCPServerConfig, inspect_mcp_server
from server.providers.model_execution_service import candidate_ollama_text_urls, configured_model_providers
from server.state.store import read_provider_diagnostics
from server.settings import (
    BURP_MCP_CONTEXT_ENABLED,
    ENABLE_DIRECT_OLLAMA_FALLBACK,
    MCP_ENABLED,
    MCP_PROTOCOL_VERSION,
    MCP_SERVER_COMMAND,
    MCP_SERVER_URL,
    MCP_TIMEOUT_SECONDS,
    MCP_TOOL_NAME,
    MCP_TRANSPORT,
    MCP_WORKING_DIRECTORY,
    MODEL_PROVIDER_ORDER,
    EXECUTION_DEFAULT_MAX_CONCURRENCY,
    EXECUTION_DEFAULT_RATE_LIMIT,
    EXECUTION_HARD_MAX_CONCURRENCY,
    EXECUTION_HARD_MAX_RATE_LIMIT,
    EXECUTION_KILL_SWITCH,
    EXECUTION_SCOPE_ENFORCEMENT_ENABLED,
    OLLAMA_TIMEOUT_SECONDS,
    OLLAMA_URL,
    OLLAMA_VISION_MODEL,
)


def get_runtime_health() -> dict:
    return {
        "configured_provider_order": list(MODEL_PROVIDER_ORDER),
        "active_provider_order": configured_model_providers(),
        "context_priority": _context_priority(),
        "burp_mcp": _burp_mcp_health(),
        "mcp": _mcp_health(),
        "ollama": _ollama_health(),
    }


def evaluate_execution_safety(payload_like, *, policy_gate: dict | None = None, fallback_used: bool = False) -> dict:
    payload = coerce_payload(payload_like)
    target_url = (getattr(payload, "target_url", "") or "").strip()
    include_rules = _scope_rules(getattr(payload, "scope_includes_text", "") or "")
    exclude_rules = _scope_rules(getattr(payload, "scope_excludes_text", "") or "")
    scope_allowed, scope_reason = _scope_allows_target(
        target_url=target_url,
        include_rules=include_rules,
        exclude_rules=exclude_rules,
    )
    rate_limit_requested = _extract_positive_int(getattr(payload, "rate_limit_text", "") or "")
    concurrency_requested = _extract_positive_int(getattr(payload, "max_concurrency_text", "") or "")
    rate_limit_effective = min(
        rate_limit_requested or max(1, int(EXECUTION_DEFAULT_RATE_LIMIT or 1)),
        max(1, int(EXECUTION_HARD_MAX_RATE_LIMIT or 1)),
    )
    concurrency_effective = min(
        concurrency_requested or max(1, int(EXECUTION_DEFAULT_MAX_CONCURRENCY or 1)),
        max(1, int(EXECUTION_HARD_MAX_CONCURRENCY or 1)),
    )
    kill_switch_active, kill_switch_reason = _kill_switch_state(payload)
    gate = dict(policy_gate or {})
    policy_gate_applies = bool(gate.get("effective_applies", gate.get("applies")))
    policy_gate_allowed = not policy_gate_applies or bool(gate.get("effective_allowed", gate.get("allowed", False)))
    blocked_reasons: list[str] = []

    if kill_switch_active:
        blocked_reasons.append(kill_switch_reason or "Execution kill-switch is active.")
    if EXECUTION_SCOPE_ENFORCEMENT_ENABLED and not scope_allowed:
        blocked_reasons.append(scope_reason or "Target is outside the configured scope.")
    if policy_gate_applies and not policy_gate_allowed:
        blocked_reasons.append((gate.get("reason") or "Program policy gate blocks escalation.").strip())
    if fallback_used:
        blocked_reasons.append("Model fallback is active, so expansion remains bounded until stronger evidence is available.")

    warnings: list[str] = []
    if not rate_limit_requested:
        warnings.append(f"Rate limit was not provided; enforced default is {rate_limit_effective} req/sec.")
    if not concurrency_requested:
        warnings.append(f"Concurrency was not provided; enforced default is {concurrency_effective}.")
    if rate_limit_requested and rate_limit_requested > rate_limit_effective:
        warnings.append(
            f"Requested rate limit {rate_limit_requested} req/sec exceeded safety cap {rate_limit_effective}; capped."
        )
    if concurrency_requested and concurrency_requested > concurrency_effective:
        warnings.append(
            f"Requested concurrency {concurrency_requested} exceeded safety cap {concurrency_effective}; capped."
        )

    safe_to_expand = not blocked_reasons
    return {
        "safe_to_expand": safe_to_expand,
        "blocked": not safe_to_expand,
        "blocked_reasons": blocked_reasons[:6],
        "warnings": warnings[:6],
        "kill_switch": {
            "active": kill_switch_active,
            "reason": kill_switch_reason,
        },
        "scope": {
            "enforcement_enabled": bool(EXECUTION_SCOPE_ENFORCEMENT_ENABLED),
            "target_url": target_url,
            "include_rules": include_rules[:8],
            "exclude_rules": exclude_rules[:8],
            "allowed": scope_allowed,
            "reason": scope_reason,
        },
        "limits": {
            "rate_limit_requested": rate_limit_requested,
            "rate_limit_effective": rate_limit_effective,
            "max_concurrency_requested": concurrency_requested,
            "max_concurrency_effective": concurrency_effective,
            "hard_max_rate_limit": max(1, int(EXECUTION_HARD_MAX_RATE_LIMIT or 1)),
            "hard_max_concurrency": max(1, int(EXECUTION_HARD_MAX_CONCURRENCY or 1)),
        },
        "policy_gate": {
            "applies": policy_gate_applies,
            "allowed": policy_gate_allowed,
            "reason": (gate.get("effective_reason") or gate.get("reason") or "").strip(),
        },
    }


def get_runtime_readiness(payload_like) -> dict:
    payload = coerce_payload(payload_like)
    health = get_runtime_health()
    burp_context_summary = summarize_burp_context(payload)
    dashboard_issue = get_dashboard_issue_context(payload)
    project_config = get_project_config_snapshot(payload)

    request_present = bool((getattr(payload, "raw_request", "") or "").strip())
    target_present = bool((getattr(payload, "target_url", "") or "").strip())
    runtime_statuses = []
    burp_mcp = health.get("burp_mcp") or {}
    if burp_mcp.get("enabled"):
        runtime_statuses.append(("burp_mcp", burp_mcp.get("status", "")))
    for provider in health["active_provider_order"]:
        if provider == "mcp":
            runtime_statuses.append((provider, health["mcp"]["status"]))
        elif provider == "ollama":
            runtime_statuses.append((provider, health["ollama"]["status"]))

    runtime_ready = any(status == "ready" for _, status in runtime_statuses)
    runtime_degraded = not runtime_ready and any(status == "degraded" for _, status in runtime_statuses)
    has_burp_context = bool(
        dashboard_issue.get("found")
        or burp_context_summary.get("proxy_history_count")
        or burp_context_summary.get("logger_entry_count")
        or burp_context_summary.get("repeater_request_count")
    )
    has_project_config = bool(
        project_config.get("enabled_tools")
        or project_config.get("scope_includes")
        or project_config.get("scope_excludes")
        or project_config.get("program_policy")
        or project_config.get("rate_limit_notes")
        or project_config.get("custom_headers_notes")
    )
    has_visual_or_header_context = bool(
        (getattr(payload, "burp_screenshot_audit_text", "") or "").strip()
        or (getattr(payload, "program_screenshot_audit_text", "") or "").strip()
        or (getattr(payload, "custom_headers_text", "") or "").strip()
        or project_config.get("custom_headers_notes")
    )

    checks = [
        _readiness_check(
            "context-priority",
            "ready" if health.get("context_priority", {}).get("status") == "ready" else "degraded",
            (health.get("context_priority") or {}).get("summary") or "Context priority could not be determined.",
        ),
        _readiness_check(
            "runtime-providers",
            "ready" if runtime_ready else ("degraded" if runtime_degraded else "not-ready"),
            _runtime_check_detail(runtime_statuses, health),
        ),
        _readiness_check(
            "request-payload",
            "ready" if request_present and target_present else "not-ready",
            "Raw request and target URL are present." if request_present and target_present else "Include both raw_request and target_url in the analysis payload.",
        ),
        _readiness_check(
            "burp-context",
            "ready" if has_burp_context else "degraded",
            "Burp context is attached and can support impact/validation ranking."
            if has_burp_context
            else "Attach Burp issue context, proxy history, logger deltas, or repeater requests for stronger phase outputs.",
        ),
        _readiness_check(
            "project-config",
            "ready" if has_project_config else "degraded",
            "Project scope/config context is available."
            if has_project_config
            else "Attach scope, enabled tools, or policy/config notes so readiness and Burp action guidance stay specific.",
        ),
        _readiness_check(
            "visual-headers",
            "ready" if has_visual_or_header_context else "degraded",
            "Screenshot or header context is present."
            if has_visual_or_header_context
            else "Optional but useful: include screenshot audit notes or custom header context for safer Burp guidance.",
        ),
    ]

    blockers = [item["detail"] for item in checks if item["status"] == "not-ready"]
    warnings = [item["detail"] for item in checks if item["status"] == "degraded"]
    input_ready = request_present and target_present
    readiness_status = "ready" if runtime_ready and input_ready else ("degraded" if input_ready and (runtime_degraded or has_burp_context or has_project_config) else "not-ready")
    summary = (
        "Runtime and payload are ready for high-quality analysis."
        if readiness_status == "ready"
        else "Runtime is partially ready, but more context or a healthier provider path would improve output quality."
        if readiness_status == "degraded"
        else "Analysis is not ready yet because required payload or provider prerequisites are missing."
    )
    execution_safety = evaluate_execution_safety(payload)

    return {
        "request_id": getattr(payload, "request_id", "") or "",
        "status": readiness_status,
        "summary": summary,
        "recommended_analysis_endpoint": "/api/analyze/jobs",
        "runtime_ready": runtime_ready or runtime_degraded,
        "input_ready": input_ready,
        "checks": checks,
        "blockers": blockers[:6],
        "warnings": warnings[:6],
        "burp_context_summary": burp_context_summary,
        "project_config": project_config,
        "execution_safety": execution_safety,
        "runtime_health": health,
        "context_priority": health.get("context_priority") or {},
        "labeled_next_steps": label_actions(
            blockers[:3] + warnings[:3] + ["Prefer /api/analyze/jobs for IDE and extension flows."],
            fallback_used=not runtime_ready,
        )[:8],
    }


def get_provider_diagnostics_history(
    *,
    limit: int = 20,
    cursor: int = 0,
    job_id: str = "",
    request_id: str = "",
    provider: str = "",
    final_status: str = "",
) -> dict:
    normalized_limit = max(1, min(limit, 200))
    normalized_cursor = max(0, int(cursor or 0))
    provider_name = (provider or "").strip().lower()
    normalized_final_status = (final_status or "").strip().lower()
    filtered = []
    for entry in read_provider_diagnostics():
        if job_id and (entry.get("job_id") or "").strip() != job_id.strip():
            continue
        if request_id and (entry.get("request_id") or "").strip() != request_id.strip():
            continue
        if provider_name and not _entry_mentions_provider(entry, provider_name):
            continue
        if normalized_final_status and ((entry.get("provider_failover") or {}).get("final_status") or "").strip().lower() != normalized_final_status:
            continue
        filtered.append(entry)

    filtered.sort(key=lambda item: (item.get("created_at") or "", item.get("job_id") or ""), reverse=True)
    items = filtered[normalized_cursor:normalized_cursor + normalized_limit]
    status_counts: dict[str, int] = {}
    backend_counts: dict[str, int] = {}
    for entry in filtered:
        final_status = ((entry.get("provider_failover") or {}).get("final_status") or "unknown").strip() or "unknown"
        backend = (entry.get("analysis_backend") or "unknown").strip() or "unknown"
        status_counts[final_status] = status_counts.get(final_status, 0) + 1
        backend_counts[backend] = backend_counts.get(backend, 0) + 1

    return {
        "total_matches": len(filtered),
        "count": len(items),
        "limit": normalized_limit,
        "cursor": normalized_cursor,
        "next_cursor": (normalized_cursor + len(items)) if (normalized_cursor + len(items)) < len(filtered) else None,
        "provider_status_counts": status_counts,
        "backend_counts": backend_counts,
        "items": items,
    }


def provider_diagnostics_jsonl(items: list[dict]) -> str:
    return "".join(json.dumps(item, ensure_ascii=True) + "\n" for item in items)


def provider_diagnostics_markdown(page: dict) -> str:
    items = page.get("items") or []
    lines = [
        "# Provider Diagnostics",
        "",
        f"- Total matches: {page.get('total_matches', 0)}",
        f"- Returned: {page.get('count', len(items))}",
        f"- Cursor: {page.get('cursor', 0)}",
        f"- Next cursor: {page.get('next_cursor') if page.get('next_cursor') is not None else '<none>'}",
        "",
        "## Status Counts",
    ]
    status_counts = page.get("provider_status_counts") or {}
    if status_counts:
        for status, count in status_counts.items():
            lines.append(f"- {status}: {count}")
    else:
        lines.append("- None")
    lines.extend(["", "## Items"])
    if not items:
        lines.append("- None")
        return "\n".join(lines) + "\n"

    for item in items:
        failover = item.get("provider_failover") or {}
        lines.append(
            f"- {item.get('created_at') or '<unknown>'} | {item.get('job_id') or '<unknown>'} | "
            f"{item.get('request_id') or '<unknown>'} | {item.get('analysis_backend') or '<unknown>'} | "
            f"{failover.get('final_status') or '<unknown>'}"
        )
        for outcome in failover.get("outcomes") or []:
            lines.append(
                f"  - {outcome.get('provider') or 'provider'}: {outcome.get('status') or 'unknown'} | "
                f"{outcome.get('detail') or ''}"
            )
    return "\n".join(lines) + "\n"


def _scope_rules(text: str) -> list[str]:
    if not text:
        return []
    parts = re.split(r"[,\n]+", text)
    return [part.strip() for part in parts if part.strip()]


def _extract_positive_int(text: str) -> int:
    match = re.search(r"(\d+)", text or "")
    if not match:
        return 0
    try:
        value = int(match.group(1))
    except ValueError:
        return 0
    return value if value > 0 else 0


def _normalized_host(value: str) -> str:
    parsed = urlparse(value if "://" in (value or "") else f"https://{value}")
    return (parsed.netloc or parsed.path or "").split(":", 1)[0].strip().lower()


def _normalized_path(value: str) -> str:
    parsed = urlparse(value if "://" in (value or "") else f"https://placeholder{value if value.startswith('/') else '/' + value}")
    return (parsed.path or "/").strip() or "/"


def _rule_matches_target(rule: str, *, target_url: str, target_host: str, target_path: str) -> bool:
    normalized = (rule or "").strip().lower()
    if not normalized:
        return False
    if normalized.startswith("*."):
        suffix = normalized[1:]
        return target_host.endswith(suffix)
    if "://" in normalized:
        parsed = urlparse(normalized)
        rule_host = (parsed.netloc or "").split(":", 1)[0].strip().lower()
        rule_path = parsed.path or "/"
        return bool(rule_host and target_host == rule_host and target_path.startswith(rule_path))
    if "/" in normalized:
        rule_host = _normalized_host(normalized)
        rule_path = _normalized_path(normalized)
        if rule_host and rule_host != "placeholder":
            return target_host == rule_host and target_path.startswith(rule_path)
        return target_path.startswith(rule_path)
    return target_host == _normalized_host(normalized) or target_host.endswith("." + _normalized_host(normalized))


def _scope_allows_target(*, target_url: str, include_rules: list[str], exclude_rules: list[str]) -> tuple[bool, str]:
    if not target_url:
        return False, "Target URL is missing."
    parsed = urlparse(target_url)
    target_host = (parsed.netloc or "").split(":", 1)[0].strip().lower()
    target_path = parsed.path or "/"

    excluded_match = next(
        (rule for rule in exclude_rules if _rule_matches_target(rule, target_url=target_url, target_host=target_host, target_path=target_path)),
        "",
    )
    if excluded_match:
        return False, f"Target is blocked by out-of-scope rule: {excluded_match}"

    if not include_rules:
        return True, "No explicit in-scope list was provided."

    included_match = next(
        (rule for rule in include_rules if _rule_matches_target(rule, target_url=target_url, target_host=target_host, target_path=target_path)),
        "",
    )
    if included_match:
        return True, f"Target matched in-scope rule: {included_match}"
    return False, "Target does not match any in-scope rule."


def _kill_switch_state(payload) -> tuple[bool, str]:
    if EXECUTION_KILL_SWITCH:
        return True, "Global execution kill-switch is enabled by server configuration."

    policy_text = " ".join(
        [
            getattr(payload, "program_policy_text", "") or "",
            getattr(payload, "saved_program_policy_text", "") or "",
            getattr(payload, "browser_verification_notes", "") or "",
        ]
    ).lower()
    markers = (
        "kill switch",
        "kill switch",
        "no automation",
        "manual only",
        "do not automate",
        "autonomous disabled",
    )
    for marker in markers:
        if marker in policy_text:
            return True, f"Program policy indicates execution kill-switch: '{marker}'."
    return False, ""


def _mcp_health() -> dict:
    if not MCP_ENABLED:
        return {
            "enabled": False,
            "transport": MCP_TRANSPORT,
            "tool_name": MCP_TOOL_NAME,
            "timeout_seconds": MCP_TIMEOUT_SECONDS,
            "protocol_version": MCP_PROTOCOL_VERSION,
            "status": "disabled",
            "detail": "MCP is disabled by configuration.",
            "command": MCP_SERVER_COMMAND,
            "url": MCP_SERVER_URL,
            "working_directory": MCP_WORKING_DIRECTORY,
            "server_name": "",
            "server_version": "",
            "available_tools": [],
        }

    config = MCPServerConfig(
        transport=MCP_TRANSPORT,
        tool_name=MCP_TOOL_NAME,
        timeout_seconds=MCP_TIMEOUT_SECONDS,
        protocol_version=MCP_PROTOCOL_VERSION,
        command=MCP_SERVER_COMMAND,
        url=MCP_SERVER_URL,
        working_directory=MCP_WORKING_DIRECTORY,
    )
    try:
        inspection = inspect_mcp_server(config)
    except MCPConfigurationError as exc:
        status = "misconfigured"
        detail = str(exc)
        server_name = ""
        server_version = ""
        available_tools: list[str] = []
        protocol_version = MCP_PROTOCOL_VERSION
    except MCPError as exc:
        status = "unreachable"
        detail = str(exc)
        server_name = ""
        server_version = ""
        available_tools = []
        protocol_version = MCP_PROTOCOL_VERSION
    else:
        available_tools = inspection.available_tools
        tool_ready = MCP_TOOL_NAME in available_tools if available_tools else False
        status = "ready" if tool_ready else "degraded"
        detail = (
            f"MCP server responded and advertised {len(available_tools)} tool(s)."
            if tool_ready
            else f"MCP server responded, but '{MCP_TOOL_NAME}' was not advertised."
        )
        server_name = inspection.server_name
        server_version = inspection.server_version
        protocol_version = inspection.protocol_version

    return {
        "enabled": True,
        "transport": MCP_TRANSPORT,
        "tool_name": MCP_TOOL_NAME,
        "timeout_seconds": MCP_TIMEOUT_SECONDS,
        "protocol_version": protocol_version,
        "status": status,
        "detail": detail,
        "command": MCP_SERVER_COMMAND,
        "url": MCP_SERVER_URL,
        "working_directory": MCP_WORKING_DIRECTORY,
        "server_name": server_name,
        "server_version": server_version,
        "available_tools": available_tools[:24],
    }


def _burp_mcp_health() -> dict:
    if not BURP_MCP_CONTEXT_ENABLED:
        return inspect_burp_mcp_server()
    return inspect_burp_mcp_server()


def _ollama_health() -> dict:
    active_model = get_active_ollama_model()
    candidate_urls = candidate_ollama_text_urls()
    if not ENABLE_DIRECT_OLLAMA_FALLBACK:
        return {
            "enabled": False,
            "configured_url": OLLAMA_URL,
            "model": active_model,
            "vision_model": OLLAMA_VISION_MODEL,
            "timeout_seconds": OLLAMA_TIMEOUT_SECONDS,
            "status": "disabled",
            "detail": "Direct Ollama fallback is disabled by configuration.",
            "candidate_urls": candidate_urls,
            "tag_probe_urls": _ollama_tag_probe_urls(candidate_urls),
            "selected_endpoint": "",
            "detected_models": [],
        }

    if not (OLLAMA_URL or "").strip():
        return {
            "enabled": True,
            "configured_url": OLLAMA_URL,
            "model": active_model,
            "vision_model": OLLAMA_VISION_MODEL,
            "timeout_seconds": OLLAMA_TIMEOUT_SECONDS,
            "status": "misconfigured",
            "detail": "OLLAMA_URL is empty.",
            "candidate_urls": candidate_urls,
            "tag_probe_urls": [],
            "selected_endpoint": "",
            "detected_models": [],
        }

    tag_urls = _ollama_tag_probe_urls(candidate_urls)
    selected_endpoint = candidate_urls[0] if candidate_urls else ""
    errors: list[str] = []
    for tag_url in tag_urls:
        try:
            response = requests.get(tag_url, timeout=min(max(1, OLLAMA_TIMEOUT_SECONDS), 5))
            response.raise_for_status()
            payload = response.json()
            detected_models = _extract_ollama_model_names(payload)
            model_ready = active_model in detected_models if detected_models else False
            detail = (
                "Ollama is reachable and the configured text model is available."
                if model_ready
                else "Ollama is reachable, but the configured text model was not listed by /api/tags."
            )
            return {
                "enabled": True,
                "configured_url": OLLAMA_URL,
                "model": active_model,
                "vision_model": OLLAMA_VISION_MODEL,
                "timeout_seconds": OLLAMA_TIMEOUT_SECONDS,
                "status": "ready" if model_ready else "degraded",
                "detail": detail,
                "candidate_urls": candidate_urls,
                "tag_probe_urls": tag_urls,
                "selected_endpoint": selected_endpoint,
                "detected_models": detected_models[:24],
            }
        except requests.RequestException as exc:
            errors.append(f"{tag_url}: {exc}")
        except ValueError as exc:
            errors.append(f"{tag_url}: invalid JSON ({exc})")

    return {
        "enabled": True,
        "configured_url": OLLAMA_URL,
        "model": active_model,
        "vision_model": OLLAMA_VISION_MODEL,
        "timeout_seconds": OLLAMA_TIMEOUT_SECONDS,
        "status": "unreachable",
        "detail": errors[-1] if errors else "No Ollama health probe URL could be derived from OLLAMA_URL.",
        "candidate_urls": candidate_urls,
        "tag_probe_urls": tag_urls,
        "selected_endpoint": selected_endpoint,
        "detected_models": [],
    }


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


def _extract_ollama_model_names(payload: dict) -> list[str]:
    models = payload.get("models") or []
    names: list[str] = []
    for item in models:
        if not isinstance(item, dict):
            continue
        name = (item.get("name") or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def _readiness_check(name: str, status: str, detail: str) -> dict:
    return {
        "name": name,
        "status": status,
        "detail": detail,
    }


def _runtime_check_detail(runtime_statuses: list[tuple[str, str]], health: dict) -> str:
    if not runtime_statuses:
        return "No active model providers are configured."
    parts = []
    for provider, status in runtime_statuses:
        detail = ((health.get(provider) or {}).get("detail") or "").strip()
        parts.append(f"{provider}={status}" + (f" ({detail})" if detail else ""))
    return "; ".join(parts)


def _context_priority() -> dict:
    provider_order = list(MODEL_PROVIDER_ORDER)
    provider_order_starts_with_mcp = bool(provider_order and provider_order[0] == "mcp")
    burp_context_enabled = bool(BURP_MCP_CONTEXT_ENABLED)
    mcp_enabled = bool(MCP_ENABLED)
    primary_context_source = "burp_mcp" if burp_context_enabled else "request-payload"
    status = "ready" if (burp_context_enabled and mcp_enabled and provider_order_starts_with_mcp) else "degraded"
    if status == "ready":
        summary = "Burp MCP is enabled and MCP is first in the provider order, so live Burp context is the primary source."
    elif burp_context_enabled and mcp_enabled:
        summary = "Burp MCP is enabled, but MCP is not first in the provider order. Burp context stays available, but it is not the strongest default path."
    elif burp_context_enabled:
        summary = "Burp MCP context is enabled, but the core MCP provider path is disabled. Live Burp context is partial."
    else:
        summary = "Burp MCP context is disabled, so analysis falls back to request payload and stored local context."
    return {
        "primary_context_source": primary_context_source,
        "burp_mcp_context_enabled": burp_context_enabled,
        "mcp_enabled": mcp_enabled,
        "provider_order_starts_with_mcp": provider_order_starts_with_mcp,
        "status": status,
        "summary": summary,
    }


def _entry_mentions_provider(entry: dict, provider: str) -> bool:
    if (entry.get("analysis_backend") or "").strip().lower().find(provider) >= 0:
        return True
    for outcome in ((entry.get("provider_failover") or {}).get("outcomes") or []):
        if (outcome.get("provider") or "").strip().lower() == provider:
            return True
    return False
