import json
import time
from collections import defaultdict
from threading import Lock
from typing import Any

from server.mcp_client import MCPError, MCPServerConfig, call_mcp_tool, inspect_mcp_server
from server.settings import (
    BURP_MCP_ALLOWED_CAPABILITIES,
    BURP_MCP_ALLOWED_TOOLS,
    BURP_MCP_CACHE_TTL_SECONDS,
    BURP_MCP_DEBOUNCE_WINDOW_MS,
    BURP_MCP_PROXY_COMMAND,
    BURP_MCP_READ_ONLY_ONLY,
    BURP_MCP_SERVER_URL,
    BURP_MCP_TIMEOUT_SECONDS,
    BURP_MCP_TRANSPORT,
    BURP_MCP_WORKING_DIRECTORY,
    MCP_PROTOCOL_VERSION,
)

READ_ONLY_CAPABILITIES = {
    "proxy_history",
    "regex_history_query",
    "scanner_issues",
    "active_editor",
    "project_options",
    "repeater_context",
    "intruder_results",
    "collaborator_interactions",
}
ACTION_CAPABILITIES = {
    "send_to_repeater",
    "start_intruder_attack",
    "update_project_options",
}
KNOWN_CAPABILITIES = tuple(sorted(READ_ONLY_CAPABILITIES | ACTION_CAPABILITIES))

_CAPABILITY_ALIASES = {
    "proxy_history": (
        "get_proxy_http_history",
        "get_http_history",
        "query_proxy_history",
        "query_http_history",
    ),
    "regex_history_query": (
        "search_proxy_history",
        "query_http_history",
        "query_proxy_history",
        "search_http_history",
    ),
    "scanner_issues": (
        "get_scanner_issues",
        "list_scanner_issues",
        "get_scan_issues",
    ),
    "active_editor": (
        "get_active_editor_contents",
        "get_current_editor_contents",
        "get_active_request_editor",
    ),
    "project_options": (
        "output_project_options",
        "get_project_options",
        "export_project_options",
    ),
    "repeater_context": (
        "get_repeater_requests",
        "get_repeater_tabs",
        "list_repeater_tabs",
    ),
    "intruder_results": (
        "get_intruder_results",
        "list_intruder_results",
        "list_intruder_attacks",
    ),
    "collaborator_interactions": (
        "get_collaborator_interactions",
        "poll_collaborator_interactions",
        "list_collaborator_interactions",
    ),
    "send_to_repeater": (
        "send_to_repeater",
        "open_in_repeater",
    ),
    "start_intruder_attack": (
        "send_to_intruder",
        "start_intruder_attack",
        "launch_intruder_attack",
    ),
    "update_project_options": (
        "set_project_options",
        "update_project_options",
        "import_project_options",
    ),
}

_CAPABILITY_TOKENS = {
    "proxy_history": (("proxy", "history"), ("http", "history")),
    "regex_history_query": (("history", "search"), ("history", "query"), ("proxy", "search")),
    "scanner_issues": (("scanner", "issues"), ("scan", "issues")),
    "active_editor": (("active", "editor"), ("current", "editor")),
    "project_options": (("project", "options"), ("project", "config")),
    "repeater_context": (("repeater", "request"), ("repeater", "tabs")),
    "intruder_results": (("intruder", "results"), ("intruder", "attacks")),
    "collaborator_interactions": (("collaborator", "interactions"), ("collaborator", "poll")),
    "send_to_repeater": (("send", "repeater"), ("open", "repeater")),
    "start_intruder_attack": (("intruder", "attack"), ("send", "intruder")),
    "update_project_options": (("project", "options", "set"), ("project", "options", "update")),
}

_DANGEROUS_TOOL_TOKENS = {
    "set",
    "update",
    "delete",
    "remove",
    "start",
    "launch",
    "send",
    "open",
    "import",
    "edit",
    "modify",
    "create",
}
_SAFE_ACTION_EXCEPTIONS = {"results", "issues", "history", "requests", "contents", "options", "tabs", "interactions"}

_INSPECTION_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_TOOL_CALL_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_LAST_CALL_AT: defaultdict[str, float] = defaultdict(float)
_CACHE_LOCK = Lock()


def burp_mcp_config(tool_name: str) -> MCPServerConfig:
    return MCPServerConfig(
        transport=BURP_MCP_TRANSPORT,
        tool_name=tool_name,
        timeout_seconds=BURP_MCP_TIMEOUT_SECONDS,
        protocol_version=MCP_PROTOCOL_VERSION,
        command=BURP_MCP_PROXY_COMMAND,
        url=BURP_MCP_SERVER_URL,
        working_directory=BURP_MCP_WORKING_DIRECTORY,
    )


def inspect_burp_mcp_capabilities(force_refresh: bool = False) -> dict[str, Any]:
    cache_key = "inspection"
    with _CACHE_LOCK:
        cached = _INSPECTION_CACHE.get(cache_key)
        if cached and not force_refresh and (time.monotonic() - cached[0]) <= max(1, BURP_MCP_CACHE_TTL_SECONDS):
            return dict(cached[1])

    inspection = inspect_mcp_server(burp_mcp_config(""))
    available_tools = list(inspection.available_tools or [])
    permissions = evaluate_burp_tool_permissions(available_tools)
    payload = {
        "transport": BURP_MCP_TRANSPORT,
        "timeout_seconds": BURP_MCP_TIMEOUT_SECONDS,
        "protocol_version": inspection.protocol_version,
        "url": BURP_MCP_SERVER_URL,
        "command": BURP_MCP_PROXY_COMMAND,
        "working_directory": BURP_MCP_WORKING_DIRECTORY,
        "server_name": inspection.server_name,
        "server_version": inspection.server_version,
        "available_tools": available_tools,
        **permissions,
    }
    with _CACHE_LOCK:
        _INSPECTION_CACHE[cache_key] = (time.monotonic(), dict(payload))
    return payload


def evaluate_burp_tool_permissions(available_tools: list[str]) -> dict[str, Any]:
    normalized_allowed_tools = {item.strip() for item in BURP_MCP_ALLOWED_TOOLS if item.strip()}
    normalized_allowed_capabilities = {item.strip() for item in BURP_MCP_ALLOWED_CAPABILITIES if item.strip()}

    capability_map = {}
    permitted_tools: list[str] = []
    blocked_tools: list[str] = []
    denied_capabilities: list[str] = []

    for capability in KNOWN_CAPABILITIES:
        tool_name = resolve_burp_tool_name(capability, available_tools)
        if not tool_name:
            continue
        allowed = _tool_allowed(tool_name, capability, normalized_allowed_tools, normalized_allowed_capabilities)
        capability_map[capability] = {
            "tool_name": tool_name,
            "allowed": allowed,
            "mode": "read-only" if capability in READ_ONLY_CAPABILITIES else "action",
        }
        if allowed:
            if tool_name not in permitted_tools:
                permitted_tools.append(tool_name)
        else:
            denied_capabilities.append(capability)
            if tool_name not in blocked_tools:
                blocked_tools.append(tool_name)

    for tool_name in available_tools:
        if tool_name in permitted_tools or tool_name in blocked_tools:
            continue
        if _looks_dangerous_tool(tool_name):
            blocked_tools.append(tool_name)

    return {
        "read_only_only": BURP_MCP_READ_ONLY_ONLY,
        "capability_map": capability_map,
        "permitted_tools": permitted_tools,
        "blocked_tools": blocked_tools,
        "denied_capabilities": denied_capabilities,
    }


def resolve_burp_tool_name(capability: str, available_tools: list[str]) -> str:
    normalized_capability = (capability or "").strip().lower()
    exact_aliases = _CAPABILITY_ALIASES.get(normalized_capability, ())
    available = [(tool or "").strip() for tool in available_tools if (tool or "").strip()]
    lowered = {tool.lower(): tool for tool in available}
    for alias in exact_aliases:
        if alias.lower() in lowered:
            return lowered[alias.lower()]
    token_sets = _CAPABILITY_TOKENS.get(normalized_capability, ())
    for tool_name in available:
        tokens = set(tool_name.lower().replace("-", "_").split("_"))
        for token_set in token_sets:
            if all(token in tokens for token in token_set):
                return tool_name
    return ""


def call_burp_mcp_capability(
    capability: str,
    *,
    count: int = 8,
    offset: int = 0,
    query: str = "",
    target_url: str = "",
    payload: dict[str, Any] | None = None,
    force_refresh: bool = False,
) -> dict[str, Any]:
    inspection = inspect_burp_mcp_capabilities(force_refresh=force_refresh)
    capability_entry = (inspection.get("capability_map") or {}).get((capability or "").strip().lower()) or {}
    tool_name = capability_entry.get("tool_name") or ""
    if not tool_name:
        raise MCPError(f"Burp MCP capability '{capability}' is not advertised by the connected server.")
    if not capability_entry.get("allowed"):
        raise MCPError(
            f"Burp MCP capability '{capability}' is currently blocked by the bridge tool-permission policy."
        )

    arguments = build_burp_capability_arguments(
        capability,
        count=count,
        offset=offset,
        query=query,
        target_url=target_url,
        payload=payload,
    )
    cache_key = json.dumps(
        {
            "tool_name": tool_name,
            "arguments": arguments,
        },
        ensure_ascii=True,
        sort_keys=True,
    )
    now = time.monotonic()
    with _CACHE_LOCK:
        cached = _TOOL_CALL_CACHE.get(cache_key)
        if cached and (now - cached[0]) <= max(1, BURP_MCP_CACHE_TTL_SECONDS):
            return dict(cached[1])
        last_call_at = _LAST_CALL_AT[tool_name]
    debounce_seconds = max(0.0, BURP_MCP_DEBOUNCE_WINDOW_MS / 1000.0)
    if debounce_seconds and last_call_at and (now - last_call_at) < debounce_seconds:
        time.sleep(max(0.0, debounce_seconds - (now - last_call_at)))

    result = call_mcp_tool(burp_mcp_config(tool_name), arguments)
    payload = {
        "capability": capability,
        "tool_name": tool_name,
        "arguments": arguments,
        "content_text": result.content_text.strip(),
        "structured_content": dict(result.structured_content or {}),
        "available_tools": list(result.available_tools or []),
        "server_name": result.server_name,
        "server_version": result.server_version,
        "protocol_version": result.protocol_version,
    }
    with _CACHE_LOCK:
        _TOOL_CALL_CACHE[cache_key] = (time.monotonic(), dict(payload))
        _LAST_CALL_AT[tool_name] = time.monotonic()
    return payload


def build_burp_capability_arguments(
    capability: str,
    *,
    count: int = 8,
    offset: int = 0,
    query: str = "",
    target_url: str = "",
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_capability = (capability or "").strip().lower()
    safe_count = max(1, min(int(count or 8), 20))
    safe_offset = max(0, int(offset or 0))
    request_payload = dict(payload or {})
    if normalized_capability in {"proxy_history", "scanner_issues", "repeater_context", "intruder_results", "collaborator_interactions"}:
        arguments = {"count": safe_count, "offset": safe_offset}
    elif normalized_capability == "regex_history_query":
        normalized_query = (query or target_url or "").strip()
        arguments = {"count": safe_count, "offset": safe_offset}
        if normalized_query:
            arguments.update({
                "query": normalized_query,
                "pattern": normalized_query,
                "regex": normalized_query,
                "search": normalized_query,
            })
    elif normalized_capability in {"active_editor", "project_options"}:
        arguments = {}
    elif normalized_capability == "send_to_repeater":
        request_text = str(
            request_payload.get("request_text")
            or request_payload.get("raw_request")
            or request_payload.get("request")
            or ""
        ).strip()
        tab_name = str(
            request_payload.get("tab_name")
            or request_payload.get("name")
            or request_payload.get("label")
            or "bridge-plan"
        ).strip()
        arguments = {
            "request": request_text,
            "raw_request": request_text,
            "request_text": request_text,
            "name": tab_name,
            "tab_name": tab_name,
            "label": tab_name,
            "comment": str(request_payload.get("summary") or request_payload.get("expected_signal") or "").strip(),
            "create_new_tab": True,
            "open_mode": "new-tab",
        }
        if target_url:
            arguments["target_url"] = target_url
            arguments["url"] = target_url
        if request_payload.get("issue_id"):
            arguments["issue_id"] = str(request_payload.get("issue_id") or "").strip()
    else:
        arguments = {
            "target_url": (target_url or "").strip(),
            "payload": request_payload,
        }
    if target_url and normalized_capability in {"scanner_issues", "proxy_history", "regex_history_query", "repeater_context"}:
        arguments.setdefault("target_url", target_url)
        arguments.setdefault("url", target_url)
    return arguments


def _tool_allowed(
    tool_name: str,
    capability: str,
    allowed_tools: set[str],
    allowed_capabilities: set[str],
) -> bool:
    normalized_tool = (tool_name or "").strip()
    normalized_capability = (capability or "").strip().lower()
    if normalized_tool in allowed_tools or normalized_capability in allowed_capabilities:
        return True
    if normalized_capability in READ_ONLY_CAPABILITIES:
        return True
    return not BURP_MCP_READ_ONLY_ONLY


def _looks_dangerous_tool(tool_name: str) -> bool:
    tokens = set((tool_name or "").strip().lower().replace("-", "_").split("_"))
    if not tokens:
        return False
    if not (tokens & _DANGEROUS_TOOL_TOKENS):
        return False
    return not tokens.issubset(_SAFE_ACTION_EXCEPTIONS)
