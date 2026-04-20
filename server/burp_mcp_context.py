import json
from typing import Any
from urllib.parse import urlparse

from server.burp_mcp_adapter import (
    call_burp_mcp_capability,
    inspect_burp_mcp_capabilities,
)
from server.capabilities.burp import normalize_issue_highlights
from server.capabilities.burp import normalize_issue_scanner_requests
from server.mcp_client import MCPError
from server.settings import (
    BURP_MCP_CONTEXT_ENABLED,
    BURP_MCP_CONTEXT_HISTORY_LIMIT,
    BURP_MCP_FETCH_SCANNER_ISSUES,
)

_CAPABILITY_PROXY_HISTORY = "proxy_history"
_CAPABILITY_REGEX_HISTORY_QUERY = "regex_history_query"
_CAPABILITY_SCANNER_ISSUES = "scanner_issues"
_CAPABILITY_ACTIVE_EDITOR = "active_editor"
_CAPABILITY_PROJECT_OPTIONS = "project_options"
_CAPABILITY_REPEATER_CONTEXT = "repeater_context"
_CAPABILITY_COLLABORATOR = "collaborator_interactions"


def burp_mcp_context_enabled() -> bool:
    return BURP_MCP_CONTEXT_ENABLED


def inspect_burp_mcp_server() -> dict[str, Any]:
    if not BURP_MCP_CONTEXT_ENABLED:
        return {
            "enabled": False,
            "transport": "",
            "tool_name": "",
            "timeout_seconds": 0,
            "protocol_version": "",
            "url": "",
            "command": "",
            "working_directory": "",
            "status": "disabled",
            "detail": "Burp MCP context enrichment is disabled by configuration.",
            "available_tools": [],
            "server_name": "",
            "server_version": "",
            "read_only_only": True,
            "capability_map": {},
            "permitted_tools": [],
            "blocked_tools": [],
            "denied_capabilities": [],
        }
    try:
        inspection = inspect_burp_mcp_capabilities()
    except MCPError as exc:
        return {
            "enabled": True,
            "transport": "",
            "tool_name": "",
            "timeout_seconds": 0,
            "protocol_version": "",
            "url": "",
            "command": "",
            "working_directory": "",
            "status": "unreachable",
            "detail": str(exc),
            "available_tools": [],
            "server_name": "",
            "server_version": "",
            "read_only_only": True,
            "capability_map": {},
            "permitted_tools": [],
            "blocked_tools": [],
            "denied_capabilities": [],
        }
    return {
        "enabled": True,
        "transport": inspection.get("transport", ""),
        "tool_name": "",
        "timeout_seconds": inspection.get("timeout_seconds", 0),
        "protocol_version": inspection.get("protocol_version", ""),
        "url": inspection.get("url", ""),
        "command": inspection.get("command", ""),
        "working_directory": inspection.get("working_directory", ""),
        "status": "ready",
        "detail": f"Burp MCP responded and advertised {len(inspection.get('available_tools') or [])} tool(s).",
        "available_tools": list(inspection.get("available_tools") or [])[:32],
        "server_name": inspection.get("server_name", ""),
        "server_version": inspection.get("server_version", ""),
        "read_only_only": bool(inspection.get("read_only_only", True)),
        "capability_map": inspection.get("capability_map") or {},
        "permitted_tools": list(inspection.get("permitted_tools") or [])[:32],
        "blocked_tools": list(inspection.get("blocked_tools") or [])[:32],
        "denied_capabilities": list(inspection.get("denied_capabilities") or [])[:32],
    }


def augment_payload_with_burp_mcp(payload_like) -> dict[str, Any]:
    source = _to_payload_dict(payload_like)
    if not BURP_MCP_CONTEXT_ENABLED or source.get("burp_mcp_context_applied") or source.get("burp_mcp_context_checked"):
        return source
    if not _should_query_live_burp_context(source):
        source["burp_mcp_context_checked"] = True
        return source

    try:
        inspection = inspect_burp_mcp_capabilities()
    except MCPError as exc:
        source["burp_mcp_context_applied"] = True
        source["burp_mcp_context_status"] = f"unreachable: {exc}"
        source["burp_mcp_context_checked"] = True
        return source

    capability_map = inspection.get("capability_map") or {}
    notes: list[str] = []

    if not (source.get("raw_request") or "").strip() and capability_map.get(_CAPABILITY_ACTIVE_EDITOR, {}).get("allowed"):
        editor_text = _call_capability_text(_CAPABILITY_ACTIVE_EDITOR)
        if editor_text:
            source["raw_request"] = editor_text
            notes.append("raw_request loaded from Burp active editor via MCP")

    if not source.get("proxy_history_entries") and capability_map.get(_CAPABILITY_PROXY_HISTORY, {}).get("allowed"):
        history_text = _call_capability_text(
            _CAPABILITY_PROXY_HISTORY,
            count=max(1, BURP_MCP_CONTEXT_HISTORY_LIMIT),
            target_url=source.get("target_url") or "",
        )
        history_items = _parse_json_fragments(history_text)
        normalized_history = _normalize_history_items(history_items, source.get("target_url") or "")
        if normalized_history:
            source["proxy_history_entries"] = normalized_history[:BURP_MCP_CONTEXT_HISTORY_LIMIT]
            notes.append(f"proxy history hydrated from Burp MCP ({len(normalized_history[:BURP_MCP_CONTEXT_HISTORY_LIMIT])} items)")
            if not (source.get("raw_request") or "").strip():
                first_request = _extract_first_request_text(history_items)
                if first_request:
                    source["raw_request"] = first_request

    if BURP_MCP_FETCH_SCANNER_ISSUES and capability_map.get(_CAPABILITY_SCANNER_ISSUES, {}).get("allowed"):
        issues_text = _call_capability_text(
            _CAPABILITY_SCANNER_ISSUES,
            count=20,
            target_url=source.get("target_url") or "",
        )
        issues = _parse_json_fragments(issues_text)
        selected_issue, related_issues = _select_issue_bundle(
            issues,
            source.get("target_url") or "",
            source.get("burp_dashboard_issue") or {},
        )
        if selected_issue:
            if source.get("burp_dashboard_issue"):
                source["burp_dashboard_issue"] = _merge_issue_details(source.get("burp_dashboard_issue") or {}, selected_issue)
                notes.append("scanner issue refreshed from Burp MCP using pinned issue correlation")
            else:
                source["burp_dashboard_issue"] = selected_issue
                notes.append("scanner issue hydrated from Burp MCP")
        if related_issues:
            source["burp_related_scanner_issues"] = related_issues[:5]
            notes.append(f"related scanner issues correlated from Burp MCP ({len(related_issues[:5])} items)")

    if not (source.get("burp_config_export_text") or "").strip() and capability_map.get(_CAPABILITY_PROJECT_OPTIONS, {}).get("allowed"):
        project_options_text = _call_capability_text(_CAPABILITY_PROJECT_OPTIONS)
        if project_options_text:
            source["burp_config_export_text"] = project_options_text
            notes.append("project options exported from Burp MCP")

    if not source.get("repeater_requests") and capability_map.get(_CAPABILITY_REPEATER_CONTEXT, {}).get("allowed"):
        repeater_text = _call_capability_text(
            _CAPABILITY_REPEATER_CONTEXT,
            count=3,
            target_url=source.get("target_url") or "",
        )
        repeater_items = _parse_json_fragments(repeater_text)
        normalized_repeater = _normalize_history_items(repeater_items, source.get("target_url") or "")
        if normalized_repeater:
            source["repeater_requests"] = normalized_repeater[:3]
            notes.append(f"repeater context hydrated from Burp MCP ({len(source['repeater_requests'])} items)")

    target_url = (source.get("target_url") or "").strip()
    if target_url and not source.get("proxy_history_entries") and capability_map.get(_CAPABILITY_REGEX_HISTORY_QUERY, {}).get("allowed"):
        history_query_text = _call_capability_text(
            _CAPABILITY_REGEX_HISTORY_QUERY,
            count=max(1, BURP_MCP_CONTEXT_HISTORY_LIMIT),
            query=_regex_for_target(target_url),
            target_url=target_url,
        )
        regex_items = _parse_json_fragments(history_query_text)
        normalized_regex_items = _normalize_history_items(regex_items, target_url)
        if normalized_regex_items:
            source["proxy_history_entries"] = normalized_regex_items[:BURP_MCP_CONTEXT_HISTORY_LIMIT]
            notes.append("regex-matched Burp history hydrated from MCP")

    vuln_hint = str((source.get("burp_dashboard_issue") or {}).get("vuln_hint") or "").lower()
    if vuln_hint in {"ssrf", "xxe"} and capability_map.get(_CAPABILITY_COLLABORATOR, {}).get("allowed"):
        collaborator_text = _call_capability_text(_CAPABILITY_COLLABORATOR, count=6, target_url=target_url)
        if collaborator_text and not (source.get("collaborator_evidence_text") or "").strip():
            source["collaborator_evidence_text"] = collaborator_text[:1200]
            notes.append("collaborator interactions hydrated from Burp MCP")

    if notes:
        existing = (source.get("tool_results_text") or "").strip()
        note_block = "Burp MCP live context:\n- " + "\n- ".join(notes)
        source["tool_results_text"] = f"{existing}\n\n{note_block}".strip() if existing else note_block
    source["burp_mcp_context_applied"] = True
    source["burp_mcp_context_checked"] = True
    source["burp_mcp_context_status"] = "ready"
    return source


def _call_capability_text(capability: str, *, count: int = 8, query: str = "", target_url: str = "") -> str:
    try:
        result = call_burp_mcp_capability(
            capability,
            count=count,
            query=query,
            target_url=target_url,
        )
    except MCPError:
        return ""
    content_text = (result.get("content_text") or "").strip()
    if content_text:
        return content_text
    structured_content = result.get("structured_content") or {}
    if structured_content:
        return json.dumps(structured_content, ensure_ascii=True)
    return ""


def _parse_json_fragments(text: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    decoder = json.JSONDecoder()
    index = 0
    content = (text or "").strip()
    while index < len(content):
        while index < len(content) and content[index] not in "[{\"":
            index += 1
        if index >= len(content):
            break
        try:
            value, next_index = decoder.raw_decode(content, index)
        except json.JSONDecodeError:
            index += 1
            continue
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    items.append(item)
        elif isinstance(value, dict):
            items.append(value)
        index = next_index
    return items


def _normalize_history_items(items: list[dict[str, Any]], target_url: str) -> list[dict[str, Any]]:
    parsed_target = urlparse(target_url) if target_url else None
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(items, start=1):
        request = item.get("request") if isinstance(item.get("request"), dict) else {}
        response = item.get("response") if isinstance(item.get("response"), dict) else {}
        url = _first_value(item, "url", "targetUrl", "requestUrl") or _first_value(request, "url", "requestUrl")
        if parsed_target and url:
            parsed_url = urlparse(str(url))
            if parsed_url.netloc and parsed_url.netloc != parsed_target.netloc:
                continue
        method = _first_value(item, "method", "requestMethod") or _first_value(request, "method")
        status_code = _first_value(item, "statusCode", "status") or _first_value(response, "statusCode", "status")
        request_ref = str(_first_value(item, "id", "messageId", "messageReference") or f"burp-mcp-history-{index}")
        normalized.append({
            "source": "proxy",
            "summary": _build_history_summary(method, url, status_code),
            "method": str(method or ""),
            "url": str(url or ""),
            "status_code": str(status_code or ""),
            "notes": str(_first_value(item, "annotations", "comment", "highlight") or ""),
            "request_ref": request_ref,
            "response_ref": str(_first_value(response, "id", "messageId") or ""),
            "timestamp": str(_first_value(item, "timestamp", "time") or ""),
        })
    return normalized


def _select_issue_bundle(items: list[dict[str, Any]], target_url: str, existing_issue: dict[str, Any] | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    parsed_target = urlparse(target_url) if target_url else None
    normalized_items = []
    for item in items:
        normalized = _normalize_issue_record(item, target_url)
        if not normalized:
            continue
        issue_url = normalized.get("url") or ""
        if parsed_target and issue_url:
            parsed_issue = urlparse(issue_url)
            if parsed_issue.netloc and parsed_issue.netloc != parsed_target.netloc:
                continue
        normalized_items.append(normalized)

    anchor = _normalize_issue_record(existing_issue or {}, target_url) if existing_issue else {}
    selected = _match_issue_by_id(anchor, normalized_items) or anchor or _pick_primary_issue(normalized_items, target_url)
    if not selected:
        return {}, []

    related = []
    selected_key = _issue_identity(selected)
    for item in normalized_items:
        if _issue_identity(item) == selected_key:
            continue
        if _is_related_issue(selected, item, target_url):
            related.append(item)
    return selected, related[:5]


def _match_issue_by_id(anchor: dict[str, Any], items: list[dict[str, Any]]) -> dict[str, Any]:
    issue_id = str(anchor.get("issue_id") or "").strip()
    if not issue_id:
        return {}
    for item in items:
        if str(item.get("issue_id") or "").strip() == issue_id:
            return item
    return {}


def _normalize_issue_record(item: dict[str, Any], target_url: str) -> dict[str, Any]:
    issue_url = _first_value(item, "url", "origin", "baseUrl", "target_url")
    normalized = {
        "issue_id": str(_first_value(item, "issue_id", "id", "issueId", "serialNumber") or ""),
        "name": str(_first_value(item, "name", "title", "issueName", "issue_name") or ""),
        "severity": str(_first_value(item, "severity", "severityName", "issue_severity") or ""),
        "confidence": str(_first_value(item, "confidence", "confidenceName", "issue_confidence") or ""),
        "detail": str(_first_value(item, "detail", "description", "issue_detail") or ""),
        "background": str(_first_value(item, "background", "issue_background") or ""),
        "remediation": str(_first_value(item, "remediation", "issue_remediation") or ""),
        "affected_urls": _list_value(item, "urls", "affectedUrls", "affected_urls"),
        "evidence": _list_value(item, "evidence", "evidenceItems", "evidence_items"),
        "request_refs": _reference_list(item, "requestRefs", "request_refs", "requests", "requestResponses"),
        "response_refs": _reference_list(item, "responseRefs", "response_refs", "responses", "requestResponses"),
        "highlights": normalize_issue_highlights(_list_of_any(item, "highlights", "markers", "requestMarkers", "responseMarkers")),
        "scanner_requests": normalize_issue_scanner_requests(
            _first_value(item, "scanner_requests", "requestResponses", "requestMessages", "requests")
        ),
        "url": str(issue_url or target_url or ""),
    }
    if normalized["name"] or normalized["detail"] or normalized["url"]:
        if not normalized["affected_urls"] and normalized["url"]:
            normalized["affected_urls"] = [normalized["url"]]
        return normalized
    return {}


def _pick_primary_issue(items: list[dict[str, Any]], target_url: str) -> dict[str, Any]:
    if not items:
        return {}
    parsed_target = urlparse(target_url) if target_url else None

    def _rank(item: dict[str, Any]) -> tuple[int, int, int]:
        issue_url = item.get("url") or ""
        parsed_issue = urlparse(issue_url) if issue_url else None
        same_path = int(bool(parsed_target and parsed_issue and parsed_issue.path == parsed_target.path))
        same_host = int(bool(parsed_target and parsed_issue and parsed_issue.netloc == parsed_target.netloc))
        has_refs = int(bool(item.get("request_refs") or item.get("response_refs")))
        return same_path, same_host, has_refs

    return sorted(items, key=_rank, reverse=True)[0]


def _is_related_issue(selected: dict[str, Any], candidate: dict[str, Any], target_url: str) -> bool:
    selected_url = urlparse(selected.get("url") or target_url or "")
    candidate_url = urlparse(candidate.get("url") or target_url or "")
    if selected_url.netloc and candidate_url.netloc and selected_url.netloc != candidate_url.netloc:
        return False
    selected_refs = set(selected.get("request_refs") or [])
    candidate_refs = set(candidate.get("request_refs") or [])
    if selected_refs and candidate_refs and selected_refs.intersection(candidate_refs):
        return True
    selected_paths = {urlparse(url).path for url in (selected.get("affected_urls") or []) if url}
    candidate_paths = {urlparse(url).path for url in (candidate.get("affected_urls") or []) if url}
    if selected_paths and candidate_paths and selected_paths.intersection(candidate_paths):
        return True
    if selected_url.path and candidate_url.path and selected_url.path == candidate_url.path:
        return True
    return bool(
        selected_url.netloc
        and candidate_url.netloc
        and selected_url.netloc == candidate_url.netloc
        and _path_family(selected_url.path) == _path_family(candidate_url.path)
    )


def _issue_identity(item: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(item.get("issue_id") or "").strip().lower(),
        str(item.get("name") or "").strip().lower(),
        str(item.get("url") or "").strip().lower(),
        "|".join(str(ref).strip().lower() for ref in list(item.get("request_refs") or [])[:4]),
    )


def _path_family(path: str) -> str:
    segments = [segment for segment in (path or "").split("/") if segment]
    return segments[0].lower() if segments else ""


def _extract_first_request_text(items: list[dict[str, Any]]) -> str:
    for item in items:
        request = item.get("request")
        if isinstance(request, dict):
            text = _first_value(request, "content", "message", "raw")
            if text:
                return str(text)
        text = _first_value(item, "request", "requestText")
        if isinstance(text, str) and text.strip():
            return text
    return ""


def _build_history_summary(method: Any, url: Any, status_code: Any) -> str:
    parts = [str(method or "").strip(), str(url or "").strip(), str(status_code or "").strip()]
    return " ".join(part for part in parts if part).strip() or "Burp MCP proxy history entry"


def _should_query_live_burp_context(source: dict[str, Any]) -> bool:
    source_tool = str(source.get("source_tool") or "").strip().lower()
    if source.get("use_burp_mcp_context") is True:
        return True
    has_embedded_context = bool(
        (source.get("raw_request") or "").strip()
        or source.get("burp_dashboard_issue")
        or source.get("proxy_history_entries")
        or source.get("logger_entries")
        or source.get("repeater_requests")
        or source.get("project_config_snapshot")
        or (source.get("burp_config_export_text") or "").strip()
    )
    if any(token in source_tool for token in ("burp", "proxy", "repeater", "logger", "scanner")) and not has_embedded_context:
        return True
    return False


def _list_value(source: dict[str, Any], *keys: str) -> list[str]:
    for key in keys:
        value = source.get(key)
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
    return []


def _list_of_any(source: dict[str, Any], *keys: str) -> list[Any]:
    for key in keys:
        value = source.get(key)
        if isinstance(value, list):
            return list(value)
    return []


def _reference_list(source: dict[str, Any], *keys: str) -> list[str]:
    values = _list_of_any(source, *keys)
    refs: list[str] = []
    for item in values:
        if isinstance(item, dict):
            value = _first_value(item, "id", "requestId", "responseId", "messageId", "messageReference")
            if value:
                refs.append(str(value).strip())
        elif item is not None:
            normalized = str(item).strip()
            if normalized:
                refs.append(normalized)
    return refs


def _merge_issue_details(existing: dict[str, Any], refreshed: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing or {})
    for key, value in refreshed.items():
        current = merged.get(key)
        if key not in merged or current in ("", None) or current == [] or current == {}:
            merged[key] = value
            continue
        if isinstance(value, list) and value and not merged.get(key):
            merged[key] = value
    if refreshed.get("issue_id"):
        merged["issue_id"] = refreshed.get("issue_id")
    return merged


def _first_value(source: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in source and source.get(key) is not None:
            return source.get(key)
    return None


def _to_payload_dict(payload_like) -> dict[str, Any]:
    if isinstance(payload_like, dict):
        return dict(payload_like)
    if hasattr(payload_like, "model_dump"):
        return payload_like.model_dump()
    if hasattr(payload_like, "dict"):
        return payload_like.dict()
    return dict(vars(payload_like))


def _regex_for_target(target_url: str) -> str:
    parsed = urlparse(target_url)
    path = (parsed.path or "/").strip()
    if len(path) <= 1:
        return parsed.netloc
    segments = [segment for segment in path.split("/") if segment][:3]
    return "/".join(segments) if segments else parsed.netloc
