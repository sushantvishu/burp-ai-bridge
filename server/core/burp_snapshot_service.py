import json
import uuid
from datetime import datetime, timezone
from typing import Any

from server.burp_mcp_adapter import call_burp_mcp_capability, inspect_burp_mcp_capabilities
from server.burp_mcp_context import augment_payload_with_burp_mcp
from server.capabilities.burp import normalize_burp_payload_contract
from server.core.burp_context_service import (
    get_dashboard_issue_context,
    get_related_dashboard_issue_contexts,
    get_project_config_snapshot,
    get_recent_proxy_history,
    get_repeater_request,
)
from server.state.store import append_burp_session_snapshot


def build_burp_session_snapshot(payload_like, *, persist: bool = True) -> dict[str, Any]:
    payload = normalize_burp_payload_contract(payload_like)
    payload["use_burp_mcp_context"] = True
    payload = augment_payload_with_burp_mcp(payload)
    payload["burp_mcp_context_applied"] = True

    issue_context = get_dashboard_issue_context(payload)
    related_issue_contexts = get_related_dashboard_issue_contexts(payload)
    proxy_history = get_recent_proxy_history(payload, limit=6)
    repeater_context = get_repeater_request(payload, limit=4)
    project_config = get_project_config_snapshot(payload)
    capability_summary = inspect_burp_mcp_capabilities()

    active_editor_request = _capability_text("active_editor")
    regex_history = _capability_records(
        "regex_history_query",
        target_url=payload.get("target_url") or "",
        query=_history_query(payload),
    )
    collaborator = []
    if issue_context.get("vuln_hint") in {"ssrf", "xxe"}:
        collaborator = _capability_records("collaborator_interactions", target_url=payload.get("target_url") or "")

    snapshot = {
        "snapshot_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target_url": payload.get("target_url") or "",
        "http_method": payload.get("http_method") or "",
        "source_tool": payload.get("source_tool") or "",
        "use_burp_mcp_context": True,
        "issue_context": issue_context,
        "scanner_details": {
            "issue_id": issue_context.get("issue_id", ""),
            "issue_name": issue_context.get("issue_name", ""),
            "severity": issue_context.get("severity", ""),
            "confidence": issue_context.get("confidence", ""),
            "detail": issue_context.get("detail", ""),
            "background": issue_context.get("background", ""),
            "remediation": issue_context.get("remediation", ""),
            "affected_urls": list(issue_context.get("affected_urls") or [])[:6],
            "evidence_items": list(issue_context.get("evidence_items") or [])[:8],
            "request_refs": list(issue_context.get("request_refs") or [])[:8],
            "response_refs": list(issue_context.get("response_refs") or [])[:8],
            "highlights": list((payload.get("burp_dashboard_issue") or {}).get("highlights") or [])[:8],
            "scanner_requests": list((payload.get("burp_dashboard_issue") or {}).get("scanner_requests") or [])[:8],
            "related_issues": related_issue_contexts[:4],
        },
        "proxy_history": proxy_history,
        "repeater_context": repeater_context,
        "project_config": project_config,
        "active_editor_request": active_editor_request,
        "regex_history_matches": regex_history[:8],
        "collaborator_interactions": collaborator[:8],
        "mcp_summary": {
            "server_name": capability_summary.get("server_name", ""),
            "server_version": capability_summary.get("server_version", ""),
            "permitted_tools": list(capability_summary.get("permitted_tools") or [])[:12],
            "blocked_tools": list(capability_summary.get("blocked_tools") or [])[:12],
            "read_only_only": bool(capability_summary.get("read_only_only", True)),
        },
        "evidence_bundle": _build_evidence_bundle(payload, issue_context, proxy_history, repeater_context, active_editor_request, regex_history),
        "analysis_payload": {
            "target_url": payload.get("target_url") or "",
            "http_method": payload.get("http_method") or "",
            "source_tool": payload.get("source_tool") or "",
            "use_burp_mcp_context": True,
            "raw_request": payload.get("raw_request") or active_editor_request,
            "raw_response": payload.get("raw_response") or "",
            "burp_dashboard_issue": payload.get("burp_dashboard_issue") or {},
            "burp_related_scanner_issues": list((payload.get("burp_related_scanner_issues") or related_issue_contexts or [])[:4]),
            "proxy_history_entries": list((payload.get("proxy_history_entries") or proxy_history.get("entries") or [])[:8]),
            "repeater_requests": list((payload.get("repeater_requests") or repeater_context.get("entries") or [])[:4]),
            "project_config_snapshot": payload.get("project_config_snapshot") or project_config,
        },
    }
    if persist:
        append_burp_session_snapshot(snapshot)
    return snapshot


def _capability_text(capability: str, *, target_url: str = "", query: str = "") -> str:
    try:
        result = call_burp_mcp_capability(capability, count=6, target_url=target_url, query=query)
    except Exception:
        return ""
    text = (result.get("content_text") or "").strip()
    if text:
        return text[:4000]
    structured = result.get("structured_content") or {}
    if not structured:
        return ""
    return json.dumps(structured, ensure_ascii=True)[:4000]


def _capability_records(capability: str, *, target_url: str = "", query: str = "") -> list[dict[str, Any]]:
    text = _capability_text(capability, target_url=target_url, query=query)
    if not text:
        return []
    return _parse_json_fragments(text)


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
            items.extend(item for item in value if isinstance(item, dict))
        elif isinstance(value, dict):
            items.append(value)
        index = next_index
    return items


def _build_evidence_bundle(
    payload: dict[str, Any],
    issue_context: dict[str, Any],
    proxy_history: dict[str, Any],
    repeater_context: dict[str, Any],
    active_editor_request: str,
    regex_history: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    bundle: list[dict[str, Any]] = []
    if issue_context.get("found"):
        bundle.append({
            "source": "burp-dashboard",
            "summary": issue_context.get("issue_name", ""),
            "detail": issue_context.get("detail", ""),
            "request_refs": list(issue_context.get("request_refs") or [])[:6],
            "response_refs": list(issue_context.get("response_refs") or [])[:6],
        })
    for entry in (proxy_history.get("entries") or [])[:3]:
        bundle.append({"source": "proxy", "summary": entry.get("summary", ""), "request_ref": entry.get("request_ref", "")})
    for entry in (repeater_context.get("entries") or [])[:2]:
        bundle.append({"source": "repeater", "summary": entry.get("summary", ""), "request_ref": entry.get("request_ref", "")})
    for entry in regex_history[:2]:
        bundle.append({"source": "regex-history", "summary": str(entry)[:240], "request_ref": str(entry.get("id") or "")})
    if active_editor_request:
        bundle.append({"source": "active-editor", "summary": active_editor_request.splitlines()[0][:180], "request_ref": "active-editor"})
    if not bundle and (payload.get("raw_request") or ""):
        bundle.append({"source": "payload", "summary": (payload.get("raw_request") or "").splitlines()[0][:180], "request_ref": "inline-request"})
    return bundle[:10]


def _history_query(payload: dict[str, Any]) -> str:
    target_url = (payload.get("target_url") or "").strip()
    if target_url:
        return target_url
    raw_request = (payload.get("raw_request") or "").strip().splitlines()
    return raw_request[0] if raw_request else ""
