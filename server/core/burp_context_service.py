from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse

from server.burp_mcp_context import augment_payload_with_burp_mcp


def get_dashboard_issue_context(payload_like) -> dict:
    payload = _coerce_payload(payload_like)
    issue = payload.burp_dashboard_issue if isinstance(payload.burp_dashboard_issue, dict) else {}
    target_url = _trim(issue.get("url") or issue.get("target_url") or payload.target_url)
    parsed = urlparse(target_url) if target_url else None
    issue_name = _trim(issue.get("name") or issue.get("title") or issue.get("issue_name"))
    severity = _trim(issue.get("severity") or issue.get("issue_severity")).lower()
    confidence = _trim(issue.get("confidence") or issue.get("issue_confidence")).lower()
    detail = _trim(issue.get("detail") or issue.get("issue_detail"), 480)
    background = _trim(issue.get("background") or issue.get("issue_background"), 320)
    remediation = _trim(issue.get("remediation") or issue.get("issue_remediation"), 240)
    raw_affected_urls = issue.get("affected_urls") or issue.get("urls")
    if not raw_affected_urls and issue and target_url:
        raw_affected_urls = [target_url]
    affected_urls = _normalize_string_list(raw_affected_urls or [], 6, 180)
    evidence = _normalize_string_list(issue.get("evidence") or issue.get("evidence_items") or [], 6, 220)
    request_refs = _normalize_string_list(issue.get("request_refs") or issue.get("requests") or [], 4, 120)
    response_refs = _normalize_string_list(issue.get("response_refs") or issue.get("responses") or [], 4, 120)
    found = any((issue_name, severity, confidence, detail, background, remediation, evidence, request_refs, response_refs))

    return {
        "found": found,
        "issue_id": _trim(issue.get("issue_id") or issue.get("id") or issue.get("issueId"), 80),
        "issue_name": issue_name,
        "severity": severity or "info",
        "confidence": confidence or "tentative",
        "host": parsed.netloc if parsed else "",
        "path": parsed.path if parsed else "",
        "target_url": target_url,
        "affected_urls": affected_urls,
        "background": background,
        "detail": detail,
        "remediation": remediation,
        "evidence_items": evidence,
        "request_refs": request_refs,
        "response_refs": response_refs,
        "vuln_hint": _infer_vuln_hint(issue_name, detail),
    }


def get_related_dashboard_issue_contexts(payload_like, limit: int = 4) -> list[dict]:
    payload = _coerce_payload(payload_like)
    related = payload.burp_related_scanner_issues if isinstance(payload.burp_related_scanner_issues, list) else []
    contexts: list[dict] = []
    for item in related[: max(1, min(limit, 8))]:
        if not isinstance(item, dict):
            continue
        contexts.append(get_dashboard_issue_context({"target_url": payload.target_url, "burp_dashboard_issue": item}))
    return [item for item in contexts if item.get("found")]


def get_recent_proxy_history(payload_like, limit: int = 8) -> dict:
    payload = _coerce_payload(payload_like)
    entries = _normalize_burp_entries(payload.proxy_history_entries, limit=limit, source="proxy")
    if not entries and payload.evidence_timeline_entries:
        entries = [
            {
                "source": "timeline",
                "summary": item,
                "method": "",
                "url": "",
                "status_code": "",
                "notes": "",
                "request_ref": "",
                "response_ref": "",
                "timestamp": "",
            }
            for item in _normalize_string_list(payload.evidence_timeline_entries, limit, 220)
        ]
    return {
        "target_url": payload.target_url or "",
        "count": len(entries),
        "entries": entries,
    }


def get_logger_deltas(payload_like, limit: int = 8) -> dict:
    payload = _coerce_payload(payload_like)
    entries = _normalize_burp_entries(payload.logger_entries, limit=limit, source="logger")
    if not entries:
        summary = _trim(payload.logger_evidence_text, 320)
        if summary:
            entries = [{
                "source": "logger",
                "summary": summary,
                "method": "",
                "url": payload.target_url or "",
                "status_code": "",
                "notes": "",
                "request_ref": "",
                "response_ref": "",
                "timestamp": "",
            }]
    return {
        "target_url": payload.target_url or "",
        "count": len(entries),
        "entries": entries,
    }


def get_repeater_request(payload_like, limit: int = 3) -> dict:
    payload = _coerce_payload(payload_like)
    entries = _normalize_burp_entries(payload.repeater_requests, limit=limit, source="repeater")
    if not entries and (payload.raw_request or payload.raw_response):
        entries = [{
            "source": payload.source_tool or "repeater",
            "summary": _trim(payload.annotations[0] if payload.annotations else "current assessment request", 180),
            "method": payload.http_method or _request_method(payload.raw_request),
            "url": payload.target_url or "",
            "status_code": "",
            "notes": "",
            "request_ref": "inline-request",
            "response_ref": "inline-response" if payload.raw_response else "",
            "timestamp": "",
        }]
    primary = entries[0] if entries else {}
    return {
        "target_url": payload.target_url or "",
        "count": len(entries),
        "primary_request": primary,
        "entries": entries,
    }


def get_project_config_snapshot(payload_like) -> dict:
    payload = _coerce_payload(payload_like)
    snapshot = payload.project_config_snapshot if isinstance(payload.project_config_snapshot, dict) else {}
    enabled_tools = _normalize_string_list(
        snapshot.get("enabled_tools") or _split_lines(payload.loaded_burp_tools_text),
        16,
        80,
    )
    scope_includes = _normalize_string_list(
        snapshot.get("scope_includes") or payload.review_scope_include_classes or _split_lines(payload.scope_includes_text),
        12,
        120,
    )
    scope_excludes = _normalize_string_list(
        snapshot.get("scope_excludes") or payload.review_scope_exclude_classes or _split_lines(payload.scope_excludes_text),
        12,
        120,
    )
    config_warnings = _normalize_string_list(
        snapshot.get("warnings") or _split_lines(payload.burp_screenshot_audit_text),
        10,
        180,
    )
    return {
        "selected_profile": payload.selected_profile or snapshot.get("selected_profile") or "",
        "enabled_tools": enabled_tools,
        "scope_includes": scope_includes,
        "scope_excludes": scope_excludes,
        "rate_limit_notes": _trim(snapshot.get("rate_limit_notes") or payload.rate_limit_text, 220),
        "concurrency_notes": _trim(snapshot.get("concurrency_notes") or payload.max_concurrency_text, 220),
        "custom_headers_notes": _trim(snapshot.get("custom_headers_notes") or payload.custom_headers_text, 220),
        "program_policy": _trim(snapshot.get("program_policy") or payload.program_policy_text or payload.saved_program_policy_text, 260),
        "config_warnings": config_warnings,
    }


def summarize_burp_context(payload_like) -> dict:
    payload = _coerce_payload(payload_like)
    issue = get_dashboard_issue_context(payload)
    related_issues = get_related_dashboard_issue_contexts(payload)
    proxy_history = get_recent_proxy_history(payload)
    logger_entries = get_logger_deltas(payload)
    repeater_requests = get_repeater_request(payload)
    project_config = get_project_config_snapshot(payload)
    return {
        "dashboard_issue": issue,
        "related_scanner_issue_count": len(related_issues),
        "related_scanner_issue_names": [item.get("issue_name", "") for item in related_issues[:4] if item.get("issue_name")],
        "proxy_history_count": proxy_history["count"],
        "logger_entry_count": logger_entries["count"],
        "repeater_request_count": repeater_requests["count"],
        "enabled_tool_count": len(project_config.get("enabled_tools") or []),
        "config_warning_count": len(project_config.get("config_warnings") or []),
    }


def _coerce_payload(payload_like) -> SimpleNamespace:
    if isinstance(payload_like, SimpleNamespace):
        source = dict(vars(payload_like))
    elif isinstance(payload_like, dict):
        source = dict(payload_like)
    elif hasattr(payload_like, "model_dump"):
        source = payload_like.model_dump()
    elif hasattr(payload_like, "dict"):
        source = payload_like.dict()
    else:
        source = dict(vars(payload_like))
    source = augment_payload_with_burp_mcp(source)
    return SimpleNamespace(
        raw_request=source.get("raw_request", "") or "",
        raw_response=source.get("raw_response", "") or "",
        target_url=source.get("target_url", "") or "",
        http_method=source.get("http_method", "") or "",
        source_tool=source.get("source_tool", "") or "",
        use_burp_mcp_context=bool(source.get("use_burp_mcp_context")),
        annotations=list(source.get("annotations", []) or []),
        review_scope_include_classes=list(source.get("review_scope_include_classes", []) or []),
        review_scope_exclude_classes=list(source.get("review_scope_exclude_classes", []) or []),
        evidence_timeline_entries=list(source.get("evidence_timeline_entries", []) or []),
        logger_evidence_text=source.get("logger_evidence_text", "") or "",
        loaded_burp_tools_text=source.get("loaded_burp_tools_text", "") or "",
        burp_screenshot_audit_text=source.get("burp_screenshot_audit_text", "") or "",
        scope_includes_text=source.get("scope_includes_text", "") or "",
        scope_excludes_text=source.get("scope_excludes_text", "") or "",
        rate_limit_text=source.get("rate_limit_text", "") or "",
        max_concurrency_text=source.get("max_concurrency_text", "") or "",
        custom_headers_text=source.get("custom_headers_text", "") or "",
        program_policy_text=source.get("program_policy_text", "") or "",
        burp_config_export_text=source.get("burp_config_export_text", "") or "",
        saved_program_policy_text=source.get("saved_program_policy_text", "") or "",
        selected_profile=source.get("selected_profile", "") or "",
        burp_mcp_context_checked=bool(source.get("burp_mcp_context_checked")),
        burp_mcp_context_applied=bool(source.get("burp_mcp_context_applied")),
        burp_mcp_context_status=source.get("burp_mcp_context_status", "") or "",
        burp_dashboard_issue=source.get("burp_dashboard_issue", {}) or {},
        burp_related_scanner_issues=list(source.get("burp_related_scanner_issues", []) or []),
        proxy_history_entries=list(source.get("proxy_history_entries", []) or []),
        logger_entries=list(source.get("logger_entries", []) or []),
        repeater_requests=list(source.get("repeater_requests", []) or []),
        project_config_snapshot=source.get("project_config_snapshot", {}) or {},
    )


def _normalize_burp_entries(raw_entries: Any, limit: int, source: str) -> list[dict]:
    entries: list[dict] = []
    for raw in list(raw_entries or [])[:max(1, min(limit, 20))]:
        if isinstance(raw, dict):
            summary = _trim(raw.get("summary") or raw.get("notes") or raw.get("url") or raw.get("request_ref"), 220)
            entries.append({
                "source": _trim(raw.get("source") or source, 40),
                "summary": summary,
                "method": _trim(raw.get("method"), 16),
                "url": _trim(raw.get("url"), 200),
                "status_code": str(raw.get("status_code") or raw.get("status") or ""),
                "notes": _trim(raw.get("notes"), 180),
                "request_ref": _trim(raw.get("request_ref"), 120),
                "response_ref": _trim(raw.get("response_ref"), 120),
                "timestamp": _trim(raw.get("timestamp"), 64),
            })
        elif isinstance(raw, str):
            entries.append({
                "source": source,
                "summary": _trim(raw, 220),
                "method": "",
                "url": "",
                "status_code": "",
                "notes": "",
                "request_ref": "",
                "response_ref": "",
                "timestamp": "",
            })
    return [item for item in entries if item.get("summary") or item.get("url")]


def _normalize_string_list(raw_items: Any, limit: int, max_length: int) -> list[str]:
    items: list[str] = []
    for raw in list(raw_items or [])[:max(1, min(limit, 20))]:
        normalized = _trim(raw, max_length)
        if normalized:
            items.append(normalized)
    return items


def _split_lines(value: str) -> list[str]:
    return [line.strip() for line in (value or "").splitlines() if line.strip()]


def _request_method(raw_request: str) -> str:
    lines = (raw_request or "").splitlines()
    first_line = lines[0] if lines else ""
    parts = first_line.split()
    return parts[0].upper() if parts else ""


def _infer_vuln_hint(issue_name: str, detail: str) -> str:
    normalized = f"{issue_name} {detail}".lower()
    for token in ("idor", "direct object reference", "access control", "privilege", "authorization"):
        if token in normalized:
            return "authorization"
    for token in ("xss", "cross-site scripting", "html injection"):
        if token in normalized:
            return "xss"
    for token in ("csrf", "request forgery"):
        if token in normalized:
            return "csrf"
    for token in ("ssrf", "server-side request forgery"):
        if token in normalized:
            return "ssrf"
    for token in ("sqli", "sql injection", "injection"):
        if token in normalized:
            return "injection"
    return "general"


def _trim(value: Any, max_length: int = 160) -> str:
    normalized = str(value or "").strip()
    if len(normalized) <= max_length:
        return normalized
    return normalized[: max_length - 3].rstrip() + "..."
