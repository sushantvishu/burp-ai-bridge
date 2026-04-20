from typing import Any

MAX_ISSUE_LIST_ITEMS = 12
MAX_ISSUE_TEXT_CHARS = 2400
MAX_ENTRY_TEXT_CHARS = 320
MAX_SCANNER_REQUEST_ITEMS = 4


def burp_payload_contract() -> dict:
    return {
        "contract_version": "2026-03-30",
        "description": "Normalized Burp-side payload contract for Dashboard, Proxy, Logger, Repeater, and project configuration context.",
        "transport": {
            "preferred_shape": "single JSON document with top-level request/response fields and optional burp_context envelope",
            "accepted_envelopes": ["burp_context", "context", "burp_export"],
        },
        "top_level_fields": {
            "raw_request": ["raw_request", "request", "request_text"],
            "raw_response": ["raw_response", "response", "response_text"],
            "target_url": ["target_url", "url"],
            "http_method": ["http_method", "method"],
            "source_tool": ["source_tool", "tool"],
            "use_burp_mcp_context": ["use_burp_mcp_context"],
            "enable_js_endpoint_extraction": ["enable_js_endpoint_extraction"],
            "enable_race_signal_checks": ["enable_race_signal_checks"],
            "program_platform": ["program_platform", "platform"],
            "program_policy_template": ["program_policy_template", "policy_template"],
            "browser_verification_allowed": ["browser_verification_allowed"],
            "browser_allowed_workflows": ["browser_allowed_workflows"],
            "baseline_response_text": ["baseline_response_text"],
            "issue_workflow_notes": ["issue_workflow_notes"],
            "investigation_notebook_text": ["investigation_notebook_text", "case_notebook", "investigation_notebook"],
            "repeater_variant_observations": ["repeater_variant_observations", "variant_observations"],
            "burp_dashboard_issue": ["burp_dashboard_issue", "dashboard_issue", "issue", "issue_context"],
            "burp_related_scanner_issues": ["burp_related_scanner_issues", "related_scanner_issues", "issue_relations"],
            "proxy_history_entries": ["proxy_history_entries", "proxy_history", "http_history"],
            "logger_entries": ["logger_entries", "logger", "logger_deltas"],
            "repeater_requests": ["repeater_requests", "repeater", "repeater_tabs"],
            "project_config_snapshot": ["project_config_snapshot", "project_config", "project_options"],
        },
        "phase_intent": {
            "ingest": ["raw_request", "raw_response", "target_url", "http_method", "source_tool", "use_burp_mcp_context"],
            "enrich": ["burp_dashboard_issue", "burp_related_scanner_issues", "proxy_history_entries", "logger_entries", "repeater_requests", "project_config_snapshot", "baseline_response_text", "repeater_variant_observations"],
        },
        "issue_fields": {
            "issue_id": ["issue_id", "id", "issueId", "serialNumber"],
            "issue_name": ["name", "title", "issue_name"],
            "severity": ["severity", "issue_severity"],
            "confidence": ["confidence", "issue_confidence"],
            "detail": ["detail", "issue_detail", "description"],
            "background": ["background", "issue_background"],
            "remediation": ["remediation", "issue_remediation"],
            "affected_urls": ["affected_urls", "urls"],
            "evidence_items": ["evidence", "evidence_items"],
            "request_refs": ["request_refs", "requests"],
            "response_refs": ["response_refs", "responses"],
        },
        "entry_fields": {
            "summary": ["summary", "notes", "message"],
            "method": ["method"],
            "url": ["url", "target_url"],
            "status_code": ["status_code", "status"],
            "request_ref": ["request_ref", "request_id"],
            "response_ref": ["response_ref", "response_id"],
            "timestamp": ["timestamp", "time"],
        },
        "examples": {
            "dashboard_issue": {
                "issue_id": "issue-123",
                "name": "Insecure direct object reference",
                "severity": "high",
                "confidence": "firm",
                "detail": "User profile content changes across accounts.",
                "request_refs": ["proxy-481"],
            },
            "proxy_history_entry": {
                "method": "GET",
                "url": "https://target.example/api/users/123",
                "status_code": 200,
                "summary": "Role A baseline response",
                "timestamp": "2026-03-30T00:20:00Z",
            },
            "burp_macro_body": {
                "source_tool": "repeater",
                "target_url": "https://target.example/api/users/123",
                "use_burp_mcp_context": True,
            },
        },
    }


def normalize_burp_payload_contract(payload_like) -> dict[str, Any]:
    source = _to_dict(payload_like)
    source = _merge_envelope(source)
    normalized = dict(source)

    normalized["raw_request"] = _first_value(source, "raw_request", "request", "request_text") or ""
    normalized["raw_response"] = _first_value(source, "raw_response", "response", "response_text") or ""
    normalized["target_url"] = _first_value(source, "target_url", "url") or ""
    normalized["http_method"] = _first_value(source, "http_method", "method") or ""
    normalized["source_tool"] = _first_value(source, "source_tool", "tool") or ""
    normalized["use_burp_mcp_context"] = bool(_first_value(source, "use_burp_mcp_context"))
    normalized["enable_js_endpoint_extraction"] = bool(_first_value(source, "enable_js_endpoint_extraction"))
    normalized["enable_race_signal_checks"] = bool(_first_value(source, "enable_race_signal_checks"))
    normalized["baseline_response_text"] = _first_value(source, "baseline_response_text") or ""
    normalized["issue_workflow_notes"] = list(_first_value(source, "issue_workflow_notes") or [])
    normalized["investigation_notebook_text"] = _first_value(
        source,
        "investigation_notebook_text",
        "case_notebook",
        "investigation_notebook",
    ) or ""
    normalized["repeater_variant_observations"] = list(_first_value(source, "repeater_variant_observations", "variant_observations") or [])

    normalized["burp_dashboard_issue"] = _normalize_issue(
        _first_value(source, "burp_dashboard_issue", "dashboard_issue", "issue", "issue_context")
    )
    normalized["burp_related_scanner_issues"] = _normalize_issue_list(
        _first_value(source, "burp_related_scanner_issues", "related_scanner_issues", "issue_relations")
    )
    normalized["proxy_history_entries"] = _normalize_entries(
        _first_value(source, "proxy_history_entries", "proxy_history", "http_history")
    )
    normalized["logger_entries"] = _normalize_entries(
        _first_value(source, "logger_entries", "logger", "logger_deltas")
    )
    normalized["repeater_requests"] = _normalize_entries(
        _first_value(source, "repeater_requests", "repeater", "repeater_tabs")
    )
    normalized["project_config_snapshot"] = _normalize_project_config(
        _first_value(source, "project_config_snapshot", "project_config", "project_options")
    )

    if not normalized["logger_entries"] and isinstance(source.get("logger_evidence_text"), str):
        normalized["logger_entries"] = [{"summary": source.get("logger_evidence_text", "")}]

    if not normalized["source_tool"]:
        if normalized["repeater_requests"]:
            normalized["source_tool"] = "repeater"
        elif normalized["logger_entries"]:
            normalized["source_tool"] = "logger"
        elif normalized["proxy_history_entries"]:
            normalized["source_tool"] = "proxy"
        elif normalized["burp_dashboard_issue"]:
            normalized["source_tool"] = "scanner"

    if (
        normalized["source_tool"]
        and any(token in normalized["source_tool"].lower() for token in ("burp", "proxy", "logger", "repeater", "scanner", "intruder"))
        and (
            normalized["burp_dashboard_issue"]
            or normalized["proxy_history_entries"]
            or normalized["logger_entries"]
            or normalized["repeater_requests"]
            or normalized["project_config_snapshot"]
        )
    ):
        normalized["use_burp_mcp_context"] = True

    return normalized


def _normalize_issue(raw_issue: Any) -> dict[str, Any]:
    if isinstance(raw_issue, dict):
        raw_issue = _merge_issue_envelope(raw_issue)
    if not isinstance(raw_issue, dict):
        return {}
    return {
        "issue_id": _first_value(raw_issue, "issue_id", "id", "issueId", "serialNumber") or "",
        "name": _first_value(raw_issue, "name", "title", "issue_name") or "",
        "severity": _first_value(raw_issue, "severity", "issue_severity") or "",
        "confidence": _first_value(raw_issue, "confidence", "issue_confidence") or "",
        "detail": _trim_text(_first_value(raw_issue, "detail", "issue_detail", "description"), MAX_ISSUE_TEXT_CHARS),
        "background": _trim_text(_first_value(raw_issue, "background", "issue_background"), MAX_ISSUE_TEXT_CHARS),
        "remediation": _trim_text(_first_value(raw_issue, "remediation", "issue_remediation"), MAX_ISSUE_TEXT_CHARS),
        "affected_urls": _normalize_string_list(_first_value(raw_issue, "affected_urls", "urls"), limit=8, max_chars=280),
        "evidence": _normalize_string_list(_first_value(raw_issue, "evidence", "evidence_items"), limit=8, max_chars=420),
        "request_refs": _normalize_string_list(_first_value(raw_issue, "request_refs", "requests"), limit=8, max_chars=120),
        "response_refs": _normalize_string_list(_first_value(raw_issue, "response_refs", "responses"), limit=8, max_chars=120),
        "highlights": normalize_issue_highlights(
            _first_value(raw_issue, "highlights", "markers", "requestMarkers", "responseMarkers") or []
        ),
        "scanner_requests": normalize_issue_scanner_requests(
            _first_value(raw_issue, "scanner_requests", "requestResponses", "requestMessages", "requests")
        ),
        "url": _trim_text(_first_value(raw_issue, "url", "target_url"), 280),
    }


def _normalize_issue_list(raw_issues: Any) -> list[dict[str, Any]]:
    if isinstance(raw_issues, dict):
        raw_issues = _first_value(raw_issues, "issues", "items", "related") or []
    if not isinstance(raw_issues, list):
        return []
    issues: list[dict[str, Any]] = []
    for item in raw_issues[:MAX_ISSUE_LIST_ITEMS]:
        normalized = _normalize_issue(item)
        if normalized.get("name") or normalized.get("detail") or normalized.get("url"):
            issues.append(normalized)
    return issues


def normalize_issue_highlights(raw_items: Any) -> list[dict[str, Any]]:
    if isinstance(raw_items, dict):
        raw_items = _first_value(raw_items, "items", "markers", "highlights") or []
    if not isinstance(raw_items, list):
        return []
    items: list[dict[str, Any]] = []
    for raw in raw_items[:16]:
        normalized = _normalize_highlight(raw)
        if normalized:
            items.append(normalized)
    return items


def _normalize_highlight(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        start_offset, end_offset = _extract_offset_range(raw)
        return {
            "text": str(raw.get("text") or raw.get("value") or raw.get("highlight") or raw.get("content") or "").strip(),
            "location": str(raw.get("location") or raw.get("part") or raw.get("section") or "").strip().lower(),
            "label": str(raw.get("label") or raw.get("name") or raw.get("type") or "").strip(),
            "selector": str(raw.get("selector") or raw.get("parameter") or raw.get("field") or "").strip(),
            "reason": str(raw.get("reason") or raw.get("description") or raw.get("comment") or "").strip(),
            "marker_type": str(raw.get("marker_type") or raw.get("markerType") or raw.get("kind") or "").strip(),
            "part": str(raw.get("part") or raw.get("source") or "").strip().lower(),
            "start_offset": start_offset,
            "end_offset": end_offset,
        }
    if isinstance(raw, (list, tuple)) and len(raw) >= 2:
        try:
            start_offset = int(raw[0])
            end_offset = int(raw[1])
        except (TypeError, ValueError):
            return {}
        return {
            "text": "",
            "location": "",
            "label": "",
            "selector": "",
            "reason": "",
            "marker_type": "",
            "part": "",
            "start_offset": start_offset,
            "end_offset": end_offset,
        }
    if isinstance(raw, str) and raw.strip():
        return {
            "text": raw.strip(),
            "location": "",
            "label": "",
            "selector": "",
            "reason": "",
            "marker_type": "",
            "part": "",
            "start_offset": -1,
            "end_offset": -1,
        }
    return {}


def _extract_offset_range(raw: dict[str, Any]) -> tuple[int, int]:
    start_value = _first_value(raw, "start_offset", "startOffset", "start", "from", "offset")
    end_value = _first_value(raw, "end_offset", "endOffset", "end", "to")
    if isinstance(_first_value(raw, "range", "offsets", "span"), (list, tuple)):
        pair = list(_first_value(raw, "range", "offsets", "span"))
        if len(pair) >= 2:
            start_value = pair[0]
            end_value = pair[1]
    try:
        start_offset = int(start_value)
    except (TypeError, ValueError):
        start_offset = -1
    try:
        end_offset = int(end_value)
    except (TypeError, ValueError):
        end_offset = -1
    return start_offset, end_offset


def _normalize_entries(raw_entries: Any) -> list[dict[str, Any]]:
    if isinstance(raw_entries, dict):
        raw_entries = _first_value(raw_entries, "entries", "items", "history") or []
    if not isinstance(raw_entries, list):
        return []
    entries: list[dict[str, Any]] = []
    for item in raw_entries[:MAX_ISSUE_LIST_ITEMS]:
        if isinstance(item, dict):
            entries.append({
                "summary": _trim_text(_first_value(item, "summary", "notes", "message"), MAX_ENTRY_TEXT_CHARS),
                "method": _trim_text(_first_value(item, "method"), 20),
                "url": _trim_text(_first_value(item, "url", "target_url"), 280),
                "status_code": _trim_text(_first_value(item, "status_code", "status"), 16),
                "notes": _trim_text(_first_value(item, "notes", "summary", "message"), MAX_ENTRY_TEXT_CHARS),
                "request_ref": _trim_text(_first_value(item, "request_ref", "request_id"), 120),
                "response_ref": _trim_text(_first_value(item, "response_ref", "response_id"), 120),
                "timestamp": _trim_text(_first_value(item, "timestamp", "time"), 64),
            })
        elif isinstance(item, str):
            entries.append({"summary": _trim_text(item, MAX_ENTRY_TEXT_CHARS)})
    return entries


def normalize_issue_scanner_requests(raw_items: Any, *, limit: int = MAX_SCANNER_REQUEST_ITEMS) -> list[dict[str, Any]]:
    if isinstance(raw_items, dict):
        raw_items = _first_value(raw_items, "items", "entries", "requests", "requestResponses") or []
    if not isinstance(raw_items, list):
        return []

    normalized: list[dict[str, Any]] = []
    safe_limit = max(1, min(int(limit or MAX_SCANNER_REQUEST_ITEMS), 8))
    for index, item in enumerate(raw_items[:safe_limit], start=1):
        if isinstance(item, str):
            text = _trim_text(item, MAX_ENTRY_TEXT_CHARS)
            if text:
                normalized.append({
                    "summary": text,
                    "method": "",
                    "url": "",
                    "status_code": "",
                    "request_ref": "",
                    "response_ref": "",
                    "has_request": False,
                    "has_response": False,
                })
            continue
        if not isinstance(item, dict):
            continue

        request = item.get("request") if isinstance(item.get("request"), dict) else {}
        response = item.get("response") if isinstance(item.get("response"), dict) else {}
        method = _trim_text(_first_value(item, "method", "requestMethod") or _first_value(request, "method"), 16)
        url = _trim_text(
            _first_value(item, "url", "targetUrl", "requestUrl")
            or _first_value(request, "url", "requestUrl"),
            280,
        )
        status_code = _trim_text(_first_value(item, "statusCode", "status") or _first_value(response, "statusCode", "status"), 16)
        request_ref = _trim_text(
            _first_value(item, "id", "request_id", "requestId", "messageId", "messageReference")
            or _first_value(request, "id", "requestId", "messageId"),
            120,
        )
        response_ref = _trim_text(
            _first_value(item, "response_id", "responseId")
            or _first_value(response, "id", "responseId", "messageId"),
            120,
        )
        summary = _trim_text(_first_value(item, "summary", "description", "note", "comment"), MAX_ENTRY_TEXT_CHARS)
        if not summary:
            parts = [method, url, status_code]
            summary = " ".join(part for part in parts if part).strip() or f"scanner-request-{index}"
        normalized.append({
            "summary": summary,
            "method": method,
            "url": url,
            "status_code": status_code,
            "request_ref": request_ref or f"scanner-request-{index}",
            "response_ref": response_ref,
            "has_request": bool(request or _first_value(item, "request", "requestText", "requestBytes")),
            "has_response": bool(response or _first_value(item, "response", "responseText", "responseBytes")),
        })

    return normalized


def _normalize_project_config(raw_config: Any) -> dict[str, Any]:
    if isinstance(raw_config, dict):
        raw_config = _merge_project_config_envelope(raw_config)
    if not isinstance(raw_config, dict):
        return {}
    return {
        "selected_profile": _first_value(raw_config, "selected_profile", "profile") or "",
        "enabled_tools": list(_first_value(raw_config, "enabled_tools", "loaded_tools") or []),
        "scope_includes": list(_first_value(raw_config, "scope_includes", "include_scope") or []),
        "scope_excludes": list(_first_value(raw_config, "scope_excludes", "exclude_scope") or []),
        "warnings": list(_first_value(raw_config, "warnings", "config_warnings") or []),
        "rate_limit_notes": _first_value(raw_config, "rate_limit_notes", "rate_limit") or "",
        "concurrency_notes": _first_value(raw_config, "concurrency_notes", "max_concurrency") or "",
        "custom_headers_notes": _first_value(raw_config, "custom_headers_notes", "custom_headers") or "",
        "program_policy": _first_value(raw_config, "program_policy", "policy") or "",
    }


def _to_dict(payload_like) -> dict[str, Any]:
    if isinstance(payload_like, dict):
        return dict(payload_like)
    if hasattr(payload_like, "__dict__"):
        try:
            source = dict(vars(payload_like))
            if source:
                return source
        except Exception:
            pass
    if hasattr(payload_like, "model_dump"):
        return payload_like.model_dump()
    if hasattr(payload_like, "dict"):
        return payload_like.dict()
    return dict(vars(payload_like))


def _first_value(source: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in source and source.get(name) is not None:
            return source.get(name)
    return None


def _merge_envelope(source: dict[str, Any]) -> dict[str, Any]:
    merged = dict(source)
    for envelope_name in ("burp_context", "context", "burp_export"):
        envelope = source.get(envelope_name)
        if isinstance(envelope, dict):
            for key, value in envelope.items():
                merged.setdefault(key, value)
    return merged


def _merge_issue_envelope(raw_issue: dict[str, Any]) -> dict[str, Any]:
    merged = dict(raw_issue)
    for envelope_name in ("selected_issue", "issue", "dashboard_issue"):
        envelope = raw_issue.get(envelope_name)
        if isinstance(envelope, dict):
            for key, value in envelope.items():
                merged.setdefault(key, value)
    return merged


def _merge_project_config_envelope(raw_config: dict[str, Any]) -> dict[str, Any]:
    merged = dict(raw_config)
    for envelope_name in ("project", "config", "options"):
        envelope = raw_config.get(envelope_name)
        if isinstance(envelope, dict):
            for key, value in envelope.items():
                merged.setdefault(key, value)
    return merged


def _normalize_string_list(raw_items: Any, *, limit: int, max_chars: int) -> list[str]:
    if not isinstance(raw_items, list):
        return []
    items: list[str] = []
    for value in raw_items[:max(1, min(limit, 20))]:
        normalized = _trim_text(value, max_chars)
        if normalized:
            items.append(normalized)
    return items


def _trim_text(value: Any, max_chars: int) -> str:
    text = str(value or "").strip()
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."
