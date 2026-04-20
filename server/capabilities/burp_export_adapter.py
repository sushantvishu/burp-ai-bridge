from typing import Any

from server.capabilities.burp import burp_payload_contract, normalize_burp_payload_contract
from server.capabilities.burp_exporter import build_burp_exporter_config


def prepare_burp_export_payload(payload_like) -> dict[str, Any]:
    payload = normalize_burp_payload_contract(payload_like)
    contract = burp_payload_contract()
    exporter = build_burp_exporter_config()

    dashboard_issue = payload.get("burp_dashboard_issue") or {}
    proxy_history = payload.get("proxy_history_entries") or []
    logger_entries = payload.get("logger_entries") or []
    repeater_requests = payload.get("repeater_requests") or []
    project_config = payload.get("project_config_snapshot") or {}
    if not payload.get("use_burp_mcp_context"):
        payload["use_burp_mcp_context"] = True
    if not payload.get("source_tool"):
        payload["source_tool"] = "repeater" if repeater_requests else "proxy"

    return {
        "contract_version": contract.get("contract_version", ""),
        "payload": payload,
        "summary": {
            "target_url": payload.get("target_url", ""),
            "http_method": payload.get("http_method", ""),
            "source_tool": payload.get("source_tool", ""),
            "dashboard_issue_found": bool(dashboard_issue),
            "proxy_history_count": len(proxy_history),
            "logger_entry_count": len(logger_entries),
            "repeater_request_count": len(repeater_requests),
            "enabled_tool_count": len(project_config.get("enabled_tools") or []),
        },
        "next_step": {
            "api_endpoint": "/api/analyze/jobs",
            "mcp_tool": "analyze_security_exchange",
            "notes": [
                "POST the normalized payload directly without reshaping the Burp fields again.",
                "Prefer the async jobs endpoint for IDE or extension flows so long-running local model calls do not block the client.",
                "Keep request/response refs and timestamps when available so phase history and evidence ranking stay useful.",
                "Prefer the burp_context envelope or the top-level normalized field names from the contract.",
                "Set use_burp_mcp_context=true for Burp-originated requests so live Burp context hydration stays predictable.",
            ],
        },
        "exporter": exporter,
    }
