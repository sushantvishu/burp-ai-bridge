from typing import Any

from server.burp_mcp_adapter import call_burp_mcp_capability, inspect_burp_mcp_capabilities
from server.core.analysis_service import analyze_exchange, coerce_payload
from server.core.burp_action_service import burp_repeater_plan
from server.core.issue_workflow_service import upsert_issue_workflow
from server.core.repeater_tab_service import build_repeater_tab_specs
from server.mcp_client import MCPError


def open_repeater_plan(payload_like, advisory: dict | None = None, *, dispatch: bool = True) -> dict[str, Any]:
    payload = coerce_payload(payload_like)
    if advisory is None:
        advisory = analyze_exchange(payload)["advisory"]

    plan = burp_repeater_plan(payload, advisory=advisory)
    tabs = build_repeater_tab_specs(payload, plan)
    inspection = inspect_burp_mcp_capabilities()
    capability = (inspection.get("capability_map") or {}).get("send_to_repeater") or {}
    capability_allowed = bool(capability.get("allowed"))
    tool_name = capability.get("tool_name") or ""

    results: list[dict[str, Any]] = []
    opened_count = 0
    if dispatch and tabs and capability_allowed and tool_name:
        for item in tabs:
            result = _dispatch_repeater_tab(item, getattr(payload, "target_url", "") or "")
            results.append(result)
            if result.get("status") == "opened":
                opened_count += 1
    else:
        status = "ready"
        detail = "Repeater tab specs prepared."
        if not tabs:
            status = "empty"
            detail = "No baseline request or variant requests were available to open."
        elif dispatch and not capability_allowed:
            status = "blocked"
            detail = "Burp MCP send_to_repeater is blocked by the current bridge tool-permission policy."
        elif dispatch and not tool_name:
            status = "unavailable"
            detail = "Burp MCP did not advertise a send_to_repeater/open_in_repeater tool."
        for item in tabs:
            results.append({
                "tab_name": item.get("tab_name", ""),
                "status": status,
                "detail": detail,
                "tool_name": tool_name,
            })

    response = {
        "target_url": getattr(payload, "target_url", "") or "",
        "snapshot_id": getattr(payload, "snapshot_id", "") or "",
        "dashboard_issue": plan.get("dashboard_issue") or {},
        "related_scanner_issues": list(plan.get("related_scanner_issues") or [])[:4],
        "preferred_request_ref": plan.get("preferred_request_ref", ""),
        "analysis_backend": plan.get("analysis_backend", ""),
        "capability_allowed": capability_allowed,
        "tool_name": tool_name,
        "dispatch_requested": bool(dispatch),
        "opened_count": opened_count,
        "tabs": tabs,
        "results": results,
        "notes": _build_notes(plan, capability_allowed, tool_name),
    }
    workflow = upsert_issue_workflow(payload, plan=plan)
    response["workflow_id"] = workflow.get("workflow_id", "")
    response["workflow_status"] = workflow.get("status", "")
    return response

def _dispatch_repeater_tab(item: dict[str, Any], target_url: str) -> dict[str, Any]:
    payload = {
        "request": item.get("request_text", ""),
        "raw_request": item.get("request_text", ""),
        "request_text": item.get("request_text", ""),
        "name": item.get("tab_name", ""),
        "tab_name": item.get("tab_name", ""),
        "label": item.get("tab_name", ""),
        "summary": item.get("summary", ""),
        "expected_signal": item.get("expected_signal", ""),
        "request_ref": item.get("request_ref", ""),
        "issue_id": item.get("issue_id", ""),
        "create_new_tab": True,
        "open_mode": "new-tab",
    }
    try:
        result = call_burp_mcp_capability("send_to_repeater", target_url=target_url, payload=payload)
    except MCPError as exc:
        return {
            "tab_name": item.get("tab_name", ""),
            "status": "failed",
            "detail": str(exc),
            "tool_name": "",
        }
    return {
        "tab_name": item.get("tab_name", ""),
        "status": "opened",
        "detail": "Repeater tab dispatched through Burp MCP.",
        "tool_name": result.get("tool_name", ""),
    }


def _build_notes(plan: dict[str, Any], capability_allowed: bool, tool_name: str) -> list[str]:
    notes = []
    if capability_allowed and tool_name:
        notes.append(f"Burp MCP action capability available: {tool_name}.")
    else:
        notes.append("Enable BURP_MCP_ALLOWED_CAPABILITIES=send_to_repeater or BURP_MCP_ALLOWED_TOOLS=<tool-name> if you want the bridge to open Repeater tabs directly.")
    if plan.get("issue_chain_strategy"):
        notes.extend(list(plan.get("issue_chain_strategy") or [])[:2])
    return notes[:5]
