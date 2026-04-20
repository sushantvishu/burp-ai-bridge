from dataclasses import dataclass
from typing import Any, Callable


ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(slots=True)
class ToolDefinition:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolHandler


def payload_schema(required: bool = True) -> dict[str, Any]:
    schema = {
        "type": "object",
        "properties": {
            "raw_request": {"type": "string"},
            "raw_response": {"type": "string"},
            "target_url": {"type": "string"},
            "http_method": {"type": "string"},
            "source_tool": {"type": "string"},
            "use_burp_mcp_context": {"type": "boolean"},
            "enable_js_endpoint_extraction": {"type": "boolean"},
            "enable_race_signal_checks": {"type": "boolean"},
            "annotations": {"type": "array", "items": {"type": "string"}},
            "operator_answers": {"type": "object"},
            "tool_help_text": {"type": "string"},
            "scope_includes_text": {"type": "string"},
            "scope_excludes_text": {"type": "string"},
            "rate_limit_text": {"type": "string"},
            "max_concurrency_text": {"type": "string"},
            "custom_headers_text": {"type": "string"},
            "program_policy_text": {"type": "string"},
            "program_platform": {"type": "string"},
            "program_policy_template": {"type": "string"},
            "tool_results_text": {"type": "string"},
            "burp_config_export_text": {"type": "string"},
            "burp_screenshot_audit_text": {"type": "string"},
            "loaded_burp_tools_text": {"type": "string"},
            "saved_program_policy_text": {"type": "string"},
            "program_screenshot_audit_text": {"type": "string"},
            "response_delta_text": {"type": "string"},
            "evidence_timeline_entries": {"type": "array", "items": {"type": "string"}},
            "bapp_findings_text": {"type": "string"},
            "logger_evidence_text": {"type": "string"},
            "collaborator_evidence_text": {"type": "string"},
            "privacy_mode_override": {"type": "string"},
            "selected_profile": {"type": "string"},
            "review_scope_include_classes": {"type": "array", "items": {"type": "string"}},
            "review_scope_exclude_classes": {"type": "array", "items": {"type": "string"}},
            "browser_verification_allowed": {"type": "boolean"},
            "browser_allowed_workflows": {"type": "array", "items": {"type": "string"}},
            "browser_verification_notes": {"type": "string"},
            "baseline_response_text": {"type": "string"},
            "issue_workflow_notes": {"type": "array", "items": {"type": "string"}},
            "investigation_notebook_text": {"type": "string"},
            "repeater_variant_observations": {"type": "array", "items": {"type": "object"}},
            "burp_dashboard_issue": {"type": "object"},
            "burp_related_scanner_issues": {"type": "array", "items": {"type": "object"}},
            "proxy_history_entries": {"type": "array", "items": {"type": "object"}},
            "logger_entries": {"type": "array", "items": {"type": "object"}},
            "repeater_requests": {"type": "array", "items": {"type": "object"}},
            "project_config_snapshot": {"type": "object"},
        },
    }
    if required:
        schema["required"] = ["raw_request"]
    return schema


def extract_payload(arguments: dict[str, Any]) -> dict[str, Any]:
    payload = arguments.get("payload")
    if isinstance(payload, dict):
        return payload
    return dict(arguments)


def parse_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        normalized = int(value)
    except (TypeError, ValueError):
        normalized = default
    return max(minimum, min(normalized, maximum))
