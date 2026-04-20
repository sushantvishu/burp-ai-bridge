from typing import Any


def build_burp_exporter_config() -> dict[str, Any]:
    return {
        "contract_version": "2026-03-31",
        "bridge_endpoint": "/api/analyze/jobs",
        "required_fields": ["source_tool", "target_url", "use_burp_mcp_context"],
        "default_flags": {"use_burp_mcp_context": True},
        "source_tool_map": {
            "Proxy": "proxy",
            "Logger": "logger",
            "Repeater": "repeater",
            "Intruder": "intruder",
            "Scanner": "scanner",
            "Target": "target",
        },
        "macro_template": {
            "method": "POST",
            "path": "/api/analyze/jobs",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "raw_request": "<request_text>",
                "raw_response": "<response_text>",
                "target_url": "<target_url>",
                "http_method": "<http_method>",
                "source_tool": "repeater",
                "use_burp_mcp_context": True,
            },
        },
        "notes": [
            "Always send source_tool from the originating Burp tab or feature so the bridge can bias the next-step plan correctly.",
            "Always send target_url even when the request line already contains the path so live Burp MCP queries can focus on the right asset.",
            "Set use_burp_mcp_context=true for Burp-originated requests so the bridge can hydrate scanner issue details, history, and project options deterministically.",
            "Prefer the async jobs endpoint for extension or IDE-driven flows.",
        ],
    }
