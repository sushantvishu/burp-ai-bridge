from typing import Any


def build_burp_direct_submit_config() -> dict[str, Any]:
    python_sender_template = """import json
import requests

BRIDGE_BASE_URL = "http://127.0.0.1:8000"

def submit_selected_request(raw_request, raw_response="", target_url="", http_method="", source_tool="repeater"):
    payload = {
        "raw_request": raw_request,
        "raw_response": raw_response,
        "target_url": target_url,
        "http_method": http_method,
        "source_tool": source_tool,
        "use_burp_mcp_context": True,
    }
    response = requests.post(f"{BRIDGE_BASE_URL}/api/burp/submit-job", json=payload, timeout=20)
    response.raise_for_status()
    return response.json()
"""
    python_repeater_template = """import requests

BRIDGE_BASE_URL = "http://127.0.0.1:8000"

def open_plan_in_repeater(raw_request, raw_response="", target_url="", http_method="", source_tool="scanner"):
    payload = {
        "raw_request": raw_request,
        "raw_response": raw_response,
        "target_url": target_url,
        "http_method": http_method,
        "source_tool": source_tool,
        "use_burp_mcp_context": True,
    }
    response = requests.post(f"{BRIDGE_BASE_URL}/api/burp/open-repeater-plan", json=payload, timeout=20)
    response.raise_for_status()
    return response.json()
"""
    python_sync_template = """import requests

BRIDGE_BASE_URL = "http://127.0.0.1:8000"

def sync_selected_repeater_tabs(raw_request, baseline_response_text="", target_url="", source_tool="repeater", repeater_variant_observations=None):
    payload = {
        "raw_request": raw_request,
        "baseline_response_text": baseline_response_text,
        "target_url": target_url,
        "source_tool": source_tool,
        "use_burp_mcp_context": True,
        "repeater_variant_observations": repeater_variant_observations or [],
    }
    response = requests.post(f"{BRIDGE_BASE_URL}/api/burp/repeater-sync", json=payload, timeout=20)
    response.raise_for_status()
    return response.json()
"""
    python_panel_template = """import requests

BRIDGE_BASE_URL = "http://127.0.0.1:8000"

def refresh_panel_state(raw_request="", target_url="", issue_id="", snapshot_id="", workflow_id=""):
    payload = {
        "raw_request": raw_request,
        "target_url": target_url,
        "use_burp_mcp_context": True,
    }
    params = {
        "issue_id": issue_id,
        "snapshot_id": snapshot_id,
        "workflow_id": workflow_id,
    }
    response = requests.post(f"{BRIDGE_BASE_URL}/api/burp/panel-state", params=params, json=payload, timeout=20)
    response.raise_for_status()
    return response.json()
"""
    python_bcheck_result_template = """import requests

BRIDGE_BASE_URL = "http://127.0.0.1:8000"

def record_bcheck_result(target_url, selected_bcheck, outcome_label, raw_request="", issue_id="", notes="", evidence_signal=""):
    payload = {
        "raw_request": raw_request,
        "target_url": target_url,
        "issue_id": issue_id,
        "selected_bcheck": selected_bcheck,
        "outcome_label": outcome_label,
        "notes": notes,
        "evidence_signal": evidence_signal,
    }
    response = requests.post(f"{BRIDGE_BASE_URL}/api/bchecks/results", json=payload, timeout=20)
    response.raise_for_status()
    return response.json()
"""
    return {
        "submit_endpoint": "/api/burp/submit-job",
        "snapshot_endpoint": "/api/burp/session-snapshot",
        "open_repeater_plan_endpoint": "/api/burp/open-repeater-plan",
        "companion_config_endpoint": "/api/burp/companion-config",
        "companion_extension_endpoint": "/api/burp/companion-extension",
        "capability_recommendations_endpoint": "/api/burp/capability-recommendations",
        "bcheck_result_endpoint": "/api/bchecks/results",
        "model_options_endpoint": "/api/runtime/model-options",
        "model_selection_endpoint": "/api/runtime/model-selection",
        "panel_state_endpoint": "/api/burp/panel-state",
        "required_fields": ["raw_request", "target_url", "source_tool", "use_burp_mcp_context"],
        "default_payload": {
            "raw_request": "<request_text>",
            "raw_response": "<response_text>",
            "target_url": "<target_url>",
            "http_method": "<http_method>",
            "source_tool": "repeater",
            "use_burp_mcp_context": True,
        },
        "python_sender_template": python_sender_template,
        "python_repeater_template": python_repeater_template,
        "python_sync_template": python_sync_template,
        "python_panel_template": python_panel_template,
        "python_bcheck_result_template": python_bcheck_result_template,
        "notes": [
            "POST directly to /api/burp/submit-job from the selected Burp request or issue action.",
            "The bridge will capture a bounded Burp session snapshot first and then submit the analysis job with snapshot_id attached.",
            "Keep source_tool aligned with the Burp origin, for example proxy, repeater, intruder, or scanner.",
            "POST to /api/burp/open-repeater-plan when you want the bridge to create one Burp Repeater tab per planned variant.",
            "POST to /api/burp/repeater-sync when you want one API call that scores selected Repeater responses, refreshes issue workflow state, and returns the best next tab.",
            "POST to /api/burp/panel-state when the Burp-side panel needs one compact state refresh for the current issue or selected request.",
            "POST to /api/burp/capability-recommendations when the panel needs a Burp-feature-aware recommendation for the current finding.",
            "POST to /api/bchecks/results after you import and run one official PortSwigger BCheck so the bridge can learn whether it was useful or noisy on this issue family.",
            "GET /api/runtime/model-options when the Burp-side settings panel needs the exact local Ollama tags it can switch to.",
            "POST /api/runtime/model-selection when the Burp-side settings panel needs to switch the active Ollama model without restarting the bridge server.",
            "Direct Repeater tab creation requires the PortSwigger MCP extension to advertise send_to_repeater/open_in_repeater and for the bridge allowlist to permit it.",
        ],
    }
