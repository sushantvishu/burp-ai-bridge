from __future__ import annotations

from pathlib import Path
from typing import Any


def build_burp_companion_extension_bundle() -> dict[str, Any]:
    samples_dir = Path(__file__).resolve().parents[1] / "samples" / "burp"
    docs_path = Path(__file__).resolve().parents[1] / "BURP_COMPANION_EXTENSION.md"
    assets_dir = Path(__file__).resolve().parents[1] / "burp_assets"
    return {
        "name": "burp-ai-bridge-companion",
        "panel_endpoint": "/api/burp/panel-state",
        "sync_endpoint": "/api/burp/repeater-sync",
        "open_repeater_plan_endpoint": "/api/burp/open-repeater-plan",
        "submit_job_endpoint": "/api/burp/submit-job",
        "capability_recommendations_endpoint": "/api/burp/capability-recommendations",
        "sample_paths": {
            "jython": str(samples_dir / "BurpAiBridgePanel.py"),
            "java": str(samples_dir / "BurpAiBridgePanel.java"),
            "montoya": str(samples_dir / "BurpAiBridgeMontoyaExtension.java"),
            "docs": str(docs_path),
        },
        "starter_asset_paths": {
            "root": str(assets_dir),
            "custom_scan_checks": str(assets_dir / "custom_scan_checks"),
            "bambda": str(assets_dir / "bambda"),
        },
        "recommended_actions": [
            "submit_scanner_issue",
            "open_repeater_plan",
            "sync_selected_repeater_tabs",
            "refresh_panel_state",
            "burp_capability_recommendations",
        ],
        "selected_message_fields": [
            "raw_request",
            "raw_response",
            "target_url",
            "http_method",
            "issue_id",
            "snapshot_id",
            "baseline_response_text",
            "repeater_variant_observations",
            "burp_dashboard_issue",
            "burp_related_scanner_issues",
        ],
        "workflow_loop": [
            "User selects a Burp Scanner issue or Repeater tab.",
            "Panel posts the selected request to /api/burp/open-repeater-plan when new mutations are needed.",
            "User sends one or more generated tabs in Repeater.",
            "Panel posts the returned request/response pairs to /api/burp/repeater-sync.",
            "Panel refreshes /api/burp/panel-state and renders strongest delta, workflow status, and best next tab.",
            "Panel can request /api/burp/capability-recommendations to show the best next Burp feature, starter scan checks, Bambdas, and bounded external tools.",
        ],
        "notes": [
            "The bundled Jython, legacy Java, and Montoya Java files are companion-extension templates, not signed production plugins.",
            "Use the Montoya Java sample as the preferred long-term Burp extension path.",
            "Keep the Burp-side panel read-only except for explicit user-triggered actions such as Open plan in Repeater or Sync selected tabs.",
            "Pin issue correlation with Burp issue ID whenever Burp exposes it; otherwise fall back to snapshot_id.",
        ],
    }
