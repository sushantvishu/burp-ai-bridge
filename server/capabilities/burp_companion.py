from typing import Any


def build_burp_companion_config() -> dict[str, Any]:
    return {
        "extension_bundle_endpoint": "/api/burp/companion-extension",
        "model_options_endpoint": "/api/runtime/model-options",
        "model_selection_endpoint": "/api/runtime/model-selection",
        "actions": [
            {
                "name": "submit_scanner_issue",
                "endpoint": "/api/burp/submit-job",
                "purpose": "Capture a snapshot and submit the selected Burp issue or request to the async analysis flow.",
            },
            {
                "name": "open_repeater_plan",
                "endpoint": "/api/burp/open-repeater-plan",
                "purpose": "Create one Burp Repeater tab per planned variant when send_to_repeater is allowed.",
            },
            {
                "name": "score_repeater_diffs",
                "endpoint": "/api/burp/repeater-diff-score",
                "purpose": "Score the baseline-vs-variant responses after Repeater sends complete.",
            },
            {
                "name": "sync_selected_repeater_tabs",
                "endpoint": "/api/burp/repeater-sync",
                "purpose": "Ingest selected Repeater tab results and return diff scoring, refreshed workflow state, and the best next tab in one call.",
            },
            {
                "name": "best_next_tab",
                "endpoint": "/api/burp/best-next-tab",
                "purpose": "Return the highest-value next Repeater tab or evidence-capture step for the current issue workflow.",
            },
            {
                "name": "refresh_panel_state",
                "endpoint": "/api/burp/panel-state",
                "purpose": "Refresh the full Burp AI Bridge panel state, including workflow, diff summary, and best-next-tab guidance.",
            },
            {
                "name": "impact_upgrade_plan",
                "endpoint": "/api/impact/upgrade-plan",
                "purpose": "Return the dedicated proof-level, next-step, reportability, and severity-upgrade planner for the current finding.",
            },
            {
                "name": "burp_capability_recommendations",
                "endpoint": "/api/burp/capability-recommendations",
                "purpose": "Recommend the best Burp feature, custom check, Bambda, and bounded external tool for the current finding.",
            },
            {
                "name": "record_bcheck_result",
                "endpoint": "/api/bchecks/results",
                "purpose": "Record whether the one imported official BCheck added a useful signal or stayed noisy for this issue family.",
            },
        ],
        "sender_module": "python -m server.burp_direct_sender",
        "notes": [
            "Fetch /api/burp/companion-extension for bundled Jython/Java sample paths and the recommended panel workflow.",
            "Fetch /api/runtime/model-options when the Burp-side settings panel needs the locally installed Ollama model tags to switch to.",
            "POST /api/runtime/model-selection with the chosen model_name when the Burp-side settings panel switches the active Ollama model without restarting the server.",
            "The bridge no longer exposes a profile picker in the Burp-side settings flow; use MCP-first context plus model switching instead.",
            "Use open_repeater_plan first when the bridge should create tabs in Burp automatically.",
            "Use repeater_sync after you capture selected Repeater tab responses back from Burp; it returns diff scoring, workflow refresh, and next-tab guidance in one round trip.",
            "Use repeater_diff_score after you paste or export the baseline and variant responses back into the bridge.",
            "Use panel_state when the Burp-side panel just needs a workflow refresh for the selected issue, snapshot, or target.",
            "Use impact_upgrade_plan when the Burp-side panel needs the focused proof-level and severity-upgrade card for one finding.",
            "Use burp_capability_recommendations when the panel needs a focused Burp-feature-aware recommendation instead of only payload advice.",
            "Use record_bcheck_result after you run one selected official PortSwigger BCheck and know whether it helped or stayed noisy on this exact issue family.",
            "Issue-centric workflow state is keyed by Burp issue ID when available, otherwise snapshot ID or target URL.",
        ],
    }
