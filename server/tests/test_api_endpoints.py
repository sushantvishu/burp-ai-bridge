import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server import main as main_module


class ApiEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main_module.app)

    def test_prepare_burp_export_endpoint_returns_normalized_payload(self):
        prepared = {
            "contract_version": "2026-03-30",
            "payload": {"target_url": "https://example.com", "raw_request": "GET / HTTP/1.1", "use_burp_mcp_context": True},
            "summary": {"dashboard_issue_found": True, "proxy_history_count": 2},
            "next_step": {"api_endpoint": "/api/analyze/jobs", "mcp_tool": "analyze_security_exchange", "notes": ["post directly"]},
            "exporter": {"required_fields": ["source_tool", "target_url", "use_burp_mcp_context"]},
        }
        with patch.object(main_module, "prepare_burp_export", return_value=prepared):
            response = self.client.post("/api/burp/prepare-export", json={"raw_request": "GET / HTTP/1.1"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["contract_version"], "2026-03-30")
        self.assertEqual(response.json()["payload"]["target_url"], "https://example.com")
        self.assertTrue(response.json()["payload"]["use_burp_mcp_context"])
        self.assertEqual(response.json()["next_step"]["api_endpoint"], "/api/analyze/jobs")
        self.assertIn("use_burp_mcp_context", response.json()["exporter"]["required_fields"])

    def test_burp_exporter_mcp_capabilities_and_session_snapshot_endpoints_return_typed_payloads(self):
        capabilities = {
            "transport": "auto",
            "timeout_seconds": 20,
            "protocol_version": "2025-06-18",
            "url": "http://127.0.0.1:9876",
            "command": "",
            "working_directory": "",
            "server_name": "burp-mcp",
            "server_version": "1.0",
            "available_tools": ["get_proxy_http_history"],
            "read_only_only": True,
            "capability_map": {"proxy_history": {"tool_name": "get_proxy_http_history", "allowed": True, "mode": "read-only"}},
            "permitted_tools": ["get_proxy_http_history"],
            "blocked_tools": [],
            "denied_capabilities": [],
        }
        session_snapshot = {
            "snapshot_id": "snap-1",
            "created_at": "2026-03-31T00:00:00+00:00",
            "target_url": "https://example.com",
            "http_method": "GET",
            "source_tool": "repeater",
            "use_burp_mcp_context": True,
            "issue_context": {"found": False},
            "scanner_details": {"issue_name": ""},
            "proxy_history": {"target_url": "https://example.com", "count": 1, "entries": [{"source": "proxy", "summary": "baseline"}]},
            "repeater_context": {"target_url": "https://example.com", "count": 1, "entries": [{"source": "repeater", "summary": "comparison"}], "primary_request": {"source": "repeater", "summary": "comparison"}},
            "project_config": {"enabled_tools": ["Proxy"], "scope_includes": [], "scope_excludes": [], "config_warnings": []},
            "active_editor_request": "GET / HTTP/1.1",
            "regex_history_matches": [],
            "collaborator_interactions": [],
            "mcp_summary": {"read_only_only": True},
            "evidence_bundle": [{"source": "proxy", "summary": "baseline"}],
            "analysis_payload": {"target_url": "https://example.com"},
        }
        exporter = {
            "contract_version": "2026-03-31",
            "bridge_endpoint": "/api/analyze/jobs",
            "required_fields": ["source_tool", "target_url", "use_burp_mcp_context"],
            "default_flags": {"use_burp_mcp_context": True},
            "source_tool_map": {"Repeater": "repeater"},
            "macro_template": {"body": {"use_burp_mcp_context": True}},
            "notes": ["note"],
        }
        capability_call = {
            "capability": "proxy_history",
            "tool_name": "get_proxy_http_history",
            "arguments": {"count": 8},
            "content_text": "[]",
            "structured_content": {},
            "available_tools": ["get_proxy_http_history"],
            "server_name": "burp-mcp",
            "server_version": "1.0",
            "protocol_version": "2025-06-18",
        }
        with (
            patch.object(main_module, "build_burp_exporter_config", return_value=exporter),
            patch.object(main_module, "inspect_burp_mcp_capabilities", return_value=capabilities),
            patch.object(main_module, "call_burp_mcp_capability", return_value=capability_call),
            patch.object(main_module, "build_burp_session_snapshot", return_value=session_snapshot),
        ):
            exporter_response = self.client.get("/api/burp/exporter-config")
            capabilities_response = self.client.get("/api/burp/mcp-capabilities")
            capability_response = self.client.post("/api/burp/mcp-capability", json={"capability": "proxy_history", "payload": {"target_url": "https://example.com"}})
            snapshot_response = self.client.post("/api/burp/session-snapshot", json={"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"})

        self.assertEqual(exporter_response.status_code, 200)
        self.assertIn("use_burp_mcp_context", exporter_response.json()["required_fields"])
        self.assertEqual(capabilities_response.status_code, 200)
        self.assertTrue(capabilities_response.json()["read_only_only"])
        self.assertEqual(capability_response.status_code, 200)
        self.assertEqual(capability_response.json()["tool_name"], "get_proxy_http_history")
        self.assertEqual(snapshot_response.status_code, 200)
        self.assertEqual(snapshot_response.json()["snapshot_id"], "snap-1")

    def test_burp_direct_submit_config_and_submit_job_routes_return_snapshot_bound_job(self):
        direct_submit = {
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
            "default_payload": {"use_burp_mcp_context": True},
            "python_sender_template": "import requests",
            "python_repeater_template": "import requests",
            "python_sync_template": "import requests",
            "python_panel_template": "import requests",
            "notes": ["note"],
        }
        snapshot = {
            "snapshot_id": "snap-42",
            "analysis_payload": {"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com", "http_method": "GET"},
        }
        job = {
            "job_id": "job-42",
            "request_id": "req-42",
            "snapshot_id": "snap-42",
            "status": "queued",
            "status_message": "queued",
            "estimated_duration": "30s",
            "complexity": "medium",
            "recommendation": "use jobs",
        }
        with (
            patch.object(main_module, "build_burp_direct_submit_config", return_value=direct_submit),
            patch.object(main_module, "build_burp_session_snapshot", return_value=snapshot),
            patch.object(main_module.job_manager, "submit", return_value=job),
        ):
            config = self.client.get("/api/burp/direct-submit-config")
            submit = self.client.post("/api/burp/submit-job", headers={"X-Request-ID": "req-42"}, json={"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"})

        self.assertEqual(config.status_code, 200)
        self.assertIn("source_tool", config.json()["required_fields"])
        self.assertEqual(config.json()["open_repeater_plan_endpoint"], "/api/burp/open-repeater-plan")
        self.assertEqual(config.json()["companion_config_endpoint"], "/api/burp/companion-config")
        self.assertEqual(config.json()["companion_extension_endpoint"], "/api/burp/companion-extension")
        self.assertEqual(config.json()["capability_recommendations_endpoint"], "/api/burp/capability-recommendations")
        self.assertEqual(config.json()["bcheck_result_endpoint"], "/api/bchecks/results")
        self.assertEqual(config.json()["model_options_endpoint"], "/api/runtime/model-options")
        self.assertEqual(config.json()["model_selection_endpoint"], "/api/runtime/model-selection")
        self.assertEqual(config.json()["panel_state_endpoint"], "/api/burp/panel-state")
        self.assertEqual(submit.status_code, 202)
        self.assertEqual(submit.json()["snapshot_id"], "snap-42")
        self.assertEqual(submit.json()["job_id"], "job-42")

    def test_burp_companion_config_endpoint_returns_actions(self):
        companion = {
            "extension_bundle_endpoint": "/api/burp/companion-extension",
            "model_options_endpoint": "/api/runtime/model-options",
            "model_selection_endpoint": "/api/runtime/model-selection",
            "actions": [
                {"name": "open_repeater_plan", "endpoint": "/api/burp/open-repeater-plan", "purpose": "open tabs"},
                {"name": "sync_selected_repeater_tabs", "endpoint": "/api/burp/repeater-sync", "purpose": "sync tabs"},
                {"name": "refresh_panel_state", "endpoint": "/api/burp/panel-state", "purpose": "refresh panel"},
                {"name": "burp_capability_recommendations", "endpoint": "/api/burp/capability-recommendations", "purpose": "feature guidance"},
                {"name": "record_bcheck_result", "endpoint": "/api/bchecks/results", "purpose": "record outcome"},
            ],
            "sender_module": "python -m server.burp_direct_sender",
            "notes": ["note"],
        }
        with patch.object(main_module, "build_burp_companion_config", return_value=companion):
            response = self.client.get("/api/burp/companion-config")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["extension_bundle_endpoint"], "/api/burp/companion-extension")
        self.assertEqual(response.json()["model_options_endpoint"], "/api/runtime/model-options")
        self.assertEqual(response.json()["model_selection_endpoint"], "/api/runtime/model-selection")
        self.assertEqual(response.json()["actions"][0]["name"], "open_repeater_plan")
        self.assertEqual(response.json()["actions"][1]["endpoint"], "/api/burp/repeater-sync")
        self.assertEqual(response.json()["actions"][2]["endpoint"], "/api/burp/panel-state")
        self.assertEqual(response.json()["actions"][3]["endpoint"], "/api/burp/capability-recommendations")
        self.assertEqual(response.json()["actions"][4]["endpoint"], "/api/bchecks/results")

    def test_burp_companion_extension_endpoint_returns_sample_paths_and_workflow(self):
        extension_bundle = {
            "name": "burp-ai-bridge-companion",
            "panel_endpoint": "/api/burp/panel-state",
            "sync_endpoint": "/api/burp/repeater-sync",
            "open_repeater_plan_endpoint": "/api/burp/open-repeater-plan",
            "submit_job_endpoint": "/api/burp/submit-job",
            "sample_paths": {
                "jython": "D:/repo/server/samples/burp/BurpAiBridgePanel.py",
                "java": "D:/repo/server/samples/burp/BurpAiBridgePanel.java",
                "montoya": "D:/repo/server/samples/burp/BurpAiBridgeMontoyaExtension.java",
                "docs": "D:/repo/server/BURP_COMPANION_EXTENSION.md",
            },
            "starter_asset_paths": {
                "root": "D:/repo/server/burp_assets",
                "custom_scan_checks": "D:/repo/server/burp_assets/custom_scan_checks",
                "bambda": "D:/repo/server/burp_assets/bambda",
            },
            "capability_recommendations_endpoint": "/api/burp/capability-recommendations",
            "recommended_actions": ["open_repeater_plan", "sync_selected_repeater_tabs", "refresh_panel_state"],
            "selected_message_fields": ["raw_request", "raw_response", "target_url", "issue_id"],
            "workflow_loop": ["select issue", "open plan", "send tabs", "sync tabs", "refresh panel"],
            "notes": ["note"],
        }
        with patch.object(main_module, "build_burp_companion_extension_bundle", return_value=extension_bundle):
            response = self.client.get("/api/burp/companion-extension")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["sample_paths"]["jython"], "D:/repo/server/samples/burp/BurpAiBridgePanel.py")
        self.assertEqual(body["sample_paths"]["montoya"], "D:/repo/server/samples/burp/BurpAiBridgeMontoyaExtension.java")
        self.assertEqual(body["panel_endpoint"], "/api/burp/panel-state")
        self.assertEqual(body["capability_recommendations_endpoint"], "/api/burp/capability-recommendations")
        self.assertEqual(body["workflow_loop"][2], "send tabs")

    def test_burp_repeater_sync_endpoint_returns_combined_payload(self):
        synced = {
            "target_url": "https://example.com",
            "issue_id": "issue-104",
            "workflow_id": "wf-104",
            "workflow_status": "evidence-collected",
            "diff": {
                "issue_id": "issue-104",
                "target_url": "https://example.com",
                "baseline_status": 403,
                "items": [
                    {
                        "tab_name": "variant-1",
                        "score": 0.82,
                        "status_delta": "403 -> 200",
                        "length_delta": 120,
                        "evidence_signals": ["status-change"],
                    }
                ],
                "best_item": {
                    "tab_name": "variant-1",
                    "score": 0.82,
                    "status_delta": "403 -> 200",
                    "length_delta": 120,
                    "evidence_signals": ["status-change"],
                },
            },
            "workflow": {
                "workflow_id": "wf-104",
                "issue_id": "issue-104",
                "status": "evidence-collected",
                "request_id": "req-sync",
                "target_url": "https://example.com",
                "snapshot_id": "snap-104",
                "issue_name": "Insecure direct object reference",
                "tab_observations": [{"tab_name": "variant-1", "score": 0.82}],
                "best_observation": {"tab_name": "variant-1", "score": 0.82},
                "evidence_gaps": ["capture one role-separated proof"],
                "recommended_actions": ["promote the strongest diff into a clean reproduction"],
                "report_readiness": {
                    "ready": False,
                    "status": "needs-more-evidence",
                    "missing_evidence": ["capture one role-separated proof"],
                },
                "updated_at": "2026-04-06T00:00:00+00:00",
            },
            "best_next_tab": {
                "issue_id": "issue-104",
                "tab_name": "variant-2",
                "reason": "Compare the strongest IDOR diff against a second tenant object.",
                "compare_against": "variant-1",
                "request_hint": "Swap object ID to a known second-tenant value.",
                "expected_signal": "another 200 OK on unauthorized object access",
            },
            "plan": {
                "dashboard_issue": {"issue_id": "issue-104", "issue_name": "Insecure direct object reference"},
                "repeater_variant_requests": [{"tab_name": "variant-1"}],
            },
            "summary": "Top delta: variant-1 (score 0.82). Workflow is evidence-collected. Next tab: variant-2.",
        }
        with patch.object(main_module, "sync_repeater_observations", return_value=synced):
            response = self.client.post(
                "/api/burp/repeater-sync",
                headers={"X-Request-ID": "req-sync"},
                json={
                    "raw_request": "GET /account?id=1 HTTP/1.1",
                    "target_url": "https://example.com/account",
                    "source_tool": "repeater",
                    "baseline_response_text": "HTTP/1.1 403 Forbidden",
                    "repeater_variant_observations": [{"tab_name": "variant-1", "response_text": "HTTP/1.1 200 OK"}],
                },
            )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["issue_id"], "issue-104")
        self.assertEqual(body["workflow_status"], "evidence-collected")
        self.assertEqual(body["diff"]["best_item"]["tab_name"], "variant-1")
        self.assertEqual(body["workflow"]["workflow_id"], "wf-104")
        self.assertEqual(body["best_next_tab"]["tab_name"], "variant-2")
        self.assertEqual(body["plan"]["dashboard_issue"]["issue_id"], "issue-104")

    def test_burp_panel_state_endpoint_returns_compact_refresh_payload(self):
        state = {
            "target_url": "https://example.com/account",
            "snapshot_id": "snap-104",
            "issue_id": "issue-104",
            "workflow_id": "wf-104",
            "workflow_status": "diff-scored",
            "dashboard_issue": {"issue_id": "issue-104", "issue_name": "Insecure direct object reference", "severity": "high"},
            "workflow": {
                "workflow_id": "wf-104",
                "issue_id": "issue-104",
                "issue_name": "Insecure direct object reference",
                "snapshot_id": "snap-104",
                "request_id": "req-panel",
                "target_url": "https://example.com/account",
                "source_tool": "repeater",
                "analysis_backend": "mcp+deterministic",
                "status": "diff-scored",
                "updated_at": "2026-04-06T00:00:00+00:00",
                "created_at": "2026-04-06T00:00:00+00:00",
                "issue_chain_strategy": ["confirm a second tenant object"],
                "tab_plan": [],
                "ranked_items": [],
                "strongest_delta": {"tab_name": "variant-1", "score": 1.4},
                "report_readiness": {"ready": False, "status": "needs-more-evidence", "missing_evidence": ["capture one clean screenshot diff"]},
                "notes": ["baseline stored"],
                "missing_evidence": ["capture one clean screenshot diff"],
            },
            "best_next_tab": {
                "workflow_id": "wf-104",
                "issue_id": "issue-104",
                "tab_name": "variant-2",
                "request_text": "GET /account?id=2 HTTP/1.1",
                "expected_signal": "another unauthorized 200 OK",
                "request_ref": "proxy-104",
                "reason": "Score a second tenant object before escalating.",
                "compare_checks": ["status delta"],
                "score_context": {"tab_name": "variant-1", "score": 1.4},
            },
            "diff_summary": {"count": 1, "best_item": {"tab_name": "variant-1", "score": 1.4}, "summary": "Strongest scored delta: variant-1 (score 1.4)."},
            "plan": {"dashboard_issue": {"issue_id": "issue-104", "issue_name": "Insecure direct object reference"}},
            "companion_actions": [{"name": "refresh_panel_state", "endpoint": "/api/burp/panel-state", "purpose": "refresh"}],
            "guidance_hits": [
                {
                    "id": "strix-method-pack",
                    "name": "Strix-inspired methodology pack",
                    "style": "methodology",
                    "origin": "conceptual",
                    "summary": "summary",
                    "matched_classes": ["idor"],
                    "guidance": {"workflow_focus": ["anchor one object boundary first"]},
                    "reference_links": ["https://github.com/usestrix/strix"],
                    "source_file": "methodology_packs.json",
                    "feedback_score": 1,
                    "influence_reason": "style=methodology; matched=idor; feedback=+1",
                }
            ],
            "guidance_merge_policy": ["program_policy_gates", "burp_scanner_evidence", "issue_workflow_state", "guidance_db"],
            "notes": ["Best next tab: variant-2."],
        }
        with patch.object(main_module, "build_burp_panel_state", return_value=state):
            response = self.client.post(
                "/api/burp/panel-state?issue_id=issue-104&snapshot_id=snap-104",
                headers={"X-Request-ID": "req-panel"},
                json={"raw_request": "GET /account?id=1 HTTP/1.1", "target_url": "https://example.com/account"},
            )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["issue_id"], "issue-104")
        self.assertEqual(body["workflow"]["workflow_id"], "wf-104")
        self.assertEqual(body["best_next_tab"]["tab_name"], "variant-2")
        self.assertEqual(body["companion_actions"][0]["endpoint"], "/api/burp/panel-state")
        self.assertEqual(body["guidance_hits"][0]["style"], "methodology")
        self.assertEqual(body["guidance_merge_policy"][0], "program_policy_gates")

    def test_phase_history_endpoint_returns_structured_snapshots(self):
        payload = {
            "job_id": "job-1",
            "phase": "validate",
            "count": 1,
            "items": [
                {
                    "job_id": "job-1",
                    "created_at": "2026-03-30T00:00:00+00:00",
                    "target_url": "https://example.com/a",
                    "phase": "validate",
                    "result": {"validation_status": "needs-confirmation"},
                    "input_context": {"target_url": "https://example.com/a"},
                }
            ],
        }
        with patch.object(main_module, "query_phase_history", return_value=payload):
            response = self.client.get("/api/history/jobs/job-1/phases?phase=validate&limit=10")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["items"][0]["phase"], "validate")

    def test_reasoning_endpoint_returns_state_first_summary(self):
        reasoning = {
            "job_id": "job-77",
            "target_url": "https://example.com/r",
            "top_hypothesis": {"id": "hyp-1", "vuln_class": "idor", "summary": "tenant switch"},
            "phase_highlights": [{"phase": "impact", "summary": "reportable=False, class=account"}],
            "key_evidence": [{"source": "burp-dashboard", "evidence_type": "scanner", "summary": "scanner issue", "confidence": 0.61}],
            "confidence_drivers": ["manual-diff: object id changed"],
            "downgrade_reasons": ["Validation still has unresolved evidence gaps."],
            "next_decision": {
                "primary_next_action": "collect one role-separated diff",
                "validation_status": "needs-confirmation",
                "reportability": "medium",
                "confirmation_state": "needs-confirmation",
            },
        }
        with patch.object(main_module, "explain_analysis_run", return_value=reasoning):
            response = self.client.get("/api/history/jobs/job-77/reasoning")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["top_hypothesis"]["vuln_class"], "idor")
        self.assertEqual(response.json()["next_decision"]["confirmation_state"], "needs-confirmation")

    def test_bcheck_recommendation_endpoint_returns_service_payload(self):
        recommended = {
            "target_url": "https://example.com/r",
            "recommended_bchecks": ["Passive cookie hardening check"],
            "matched_playbooks": ["Session Review"],
            "review_scope_include_classes": ["session-management"],
            "official_bcheck_candidates": [
                {
                    "name": "Cookie Session Check",
                    "relative_path": "other/session/cookie-session.bcheck",
                    "source_url": "https://github.com/PortSwigger/BChecks/blob/main/other/session/cookie-session.bcheck",
                    "scan_mode": "passive",
                    "execution_context": "request",
                    "requires_collaborator": False,
                    "methods": ["GET"],
                    "vuln_classes": ["session-management"],
                    "usage_hint": "Run only on the bounded issue family.",
                    "why": "matches target class session-management",
                    "score": 7,
                    "learning_adjustment": 0,
                    "suppressed_for_issue_family": False,
                    "preferred_for_issue_family": False,
                    "selection_references": ["https://portswigger.net/web-security/authentication/session-management"],
                }
            ],
            "selected_official_bcheck": {
                "name": "Cookie Session Check",
                "relative_path": "other/session/cookie-session.bcheck",
                "source_url": "https://github.com/PortSwigger/BChecks/blob/main/other/session/cookie-session.bcheck",
                "scan_mode": "passive",
                "execution_context": "request",
                "requires_collaborator": False,
                "methods": ["GET"],
                "vuln_classes": ["session-management"],
                "usage_hint": "Run only on the bounded issue family.",
                "why": "matches target class session-management",
                "score": 7,
                "learning_adjustment": 0,
                "suppressed_for_issue_family": False,
                "preferred_for_issue_family": False,
                "selection_references": ["https://portswigger.net/web-security/authentication/session-management"],
            },
            "issue_family_memory": {"summary": "No issue-family memory matched this issue yet."},
            "one_best_next_step": {
                "title": "Import and run Cookie Session Check on the current issue family.",
                "source": "official-bcheck-selector",
                "why": "matches target class session-management",
                "manual_step": "Import other/session/cookie-session.bcheck into Burp custom scan checks and run it only on the scanner-marked request family.",
                "expected_signal": "Run only on the bounded issue family.",
                "stop_when": "One useful proof artifact is added, or the check stays noisy on this issue family.",
                "supporting_references": ["https://portswigger.net/web-security/authentication/session-management"],
            },
            "curated_reference_links": ["https://portswigger.net/web-security/authentication/session-management"],
        }
        with patch.object(main_module, "recommend_bchecks_for_exchange", return_value=recommended):
            response = self.client.post(
                "/api/bchecks/recommend",
                json={
                    "raw_request": "GET / HTTP/1.1",
                    "target_url": "https://example.com/r",
                    "review_scope_include_classes": ["session-management"],
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["recommended_bchecks"][0], "Passive cookie hardening check")
        self.assertEqual(response.json()["matched_playbooks"][0], "Session Review")
        self.assertEqual(response.json()["selected_official_bcheck"]["name"], "Cookie Session Check")
        self.assertEqual(response.json()["one_best_next_step"]["source"], "official-bcheck-selector")

    def test_project_readiness_endpoint_returns_service_payload(self):
        readiness = {
            "target_url": "https://example.com/r",
            "project_readiness_summary": "ready",
            "project_readiness_checks": ["capture one clean baseline response"],
            "labeled_project_readiness_checks": [{"label": "high-signal", "text": "capture one clean baseline response"}],
            "burp_action_checklist": ["send the baseline to Repeater"],
            "bcheck_recommendations": ["Passive cookie hardening check"],
        }
        with patch.object(main_module, "review_project_readiness", return_value=readiness):
            response = self.client.post(
                "/api/project/readiness",
                json={
                    "raw_request": "GET / HTTP/1.1",
                    "target_url": "https://example.com/r",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["project_readiness_summary"], "ready")
        self.assertEqual(response.json()["burp_action_checklist"][0], "send the baseline to Repeater")

    def test_bcheck_result_ingestion_endpoint_returns_typed_payload(self):
        issue_family_memory = {
            "issue_family_key": "generic:bug-bounty-safe:example-com|issue:issue-104",
            "summary": "Preferred official BChecks: other/session/cookie-session.bcheck",
        }
        with (
            patch.object(main_module, "append_bcheck_result"),
            patch.object(main_module, "summarize_issue_family_memory", return_value=issue_family_memory),
        ):
            response = self.client.post(
                "/api/bchecks/results",
                json={
                    "raw_request": "GET / HTTP/1.1",
                    "target_url": "https://example.com/r",
                    "issue_id": "issue-104",
                    "selected_bcheck": {
                        "name": "Cookie Session Check",
                        "relative_path": "other/session/cookie-session.bcheck",
                        "source_url": "https://github.com/PortSwigger/BChecks/blob/main/other/session/cookie-session.bcheck",
                        "selection_references": ["https://portswigger.net/web-security/authentication/session-management"],
                    },
                    "outcome_label": "useful",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["recorded"])
        self.assertEqual(response.json()["result_label"], "useful")
        self.assertEqual(response.json()["selected_bcheck"]["name"], "Cookie Session Check")

    def test_policy_template_and_browser_verification_endpoints_return_typed_payloads(self):
        template = {
            "name": "hackerone",
            "platform": "HackerOne-style",
            "summary": "policy summary",
            "scope_prompts": ["confirm scope"],
            "rate_limit_guidance": ["keep automation conservative"],
            "safe_testing_notes": ["minimal proof"],
            "browser_verification_rules": ["bounded browser checks only"],
            "out_of_scope_risks": ["no destructive testing"],
            "report_expectations": ["lead with concise reproduction"],
        }
        plan = {
            "target_url": "https://example.com",
            "program_platform": "hackerone",
            "eligible": True,
            "allowed": True,
            "reason": "Browser confirmation can proceed within the named workflows only.",
            "verification_goal": "Confirm the rendering context.",
            "validation_status": "needs-confirmation",
            "reportability": "medium",
            "requires_manual_session": True,
            "allowed_workflows": ["profile settings"],
            "checkpoints": ["start from the same asset"],
            "evidence_to_capture": ["one screenshot"],
            "policy_notes": ["bounded browser checks only"],
            "stop_conditions": ["stop before destructive state changes"],
            "out_of_scope_risks": ["no destructive testing"],
            "suggested_steps": ["Review only these allowed workflows before opening the browser: profile settings."],
            "labeled_steps": [{"label": "high-signal", "text": "Review only these allowed workflows before opening the browser: profile settings."}],
        }
        with (
            patch.object(main_module, "list_program_policy_templates", return_value=[template]),
            patch.object(main_module, "get_program_policy_template", return_value=template),
            patch.object(main_module, "build_browser_verification_plan", return_value=plan),
        ):
            listed = self.client.get("/api/policies/templates")
            selected = self.client.get("/api/policies/templates/hackerone")
            browser = self.client.post(
                "/api/browser/verify-plan",
                json={
                    "raw_request": "GET / HTTP/1.1",
                    "target_url": "https://example.com",
                    "browser_verification_allowed": True,
                    "browser_allowed_workflows": ["profile settings"],
                },
            )

        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.json()[0]["name"], "hackerone")
        self.assertEqual(selected.status_code, 200)
        self.assertEqual(selected.json()["platform"], "HackerOne-style")
        self.assertEqual(browser.status_code, 200)
        self.assertTrue(browser.json()["allowed"])

    def test_submission_report_endpoints_return_platform_tuned_payload(self):
        report = {
            "job_id": "job-9",
            "request_id": "req-9",
            "snapshot_id": "snap-9",
            "platform": "Bugcrowd-style",
            "template_name": "bugcrowd",
            "title": "[HIGH] IDOR on report",
            "target_url": "https://example.com/report",
            "summary": "summary",
            "severity_assessment": {
                "severity": "high",
                "confidence": 0.8,
                "candidate_taxonomy": "Access Control / IDOR",
                "rationale": "rationale",
                "promotion_triggers": [],
                "downgrade_reasons": [],
            },
            "validation_status": "confirmed",
            "reportability": "high",
            "reproduction_steps": ["step 1"],
            "impact_statement": "impact",
            "evidence_highlights": ["[proxy] diff"],
            "submission_notes": ["lead with concise reproduction"],
            "policy_alignment": ["Applied policy template: bugcrowd."],
            "browser_verification_appendix": {
                "allowed": False,
                "verification_goal": "",
                "allowed_workflows": [],
                "suggested_steps": [],
                "stop_conditions": [],
            },
            "impact_upgrade_planner": {
                "vuln_class": "idor",
                "current_proof_level": "object-boundary confirmation",
                "next_strongest_allowed_step": "Confirm one cross-tenant object access.",
                "missing_artifact_for_upgrade": "One role-separated diff.",
                "likely_severity_if_confirmed": "high",
                "report_ready_impact_sentence": "The issue crosses an authorization boundary.",
                "impact_ladder": ["Keep one clean role diff."],
            },
            "finding_to_impact_template": {
                "vuln_class": "idor",
                "proof_level": "object-boundary confirmation",
                "impact_ladder": ["Keep one clean role diff."],
                "report_ready_impact_sentence": "The issue crosses an authorization boundary.",
            },
            "reportability_gate": {
                "already_proven": ["Cross-account object access is confirmed."],
                "still_inferred": ["The wider tenant blast radius is still inferred."],
                "unsafe_to_claim_yet": ["Do not claim tenant-wide exposure without one more object proof."],
            },
            "submission_value_score": {
                "score": 0.84,
                "components": {"reproducibility": 0.9},
                "summary": "Strong submission candidate with good triage value.",
            },
            "program_specific_impact_wording": {
                "platform": "bugcrowd",
                "focus": "cross-tenant data exposure and privilege boundary break",
                "wording": "Emphasize the exact artifact that makes the issue reproducible and triage-friendly.",
            },
            "burp_session_snapshot": {"snapshot_id": "snap-9"},
            "markdown": "# report\n",
        }
        with patch.object(main_module, "build_bug_bounty_submission", return_value=report) as mocked_build:
            response = self.client.get("/api/history/jobs/job-9/submission-report?platform=bugcrowd&snapshot_id=snap-9")
            markdown = self.client.get("/api/history/jobs/job-9/submission-report.md?platform=bugcrowd&snapshot_id=snap-9")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["template_name"], "bugcrowd")
        self.assertEqual(response.json()["snapshot_id"], "snap-9")
        self.assertEqual(response.json()["severity_assessment"]["severity"], "high")
        self.assertEqual(response.json()["impact_upgrade_planner"]["likely_severity_if_confirmed"], "high")
        self.assertEqual(response.json()["submission_value_score"]["score"], 0.84)
        self.assertEqual(response.json()["program_specific_impact_wording"]["platform"], "bugcrowd")
        self.assertEqual(markdown.status_code, 200)
        self.assertIn("# report", markdown.text)
        mocked_build.assert_any_call("job-9", platform="bugcrowd", snapshot_id="snap-9")

    def test_structured_report_endpoint_passes_snapshot_override(self):
        report = {
            "job_id": "job-11",
            "request_id": "req-11",
            "snapshot_id": "snap-11",
            "title": "AI Bridge Report for https://example.com/report",
            "summary": "summary",
            "primary_next_action": "baseline",
            "reporting_checklist": ["baseline"],
            "labeled_reporting_steps": [{"label": "high-signal", "text": "baseline"}],
            "hypothesis_summaries": [],
            "evidence_artifacts": [],
            "impact_assessment": {"reportable": False},
            "validation_assessment": {"validation_status": "needs-confirmation"},
            "analysis_backend": "mcp",
            "fallback_used": False,
            "source_links": [],
            "next_decision": {"primary_next_action": "baseline"},
            "burp_session_snapshot": {"snapshot_id": "snap-11"},
        }
        with patch.object(main_module, "build_structured_report_for_job", return_value=report) as mocked_build:
            response = self.client.get("/api/history/jobs/job-11/report?snapshot_id=snap-11")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["snapshot_id"], "snap-11")
        mocked_build.assert_called_once_with("job-11", snapshot_id="snap-11")

    def test_runtime_health_endpoint_returns_diagnostics_payload(self):
        health = {
            "configured_provider_order": ["mcp", "ollama"],
            "active_provider_order": ["mcp", "ollama"],
            "context_priority": {
                "primary_context_source": "burp_mcp",
                "burp_mcp_context_enabled": True,
                "mcp_enabled": True,
                "provider_order_starts_with_mcp": True,
                "status": "ready",
                "summary": "Burp MCP is enabled and MCP is first in the provider order, so live Burp context is the primary source.",
            },
            "burp_mcp": {
                "enabled": True,
                "transport": "auto",
                "tool_name": "",
                "timeout_seconds": 20,
                "protocol_version": "2025-06-18",
                "status": "ready",
                "detail": "Burp MCP responded and advertised 3 tool(s).",
                "command": "",
                "url": "http://127.0.0.1:9876",
                "working_directory": "",
                "server_name": "burp-mcp",
                "server_version": "1.0",
                "available_tools": ["get_proxy_http_history"],
            },
            "mcp": {
                "enabled": True,
                "transport": "stdio",
                "tool_name": "analyze_security_exchange",
                "timeout_seconds": 30,
                "protocol_version": "2025-06-18",
                "status": "ready",
                "detail": "MCP server responded and advertised 3 tool(s).",
                "command": "python -m server.mcp_server.app",
                "url": "",
                "working_directory": "D:/repo/server",
                "server_name": "burp-ai-bridge-mcp",
                "server_version": "1.0",
                "available_tools": ["analyze_security_exchange"],
            },
            "ollama": {
                "enabled": True,
                "configured_url": "http://127.0.0.1:11434/api/generate",
                "model": "qwen2.5-coder:3b",
                "vision_model": "",
                "timeout_seconds": 30,
                "status": "ready",
                "detail": "Ollama is reachable and the configured text model is available.",
                "candidate_urls": ["http://127.0.0.1:11434/api/generate"],
                "tag_probe_urls": ["http://127.0.0.1:11434/api/tags"],
                "selected_endpoint": "http://127.0.0.1:11434/api/generate",
                "detected_models": ["qwen2.5-coder:3b"],
            },
        }
        with patch.object(main_module, "get_runtime_health", return_value=health):
            response = self.client.get("/api/runtime/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["burp_mcp"]["status"], "ready")
        self.assertEqual(response.json()["mcp"]["status"], "ready")
        self.assertEqual(response.json()["ollama"]["detected_models"][0], "qwen2.5-coder:3b")
        self.assertEqual(response.json()["context_priority"]["primary_context_source"], "burp_mcp")

    def test_guidance_db_endpoint_returns_structured_pack_hits(self):
        guidance = {
            "hits": [
                {
                    "id": "strix-method-pack",
                    "name": "Strix-inspired methodology pack",
                    "style": "methodology",
                    "origin": "conceptual",
                    "summary": "summary",
                    "matched_classes": ["idor"],
                    "guidance": {"workflow_focus": ["anchor one object boundary first"]},
                    "reference_links": ["https://github.com/usestrix/strix"],
                    "source_file": "methodology_packs.json",
                    "feedback_score": 2,
                    "influence_reason": "style=methodology; matched=idor; feedback=+2",
                }
            ],
            "context": "[Pack: Strix-inspired methodology pack]",
            "reference_links": ["https://github.com/usestrix/strix"],
            "merge_policy": ["program_policy_gates", "burp_scanner_evidence", "issue_workflow_state", "guidance_db"],
        }
        with patch.object(main_module, "query_guidance_packs", return_value=guidance):
            response = self.client.get("/api/kb/guidance-db?vuln_class=idor&style=methodology")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["hits"][0]["style"], "methodology")
        self.assertEqual(body["hits"][0]["matched_classes"][0], "idor")
        self.assertEqual(body["reference_links"][0], "https://github.com/usestrix/strix")
        self.assertEqual(body["merge_policy"][0], "program_policy_gates")
        self.assertEqual(body["hits"][0]["feedback_score"], 2)

    def test_guidance_feedback_endpoint_records_pack_feedback(self):
        with patch.object(main_module, "append_guidance_feedback", return_value={
            "job_id": "job-1",
            "label": "useful",
            "guidance_pack_ids": ["strix_methodology_pack", "shannon_validation_impact_pack"],
        }):
            response = self.client.post(
                "/api/kb/guidance-feedback",
                json={
                    "job_id": "job-1",
                    "label": "useful",
                    "guidance_pack_ids": ["strix_methodology_pack", "shannon_validation_impact_pack"],
                    "notes": "these matched the final reportable path",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["guidance_pack_ids"][0], "strix_methodology_pack")

    def test_profiles_endpoint_exposes_recommended_model_metadata(self):
        profiles = [
            {
                "name": "deep-escalation-llama32-7b",
                "description": "profile",
                "default_review_scope": ["idor"],
                "kb_top_k": 3,
                "memory_top_k": 2,
                "prefer_small_context": False,
                "recommended_model": "llama3.2:7b",
                "best_for": "deep escalation",
                "resolved_model": "llama3.1:latest",
                "model_available": True,
                "switch_value": "llama3.1:latest",
                "availability_reason": "fallback to installed deep model",
            }
        ]
        with patch.object(main_module, "list_runtime_profiles", return_value=profiles):
            response = self.client.get("/api/profiles")

        self.assertEqual(response.status_code, 200)
        body = {item["name"]: item for item in response.json()}
        self.assertIn("deep-escalation-llama32-7b", body)
        self.assertEqual(body["deep-escalation-llama32-7b"]["recommended_model"], "llama3.2:7b")
        self.assertEqual(body["deep-escalation-llama32-7b"]["resolved_model"], "llama3.1:latest")
        self.assertTrue(body["deep-escalation-llama32-7b"]["model_available"])

    def test_runtime_model_options_endpoint_returns_switchable_models(self):
        model_options = {
            "configured_url": "http://127.0.0.1:11434/api/generate",
            "current_model": "llama3.2:3b",
            "installed_models": [
                {
                    "name": "llama3.2:3b",
                    "size": "2.0 GB",
                    "source": "ollama-list",
                    "family": "llama3.2",
                    "current": True,
                    "role_hints": ["general triage"],
                    "profile_matches": ["mcp-grounded-llama32"],
                },
                {
                    "name": "llama3.1:latest",
                    "size": "4.9 GB",
                    "source": "ollama-list",
                    "family": "llama3.1",
                    "current": False,
                    "role_hints": ["deeper escalation/reporting"],
                    "profile_matches": ["deep-escalation-llama32-7b"],
                },
            ],
            "detected_model_names": ["llama3.2:3b", "llama3.1:latest"],
            "switch_targets": {
                "active": "llama3.2:3b",
                "fast": "llama3.2:3b",
                "deep": "llama3.1:latest",
                "code": "llama3.2:3b",
            },
            "notes": ["Use the exact model tag shown here when switching."],
        }
        with patch.object(main_module, "get_runtime_model_options", return_value=model_options):
            response = self.client.get("/api/runtime/model-options")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["switch_targets"]["deep"], "llama3.1:latest")
        self.assertEqual(response.json()["installed_models"][1]["name"], "llama3.1:latest")

    def test_runtime_model_selection_endpoints_switch_and_reset_model(self):
        switched = {
            "configured_url": "http://127.0.0.1:11434/api/generate",
            "current_model": "llama3.1:latest",
            "installed_models": [],
            "detected_model_names": ["llama3.2:3b", "llama3.1:latest"],
            "switch_targets": {
                "active": "llama3.1:latest",
                "fast": "llama3.2:3b",
                "deep": "llama3.1:latest",
                "code": "qwen2.5-coder:3b",
            },
            "notes": ["switched"],
        }
        reset = dict(switched)
        reset["current_model"] = "llama3.2:3b"
        reset["switch_targets"] = {
            "active": "llama3.2:3b",
            "fast": "llama3.2:3b",
            "deep": "llama3.1:latest",
            "code": "qwen2.5-coder:3b",
        }
        with (
            patch.object(main_module, "select_runtime_model", return_value=switched),
            patch.object(main_module, "clear_runtime_model_selection", return_value=reset),
        ):
            switched_response = self.client.post(
                "/api/runtime/model-selection",
                headers={"X-Request-ID": "req-1"},
                json={"model_name": "llama3.1:latest", "source": "burp-settings"},
            )
            reset_response = self.client.delete("/api/runtime/model-selection")

        self.assertEqual(switched_response.status_code, 200)
        self.assertEqual(switched_response.json()["current_model"], "llama3.1:latest")
        self.assertEqual(reset_response.status_code, 200)
        self.assertEqual(reset_response.json()["current_model"], "llama3.2:3b")

    def test_burp_action_endpoints_return_next_try_guidance(self):
        next_action_payload = {
            "target_url": "https://example.com",
            "primary_next_action": "Send the scanner-marked baseline to Repeater first.",
            "repeater_mutation_plan": [{"location": "body", "change": "swap object id"}],
            "repeater_variant_requests": [{"tab_name": "variant-1", "request_text": "GET /api/orders/1002 HTTP/1.1"}],
            "next_try_matrix": [
                {
                    "phase": "baseline-confirmation",
                    "what_to_try": "Replay the baseline request with one object-id change.",
                    "how_it_helps": "Confirms the issue is a real authorization break, not only a scanner label.",
                    "evidence_to_capture": "Baseline and changed response pair.",
                    "impact_signal": "Unauthorized object access returns 200.",
                }
            ],
            "reporting_impact_notes": ["Do not claim stronger severity until you capture a cross-tenant object diff."],
        }
        repeater_payload = {
            "target_url": "https://example.com",
            "repeater_mutation_plan": [{"location": "path", "change": "replace tenant id"}],
            "repeater_variant_requests": [{"tab_name": "variant-1", "request_text": "GET /api/orders/1002 HTTP/1.1"}],
            "next_try_matrix": [
                {
                    "phase": "impact-branch",
                    "what_to_try": "Test one adjacent object owned by a second account.",
                    "how_it_helps": "Moves the finding from confirmation to clean cross-tenant impact.",
                    "evidence_to_capture": "Two-account diff with the same endpoint.",
                    "impact_signal": "A second tenant's record is readable.",
                }
            ],
            "reporting_impact_notes": ["Anchor the report to the proven object-boundary bypass."],
        }
        with (
            patch.object(main_module, "next_burp_action", return_value=next_action_payload),
            patch.object(main_module, "burp_repeater_plan", return_value=repeater_payload),
        ):
            next_action = self.client.post(
                "/api/burp/next-action",
                json={"raw_request": "GET /api/orders/1001 HTTP/1.1", "target_url": "https://example.com"},
            )
            repeater = self.client.post(
                "/api/burp/repeater-plan",
                json={"raw_request": "GET /api/orders/1001 HTTP/1.1", "target_url": "https://example.com"},
            )

        self.assertEqual(next_action.status_code, 200)
        self.assertEqual(next_action.json()["next_try_matrix"][0]["phase"], "baseline-confirmation")
        self.assertIn("cross-tenant object diff", next_action.json()["reporting_impact_notes"][0])
        self.assertEqual(repeater.status_code, 200)
        self.assertEqual(repeater.json()["next_try_matrix"][0]["phase"], "impact-branch")
        self.assertIn("object-boundary bypass", repeater.json()["reporting_impact_notes"][0])

    def test_runtime_readiness_endpoint_returns_typed_payload(self):
        readiness = {
            "request_id": "req-1",
            "status": "degraded",
            "summary": "Runtime is partially ready, but more context or a healthier provider path would improve output quality.",
            "recommended_analysis_endpoint": "/api/analyze/jobs",
            "runtime_ready": True,
            "input_ready": True,
            "checks": [{"name": "runtime-providers", "status": "degraded", "detail": "mcp=degraded"}],
            "blockers": [],
            "warnings": ["Attach Burp issue context."],
            "burp_context_summary": {
                "dashboard_issue": {"found": False},
                "proxy_history_count": 0,
                "logger_entry_count": 0,
                "repeater_request_count": 0,
                "enabled_tool_count": 0,
                "config_warning_count": 0,
            },
            "project_config": {"enabled_tools": [], "scope_includes": [], "scope_excludes": [], "config_warnings": []},
            "runtime_health": {
                "configured_provider_order": ["mcp", "ollama"],
                "active_provider_order": ["mcp", "ollama"],
                "burp_mcp": {"enabled": True, "status": "ready"},
                "mcp": {"enabled": True, "status": "degraded"},
                "ollama": {"enabled": True, "status": "ready"},
            },
            "labeled_next_steps": [{"label": "needs-confirmation", "text": "Attach Burp issue context."}],
        }
        with patch.object(main_module, "get_runtime_readiness", return_value=readiness):
            response = self.client.post("/api/runtime/readiness", json={"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["recommended_analysis_endpoint"], "/api/analyze/jobs")
        self.assertEqual(response.json()["checks"][0]["name"], "runtime-providers")

    def test_provider_diagnostics_history_endpoint_returns_typed_payload(self):
        diagnostics = {
            "total_matches": 1,
            "count": 1,
            "limit": 20,
            "cursor": 0,
            "next_cursor": None,
            "provider_status_counts": {"complete": 1},
            "backend_counts": {"ollama": 1},
            "items": [
                {
                    "job_id": "job-1",
                    "request_id": "req-1",
                    "created_at": "2026-03-30T00:00:00+00:00",
                    "target_url": "https://example.com",
                    "status": "completed",
                    "analysis_backend": "ollama",
                    "fallback_used": False,
                    "fallback_reason": "",
                    "provider_trace": ["REQUEST INFO: request_id=req-1", "OLLAMA USED: complete response"],
                    "provider_failover": {"final_status": "complete", "final_backend": "ollama"},
                }
            ],
        }
        with patch.object(main_module, "get_provider_diagnostics_history", return_value=diagnostics):
            response = self.client.get("/api/runtime/provider-diagnostics?request_id=req-1")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["items"][0]["request_id"], "req-1")
        self.assertEqual(response.json()["backend_counts"]["ollama"], 1)

    def test_submission_regression_import_and_asset_feedback_endpoints_return_typed_payloads(self):
        imported = {
            "imported_count": 2,
            "skipped_count": 1,
            "items": [{"job_id": "submission-regression:accepted-idor-001", "outcome_label": "confirmed-reportable"}],
            "skipped_job_ids": ["submission-regression:accepted-idor-001"],
            "summary": "Imported 2 regression example(s) into the review dataset. Skipped 1 existing example(s).",
        }
        asset_feedback = {
            "asset_type": "custom_scan_check",
            "asset_id": "idor-bola-check",
            "label": "useful",
            "target_url": "https://example.com/api/invoices/42",
            "vuln_class": "idor",
            "memory_partition_key": "generic:bug-bounty-safe:example-com",
            "notes": "",
            "job_id": "job-1",
            "request_id": "req-1",
            "created_at": "2026-04-10T00:00:00+00:00",
        }
        with (
            patch.object(main_module, "import_submission_regressions_into_review_dataset", return_value=imported),
            patch.object(main_module, "append_asset_feedback", return_value=asset_feedback),
        ):
            import_response = self.client.post(
                "/api/submissions/regressions/import",
                json={"outcome": "accepted", "limit": 10},
            )
            feedback_response = self.client.post(
                "/api/burp/assets/feedback",
                json={
                    "asset_type": "custom_scan_check",
                    "asset_id": "idor-bola-check",
                    "label": "useful",
                    "target_url": "https://example.com/api/invoices/42",
                    "vuln_class": "idor",
                    "job_id": "job-1",
                    "request_id": "req-1",
                },
            )

        self.assertEqual(import_response.status_code, 200)
        self.assertEqual(import_response.json()["imported_count"], 2)
        self.assertEqual(feedback_response.status_code, 200)
        self.assertEqual(feedback_response.json()["asset_id"], "idor-bola-check")

    def test_recent_history_page_and_exports_return_paged_records(self):
        record = {
            "job_id": "job-1",
            "request_id": "req-1",
            "snapshot_id": "snap-1",
            "status": "completed",
            "created_at": "2026-03-30T00:00:00+00:00",
            "target_url": "https://example.com",
            "batch_id": "",
            "batch_index": 0,
            "batch_total": 0,
            "result": {
                "request_id": "req-1",
                "analysis": "analysis",
                "analysis_backend": "ollama",
                "model_execution_summary": "summary",
                "provider_failover": {"final_status": "complete", "final_backend": "ollama"},
                "potential_vulnerabilities": [],
                "questions_for_user": [],
                "request_plan": [],
                "primary_next_action": "",
                "nuclei_tags": "",
                "seclists_path": "",
                "source_links": [],
            },
            "analysis_run": {"request_id": "req-1", "phase_results": {}, "phases": {}, "hypotheses": [], "evidence": []},
        }
        page = {"cursor": 0, "limit": 20, "total": 1, "count": 1, "next_cursor": None, "items": [record]}
        with patch.object(main_module, "paginate_history_records", return_value=page):
            paged = self.client.get("/api/history/recent/page?request_id=req-1")
            markdown = self.client.get("/api/history/recent/export.md?request_id=req-1")
            jsonl = self.client.get("/api/history/recent/export.jsonl?request_id=req-1")

        self.assertEqual(paged.status_code, 200)
        self.assertEqual(paged.json()["items"][0]["request_id"], "req-1")
        self.assertEqual(paged.json()["items"][0]["snapshot_id"], "snap-1")
        self.assertEqual(markdown.status_code, 200)
        self.assertIn("req-1", markdown.text)
        self.assertEqual(jsonl.status_code, 200)
        self.assertIn('"request_id": "req-1"', jsonl.text)

    def test_history_snapshot_route_returns_snapshot_bundle(self):
        snapshot = {
            "snapshot_id": "snap-99",
            "created_at": "2026-03-31T00:00:00+00:00",
            "target_url": "https://example.com",
            "http_method": "GET",
            "source_tool": "repeater",
            "use_burp_mcp_context": True,
            "issue_context": {"found": False},
            "scanner_details": {},
            "proxy_history": {"target_url": "https://example.com", "count": 0, "entries": []},
            "repeater_context": {"target_url": "https://example.com", "count": 0, "entries": [], "primary_request": {}},
            "project_config": {"enabled_tools": [], "scope_includes": [], "scope_excludes": [], "config_warnings": []},
            "active_editor_request": "",
            "regex_history_matches": [],
            "collaborator_interactions": [],
            "mcp_summary": {},
            "evidence_bundle": [],
            "analysis_payload": {},
        }
        with patch.object(main_module, "get_burp_session_snapshot", return_value=snapshot):
            response = self.client.get("/api/history/snapshots/snap-99")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["snapshot_id"], "snap-99")

    def test_provider_diagnostics_exports_return_filtered_content(self):
        diagnostics = {
            "total_matches": 1,
            "count": 1,
            "limit": 20,
            "cursor": 0,
            "next_cursor": None,
            "provider_status_counts": {"complete": 1},
            "backend_counts": {"ollama": 1},
            "items": [{"job_id": "job-1", "request_id": "req-1", "provider_failover": {"outcomes": []}}],
        }
        with patch.object(main_module, "get_provider_diagnostics_history", return_value=diagnostics):
            markdown = self.client.get("/api/runtime/provider-diagnostics/export.md?request_id=req-1")
            jsonl = self.client.get("/api/runtime/provider-diagnostics/export.jsonl?request_id=req-1")

        self.assertEqual(markdown.status_code, 200)
        self.assertIn("req-1", markdown.text)
        self.assertEqual(jsonl.status_code, 200)
        self.assertIn('"request_id": "req-1"', jsonl.text)

    def test_audit_event_endpoints_return_paged_and_exportable_results(self):
        page = {
            "cursor": 0,
            "limit": 20,
            "total": 1,
            "count": 1,
            "next_cursor": None,
            "items": [
                {
                    "timestamp": "2026-03-30T00:00:00+00:00",
                    "event_type": "job_submit",
                    "previous_hash": "prev",
                    "entry_hash": "hash",
                    "data": {"request_id": "req-1", "job_id": "job-1"},
                }
            ],
        }
        with patch.object(main_module, "paginate_audit_events", return_value=page):
            paged = self.client.get("/api/audit/events?request_id=req-1")
            markdown = self.client.get("/api/audit/events/export.md?request_id=req-1")
            jsonl = self.client.get("/api/audit/events/export.jsonl?request_id=req-1")

        self.assertEqual(paged.status_code, 200)
        self.assertEqual(paged.json()["items"][0]["event_type"], "job_submit")
        self.assertEqual(markdown.status_code, 200)
        self.assertIn("job_submit", markdown.text)
        self.assertEqual(jsonl.status_code, 200)
        self.assertIn('"event_type": "job_submit"', jsonl.text)

    def test_observability_routes_require_localhost_or_token(self):
        with (
            patch.object(main_module, "OBSERVABILITY_REQUIRE_LOCAL_OR_AUTH", True),
            patch.object(main_module, "OBSERVABILITY_ALLOW_LOCALHOST", False),
            patch.object(main_module, "OBSERVABILITY_AUTH_TOKEN", "secret-token"),
            patch.object(main_module, "_is_local_request_host", return_value=False),
        ):
            denied = self.client.get("/api/history/recent")
            with patch.object(main_module, "paginate_history_records", return_value={"cursor": 0, "limit": 20, "total": 0, "count": 0, "next_cursor": None, "items": []}):
                allowed = self.client.get("/api/history/recent", headers={"X-Bridge-Admin-Token": "secret-token"})

        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.json()["detail"]["request_id"], denied.headers["X-Request-ID"])
        self.assertEqual(allowed.status_code, 200)

    def test_validation_impact_and_burp_routes_return_typed_contracts(self):
        with (
            patch.object(main_module, "validate_hypothesis", return_value={
                "target_url": "https://example.com",
                "hypothesis": {"id": "hyp-1", "vuln_class": "idor", "summary": "cross-tenant read", "confidence": 0.72},
                "validation_status": "needs-confirmation",
                "confidence": 0.64,
                "evidence_sources": ["proxy"],
                "confirming_sources": ["proxy"],
                "evidence_score": 1.25,
                "evidence_count": 1,
                "missing_evidence": ["Collect one role-separated diff."],
                "confirmation_requirements": ["Confirm the same object across two users."],
                "safest_next_proof": "Collect one role-separated diff.",
                "recommended_actions": [{"label": "needs-confirmation", "text": "Collect one role-separated diff."}],
                "analysis_backend": "mcp+deterministic",
                "fallback_used": True,
            }),
            patch.object(main_module, "rank_impact_paths", return_value={
                "target_url": "https://example.com",
                "recommended_path": "Show cross-tenant object access.",
                "ranked_impact_paths": ["cross-tenant exposure"],
                "evidence_gaps": ["Need one clean role comparison."],
                "confirmation_requirements": ["Confirm with two identities."],
                "safest_next_proof": "Collect one role-separated diff.",
                "safe_vapt_escalation_steps": ["Capture baseline", "Capture role comparison"],
                "labeled_safe_vapt_escalation_steps": [{"label": "high-signal", "text": "Capture baseline"}],
                "escalation_profile": "authorization-boundary",
                "baseline_confirmation": "Collect one role-separated diff.",
                "business_impact_expansion_paths": ["Show the same issue on list or export views."],
                "required_evidence_for_upgrade": ["One role diff"],
                "stop_conditions": ["Do not modify other users' data."],
                "likely_severity_promotions": ["Tenant-wide exposure"],
                "business_impact_class": "high-impact",
                "confirmation_state": "needs-confirmation",
                "reportable": False,
                "reportability": "medium",
                "hypothesis_count": 1,
                "evidence_score": 1.25,
                "evidence_count": 1,
                "dashboard_issue": {"found": False},
                "burp_context_summary": {"dashboard_issue": {"found": False}},
                "action_items": [{"label": "needs-confirmation", "text": "Collect one role-separated diff."}],
                "impact_upgrade_planner": {
                    "vuln_class": "idor",
                    "current_proof_level": "baseline confirmation only",
                    "next_strongest_allowed_step": "Collect one role-separated diff.",
                    "missing_artifact_for_upgrade": "One role diff",
                    "likely_severity_if_confirmed": "high",
                    "report_ready_impact_sentence": "The issue crosses an authorization boundary.",
                    "impact_ladder": ["Show a stable 403/200 diff."],
                },
                "finding_to_impact_template": {
                    "vuln_class": "idor",
                    "proof_level": "object-boundary confirmation",
                    "impact_ladder": ["Show a stable 403/200 diff."],
                    "report_ready_impact_sentence": "The issue crosses an authorization boundary.",
                },
                "reportability_gate": {
                    "already_proven": ["The baseline issue is confirmed."],
                    "still_inferred": ["The full tenant impact is still inferred."],
                    "unsafe_to_claim_yet": ["Do not claim tenant-wide exposure yet."],
                },
                "program_specific_impact_wording": {
                    "platform": "generic",
                    "focus": "cross-tenant data exposure and privilege boundary break",
                    "wording": "Describe one direct proof artifact.",
                },
                "analysis_backend": "mcp+deterministic",
                "fallback_used": True,
            }),
            patch.object(main_module, "next_burp_action", return_value={
                "target_url": "https://example.com",
                "primary_next_action": "Send the baseline to Repeater.",
                "request_plan": ["baseline"],
                "burp_action_checklist": ["baseline first"],
                "suggested_steps": ["baseline first"],
                "labeled_steps": [{"label": "high-signal", "text": "baseline first"}],
                "dashboard_issue": {"found": False},
                "burp_context_summary": {"dashboard_issue": {"found": False}},
                "safe_vapt_escalation_steps": ["Capture baseline"],
                "labeled_safe_vapt_escalation_steps": [{"label": "high-signal", "text": "Capture baseline"}],
                "escalation_profile": "authorization-boundary",
                "baseline_confirmation": "Capture baseline",
                "business_impact_expansion_paths": ["List exposure"],
                "required_evidence_for_upgrade": ["Role diff"],
                "stop_conditions": ["Do not modify data"],
                "likely_severity_promotions": ["Tenant-wide access"],
                "scanner_focus": {"request_refs": ["proxy-1"], "highlights": [{"text": "104"}]},
                "repeater_mutation_plan": [{"location": "path", "selector": "invoice-id", "replacement": "<other-tenant-id>", "instruction": "Replace the object id."}],
                "repeater_variant_requests": [{"name": "variant-1", "request_text": "GET /api/invoices/<other-tenant-id> HTTP/1.1", "summary": "Replace id", "expected_signal": "200/403 diff"}],
                "issue_chain_strategy": ["Confirm the access-control delta first.", "Then test the XSS-marked shared view with a benign marker."],
                "related_scanner_issues": [{"found": True, "issue_name": "Stored cross-site scripting", "severity": "medium", "confidence": "firm", "host": "example.com", "path": "/comments", "target_url": "https://example.com/comments", "affected_urls": [], "background": "", "detail": "", "remediation": "", "evidence_items": [], "request_refs": [], "response_refs": [], "vuln_hint": "xss"}],
                "kb_hints": ["Local KB: IDOR note"],
                "memory_hints": ["Seen 1 similar prior exchange(s) in local memory."],
                "preferred_request_ref": "proxy-1",
                "reasoning": "Reasoning",
                "safe_to_expand": False,
                "analysis_backend": "mcp+deterministic",
                "burp_capability_recommendations": [
                    {
                        "tool": "Repeater",
                        "capability": "send_to_repeater",
                        "available": False,
                        "why": "Use Repeater for one bounded change at a time.",
                        "manual_step": "Send the baseline first.",
                        "expected_signal": "200/403 diff",
                        "stop_when": "A single reproducible high-signal delta is captured.",
                        "mcp_tool_name": "",
                        "mode": "action",
                    }
                ],
                "burp_starter_assets": {"paths": {"custom_scan_checks_dir": "D:/repo/server/burp_assets/custom_scan_checks"}},
                "curated_bapp_categories": ["passive signal collection"],
                "external_tool_recommendations": [{"name": "curl", "summary": "Replay exact requests.", "repo_url": "https://github.com/curl/curl", "install_hint": "sudo apt install -y curl"}],
            }),
            patch.object(main_module, "burp_repeater_plan", return_value={
                "target_url": "https://example.com",
                "dashboard_issue": {"found": True, "issue_name": "Insecure direct object reference", "severity": "high", "confidence": "firm", "host": "example.com", "path": "/api/invoices/104", "target_url": "https://example.com/api/invoices/104", "affected_urls": ["https://example.com/api/invoices/104"], "background": "", "detail": "", "remediation": "", "evidence_items": [], "request_refs": ["proxy-1"], "response_refs": [], "vuln_hint": "authorization"},
                "related_scanner_issues": [{"found": True, "issue_name": "Stored cross-site scripting", "severity": "medium", "confidence": "firm", "host": "example.com", "path": "/comments", "target_url": "https://example.com/comments", "affected_urls": [], "background": "", "detail": "", "remediation": "", "evidence_items": [], "request_refs": [], "response_refs": [], "vuln_hint": "xss"}],
                "burp_context_summary": {"dashboard_issue": {"found": True}, "related_scanner_issue_count": 1, "related_scanner_issue_names": ["Stored cross-site scripting"], "proxy_history_count": 1, "logger_entry_count": 0, "repeater_request_count": 1, "enabled_tool_count": 2, "config_warning_count": 0},
                "scanner_focus": {"request_refs": ["proxy-1"], "highlights": [{"text": "104"}]},
                "repeater_mutation_plan": [{"location": "path", "selector": "invoice-id", "replacement": "<other-tenant-id>", "instruction": "Replace the object id."}],
                "repeater_variant_requests": [{"name": "variant-1", "request_text": "GET /api/invoices/<other-tenant-id> HTTP/1.1", "summary": "Replace id", "expected_signal": "200/403 diff"}],
                "issue_chain_strategy": ["Confirm the access-control delta first.", "Then test the XSS-marked shared view with a benign marker."],
                "kb_hints": ["Local KB: IDOR note"],
                "memory_hints": ["Seen 1 similar prior exchange(s) in local memory."],
                "preferred_request_ref": "proxy-1",
                "baseline_confirmation": "Collect one role-separated diff.",
                "escalation_profile": "authorization-boundary",
                "analysis_backend": "mcp+deterministic",
                "safe_to_expand": False,
                "policy_gate": {"applies": False, "allowed": True},
                "burp_capability_recommendations": [
                    {
                        "tool": "Repeater",
                        "capability": "send_to_repeater",
                        "available": False,
                        "why": "Use Repeater for one bounded change at a time.",
                        "manual_step": "Send the baseline first.",
                        "expected_signal": "200/403 diff",
                        "stop_when": "A single reproducible high-signal delta is captured.",
                        "mcp_tool_name": "",
                        "mode": "action",
                    }
                ],
                "burp_starter_assets": {"paths": {"bambda_dir": "D:/repo/server/burp_assets/bambda"}},
                "curated_bapp_categories": ["API visibility"],
                "external_tool_recommendations": [{"name": "curl", "summary": "Replay exact requests.", "repo_url": "https://github.com/curl/curl", "install_hint": "sudo apt install -y curl"}],
            }),
            patch.object(main_module, "recommend_burp_capabilities", return_value={
                "primary_context_source": "burp_mcp",
                "recommendations": [
                    {
                        "tool": "Logger",
                        "capability": "proxy_history",
                        "available": True,
                        "why": "Use Logger for clean role/session diffs.",
                        "manual_step": "Compare the baseline and strongest variant side by side.",
                        "expected_signal": "Cleaner request-response delta.",
                        "stop_when": "One baseline and one stronger proof artifact are stored.",
                        "mcp_tool_name": "get_proxy_http_history",
                        "mode": "read-only",
                    }
                ],
                "starter_assets": {"paths": {"custom_scan_checks_dir": "D:/repo/server/burp_assets/custom_scan_checks"}},
                "curated_bapp_categories": ["payload encoding and decoding"],
                "external_tool_recommendations": [{"name": "jq"}],
            }),
            patch.object(main_module, "open_repeater_plan", return_value={
                "target_url": "https://example.com",
                "snapshot_id": "snap-1",
                "workflow_id": "issue:issue-1",
                "workflow_status": "planned",
                "dashboard_issue": {"found": True, "issue_id": "issue-1", "issue_name": "Insecure direct object reference", "severity": "high", "confidence": "firm", "host": "example.com", "path": "/api/invoices/104", "target_url": "https://example.com/api/invoices/104", "affected_urls": ["https://example.com/api/invoices/104"], "background": "", "detail": "", "remediation": "", "evidence_items": [], "request_refs": ["proxy-1"], "response_refs": [], "vuln_hint": "authorization"},
                "related_scanner_issues": [{"found": True, "issue_id": "issue-2", "issue_name": "Stored cross-site scripting", "severity": "medium", "confidence": "firm", "host": "example.com", "path": "/comments", "target_url": "https://example.com/comments", "affected_urls": [], "background": "", "detail": "", "remediation": "", "evidence_items": [], "request_refs": [], "response_refs": [], "vuln_hint": "xss"}],
                "preferred_request_ref": "proxy-1",
                "analysis_backend": "mcp+deterministic",
                "capability_allowed": True,
                "tool_name": "open_in_repeater",
                "dispatch_requested": True,
                "opened_count": 2,
                "tabs": [{"tab_name": "baseline-control", "request_text": "GET / HTTP/1.1", "summary": "Untouched baseline request for comparison.", "expected_signal": "Use this as the control tab before comparing variants.", "request_ref": "proxy-1", "issue_id": "issue-1"}],
                "results": [{"tab_name": "baseline-control", "status": "opened", "detail": "Repeater tab dispatched through Burp MCP.", "tool_name": "open_in_repeater"}],
                "notes": ["Burp MCP action capability available: open_in_repeater."],
            }),
            patch.object(main_module, "score_repeater_diffs", return_value={
                "baseline": {"status_code": 403, "header_count": 5, "body_length": 90, "has_body": True},
                "count": 1,
                "ranked_items": [{"tab_name": "variant-1", "summary": "Swap id", "request_ref": "proxy-1", "issue_id": "issue-1", "status_code": 200, "status_transition": "403->200", "header_delta_count": 2, "body_length_delta": 120, "body_delta_ratio": 0.41, "matched_markers": ["104"], "expected_signal": "200/403 diff", "expected_signal_matched": True, "score": 4.1, "high_signal": True, "reasons": ["HTTP status changed."]}],
                "best_item": {"tab_name": "variant-1", "score": 4.1},
                "summary": "Top tab: variant-1, status 403->200, score 4.1.",
            }),
            patch.object(main_module, "build_workflow_from_observations", return_value={
                "workflow_id": "issue:issue-1",
                "issue_id": "issue-1",
                "issue_name": "Insecure direct object reference",
                "snapshot_id": "snap-1",
                "request_id": "req-1",
                "target_url": "https://example.com",
                "source_tool": "scanner",
                "analysis_backend": "mcp+deterministic",
                "status": "high-signal-delta",
                "updated_at": "2026-04-06T00:00:00+00:00",
                "created_at": "2026-04-06T00:00:00+00:00",
                "issue_chain_strategy": ["Confirm the access-control delta first."],
                "tab_plan": [{"tab_name": "variant-1", "request_text": "GET / HTTP/1.1", "summary": "Swap id", "expected_signal": "200/403 diff", "request_ref": "proxy-1", "issue_id": "issue-1"}],
                "ranked_items": [{"tab_name": "variant-1", "score": 4.1}],
                "strongest_delta": {"tab_name": "variant-1", "score": 4.1},
                "report_readiness": {"ready": False, "status": "needs-more-evidence", "missing_evidence": ["Need one clean screenshot diff."]},
                "notes": [],
                "missing_evidence": ["Need one clean screenshot diff."],
            }),
            patch.object(main_module, "lookup_issue_workflow", return_value={
                "workflow_id": "issue:issue-1",
                "issue_id": "issue-1",
                "issue_name": "Insecure direct object reference",
                "snapshot_id": "snap-1",
                "request_id": "req-1",
                "target_url": "https://example.com",
                "source_tool": "scanner",
                "analysis_backend": "mcp+deterministic",
                "status": "high-signal-delta",
                "updated_at": "2026-04-06T00:00:00+00:00",
                "created_at": "2026-04-06T00:00:00+00:00",
                "issue_chain_strategy": ["Confirm the access-control delta first."],
                "tab_plan": [],
                "ranked_items": [{"tab_name": "variant-1", "score": 4.1}],
                "strongest_delta": {"tab_name": "variant-1", "score": 4.1},
                "report_readiness": {"ready": False, "status": "needs-more-evidence", "missing_evidence": ["Need one clean screenshot diff."]},
                "notes": [],
                "missing_evidence": ["Need one clean screenshot diff."],
            }),
            patch.object(main_module, "best_next_tab", return_value={
                "workflow_id": "issue:issue-1",
                "issue_id": "issue-1",
                "tab_name": "variant-2",
                "request_text": "GET /api/invoices/999 HTTP/1.1",
                "expected_signal": "List exposure",
                "request_ref": "proxy-1",
                "reason": "variant-2 has not been scored yet.",
                "compare_checks": ["Compare status."],
                "score_context": {"tab_name": "variant-1", "score": 4.1},
            }),
        ):
            validation = self.client.post("/api/hypotheses/validate", json={"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"})
            impact = self.client.post("/api/impact/rank", json={"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"})
            burp = self.client.post("/api/burp/next-action", json={"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"})
            capability_recs = self.client.post("/api/burp/capability-recommendations", json={"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"})
            repeater = self.client.post("/api/burp/repeater-plan", json={"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"})
            opened = self.client.post("/api/burp/open-repeater-plan", json={"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"})
            diff = self.client.post("/api/burp/repeater-diff-score", json={"raw_request": "GET / HTTP/1.1", "raw_response": "HTTP/1.1 403 Forbidden", "target_url": "https://example.com", "repeater_variant_observations": [{"tab_name": "variant-1", "response_text": "HTTP/1.1 200 OK"}]})
            workflow = self.client.post("/api/burp/issues/workflow", json={"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com", "repeater_variant_observations": [{"tab_name": "variant-1", "response_text": "HTTP/1.1 200 OK"}]})
            workflow_lookup = self.client.get("/api/burp/issues/workflow/issue-1")
            next_tab = self.client.post("/api/burp/best-next-tab", json={"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"})

        self.assertEqual(validation.status_code, 200)
        self.assertEqual(validation.json()["hypothesis"]["id"], "hyp-1")
        self.assertEqual(impact.status_code, 200)
        self.assertEqual(impact.json()["business_impact_class"], "high-impact")
        self.assertEqual(impact.json()["escalation_profile"], "authorization-boundary")
        self.assertEqual(impact.json()["impact_upgrade_planner"]["likely_severity_if_confirmed"], "high")
        self.assertEqual(impact.json()["reportability_gate"]["already_proven"][0], "The baseline issue is confirmed.")
        self.assertEqual(burp.status_code, 200)
        self.assertEqual(burp.json()["primary_next_action"], "Send the baseline to Repeater.")
        self.assertEqual(burp.json()["required_evidence_for_upgrade"][0], "Role diff")
        self.assertEqual(burp.json()["repeater_mutation_plan"][0]["location"], "path")
        self.assertEqual(burp.json()["related_scanner_issues"][0]["issue_name"], "Stored cross-site scripting")
        self.assertEqual(burp.json()["preferred_request_ref"], "proxy-1")
        self.assertEqual(burp.json()["burp_capability_recommendations"][0]["tool"], "Repeater")
        self.assertEqual(burp.json()["external_tool_recommendations"][0]["name"], "curl")
        self.assertEqual(capability_recs.status_code, 200)
        self.assertEqual(capability_recs.json()["primary_context_source"], "burp_mcp")
        self.assertEqual(capability_recs.json()["recommendations"][0]["mcp_tool_name"], "get_proxy_http_history")
        self.assertEqual(repeater.status_code, 200)
        self.assertEqual(repeater.json()["issue_chain_strategy"][0], "Confirm the access-control delta first.")
        self.assertEqual(repeater.json()["related_scanner_issues"][0]["vuln_hint"], "xss")
        self.assertEqual(repeater.json()["burp_capability_recommendations"][0]["tool"], "Repeater")
        self.assertEqual(opened.status_code, 200)
        self.assertEqual(opened.json()["opened_count"], 2)
        self.assertEqual(opened.json()["tabs"][0]["issue_id"], "issue-1")
        self.assertEqual(diff.status_code, 200)
        self.assertEqual(diff.json()["ranked_items"][0]["status_transition"], "403->200")
        self.assertEqual(workflow.status_code, 200)
        self.assertEqual(workflow.json()["workflow_id"], "issue:issue-1")
        self.assertEqual(workflow_lookup.status_code, 200)
        self.assertEqual(workflow_lookup.json()["status"], "high-signal-delta")
        self.assertEqual(next_tab.status_code, 200)
        self.assertEqual(next_tab.json()["tab_name"], "variant-2")

    def test_analyze_endpoint_defaults_to_async_job_submission(self):
        job = {
            "job_id": "job-async",
            "request_id": "req-abc",
            "status": "queued",
            "status_message": "queued",
            "estimated_duration": "30s",
            "complexity": "medium",
            "recommendation": "use jobs",
        }
        with patch.object(main_module.job_manager, "submit", return_value=job):
            response = self.client.post(
                "/api/analyze",
                headers={"X-Request-ID": "req-abc"},
                json={"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"},
            )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["job_id"], "job-async")
        self.assertEqual(response.headers["X-Request-ID"], "req-abc")
        self.assertEqual(response.headers["X-Preferred-Analysis-Endpoint"], "/api/analyze/jobs")
        self.assertEqual(response.headers["X-Deprecated-Endpoint"], "/api/analyze")
        self.assertEqual(response.headers["Deprecation"], "true")

    def test_analyze_endpoint_legacy_sync_still_returns_advisory_when_explicitly_requested(self):
        advisory = {
            "request_id": "req-abc",
            "analysis": "analysis",
            "analysis_backend": "ollama",
            "model_execution_summary": "summary",
            "model_execution_trace": ["REQUEST INFO: request_id=req-abc"],
            "provider_failover": {"final_status": "complete", "final_backend": "ollama"},
            "fallback_used": False,
            "primary_next_action": "use repeater",
            "request_plan": [],
            "tool_availability_summary": "",
            "potential_vulnerabilities": [],
            "nuclei_tags": "",
            "seclists_path": "",
            "questions_for_user": [],
            "source_links": [],
            "report_bundle": {
                "status": "active",
                "title": "Insecure direct object reference on /api/invoices/104",
                "summary": "Phase `impact` on `authorization`.",
                "phase": "impact",
                "reportability": "impact-ready",
                "top_path": "unauthorized cross-tenant invoice access",
                "proof_bundle": ["baseline request", "changed request"],
            },
        }
        with patch.object(main_module, "analyze_payload", return_value=advisory):
            response = self.client.post(
                "/api/analyze?legacy_sync=true",
                headers={"X-Request-ID": "req-abc"},
                json={"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["analysis_backend"], "ollama")
        self.assertEqual(response.json()["report_bundle"]["phase"], "impact")
        self.assertEqual(response.headers["X-Preferred-Analysis-Endpoint"], "/api/analyze/jobs")

    def test_upgrade_review_regression_benchmark_and_bundle_endpoints(self):
        with (
            patch.object(main_module, "validate_hypothesis", return_value={"validation_status": "confirmed", "hypothesis": {"vuln_class": "idor"}}),
            patch.object(main_module, "rank_impact_paths", return_value={
                "dashboard_issue": {"vuln_hint": "idor"},
                "impact_upgrade_planner": {
                    "vuln_class": "idor",
                    "current_proof_level": "object-boundary confirmation",
                    "next_strongest_allowed_step": "Confirm one cross-tenant object access.",
                    "missing_artifact_for_upgrade": "One role-separated diff.",
                    "likely_severity_if_confirmed": "high",
                    "report_ready_impact_sentence": "The issue crosses an authorization boundary.",
                    "impact_ladder": ["Keep one clean role diff."],
                },
                "finding_to_impact_template": {
                    "vuln_class": "idor",
                    "proof_level": "object-boundary confirmation",
                    "impact_ladder": ["Keep one clean role diff."],
                    "report_ready_impact_sentence": "The issue crosses an authorization boundary.",
                },
                "reportability_gate": {
                    "already_proven": ["Cross-account object access is confirmed."],
                    "still_inferred": ["The wider tenant blast radius is still inferred."],
                    "unsafe_to_claim_yet": ["Do not claim tenant-wide exposure yet."],
                },
                "reportable": True,
                "business_impact_class": "high-impact",
            }),
            patch.object(main_module, "assess_submission_severity", return_value={
                "submission_value_score": {
                    "score": 0.84,
                    "platform": "bugcrowd",
                    "components": {"reproducibility": 0.9},
                    "platform_adjustment": 0.03,
                    "platform_notes": ["Bugcrowd favors clean reproducibility."],
                    "summary": "Strong submission candidate with good triage value.",
                },
                "confidence_calibration": {"level": "high"},
            }),
            patch.object(main_module, "build_operator_review", return_value={
                "job_id": "job-200",
                "request_id": "req-200",
                "snapshot_id": "snap-200",
                "platform": "bugcrowd",
                "title": "[HIGH] IDOR",
                "strongest_evidence": ["[proxy] 200/403 diff"],
                "weakest_assumption": "Wider tenant blast radius is still inferred.",
                "next_best_allowed_step": "Confirm one cross-tenant object access.",
                "reportability_gate": {"already_proven": ["proof"]},
                "submission_value_score": {"score": 0.84},
                "confidence_to_claim_map": {"allowed_claims": ["Use direct boundary-break wording."]},
                "program_specific_impact_wording": {"platform": "bugcrowd", "focus": "cross-tenant risk", "wording": "Keep it direct."},
                "summary": "summary",
            }),
            patch.object(main_module, "build_runtime_benchmark", return_value={
                "window_count": 10,
                "latency_by_model": {"llama3.1:latest": {"count": 4, "avg_seconds": 22.5, "max_seconds": 31.0}},
                "fallback_frequency": {"history_fallback_rate": 0.1},
                "average_context_size": {"avg_chars": 420.0},
                "suggested_step_success_rate": {"workflow_success_rate": 0.6},
                "summary": "summary",
            }),
            patch.object(main_module, "build_evidence_bundle", return_value={
                "job_id": "job-200",
                "request_id": "req-200",
                "snapshot_id": "snap-200",
                "target_url": "https://example.com",
                "request_response": {"raw_request": "GET / HTTP/1.1", "raw_response": "HTTP/1.1 200 OK"},
                "burp_snapshot": {"snapshot_id": "snap-200"},
                "best_diff": {"tab_name": "variant-1", "score": 3.1},
                "planner": {
                    "vuln_class": "idor",
                    "current_proof_level": "object-boundary confirmation",
                    "next_strongest_allowed_step": "Confirm one cross-tenant object access.",
                    "missing_artifact_for_upgrade": "One role-separated diff.",
                    "likely_severity_if_confirmed": "high",
                    "report_ready_impact_sentence": "The issue crosses an authorization boundary.",
                    "impact_ladder": ["Keep one clean role diff."],
                },
                "report_draft": {"title": "draft", "summary": "summary", "impact_statement": "impact", "markdown": "# draft"},
                "guidance_hits": [],
            }),
            patch.object(main_module, "render_evidence_bundle_markdown", return_value="# bundle\n"),
            patch.object(main_module, "query_submission_regressions", return_value={
                "count": 1,
                "items": [{"id": "accepted-idor-001"}],
                "review_examples": [],
                "summary": "Loaded 1 curated regression example(s).",
            }),
            patch.object(main_module, "build_wording_comparison", return_value={
                "vuln_class": "idor",
                "platform": "bugcrowd",
                "too_vague": ["unexpected access may be possible"],
                "too_strong": ["full tenant compromise"],
                "just_right": ["another tenant invoice object is exposed"],
                "summary": "Use the just-right wording patterns as the default report tone.",
            }),
        ):
            upgrade = self.client.post("/api/impact/upgrade-plan", json={"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"})
            review = self.client.get("/api/history/jobs/job-200/operator-review")
            benchmark = self.client.get("/api/runtime/benchmark")
            bundle = self.client.get("/api/history/jobs/job-200/evidence-bundle")
            bundle_md = self.client.get("/api/history/jobs/job-200/evidence-bundle.md")
            regressions = self.client.get("/api/submissions/regressions?vuln_class=idor&outcome=accepted&platform=bugcrowd")
            wording = self.client.get("/api/submissions/wording-comparisons?vuln_class=idor&platform=bugcrowd")

        self.assertEqual(upgrade.status_code, 200)
        self.assertEqual(upgrade.json()["planner"]["likely_severity_if_confirmed"], "high")
        self.assertEqual(upgrade.json()["submission_value_score"]["platform"], "bugcrowd")
        self.assertEqual(review.status_code, 200)
        self.assertEqual(review.json()["next_best_allowed_step"], "Confirm one cross-tenant object access.")
        self.assertEqual(benchmark.status_code, 200)
        self.assertEqual(benchmark.json()["window_count"], 10)
        self.assertEqual(bundle.status_code, 200)
        self.assertEqual(bundle.json()["best_diff"]["tab_name"], "variant-1")
        self.assertEqual(bundle_md.status_code, 200)
        self.assertIn("# bundle", bundle_md.text)
        self.assertEqual(regressions.status_code, 200)
        self.assertEqual(regressions.json()["count"], 1)
        self.assertEqual(wording.status_code, 200)
        self.assertEqual(wording.json()["just_right"][0], "another tenant invoice object is exposed")


if __name__ == "__main__":
    unittest.main()
