import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server import ai_client
from server import rule_engine
from server.providers import model_execution_service


def _payload() -> SimpleNamespace:
    return SimpleNamespace(
        raw_request="POST /api/v2/internal/users/profile HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"user_id":"42","callback_url":"http://callback.test","template":"{{7*7}}"}',
        raw_response="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}",
        target_url="https://example.com/api/v2/internal/users/profile?account_id=10",
        http_method="POST",
        source_tool="repeater",
        annotations=[],
        operator_answers={},
        tool_help_text="",
        scope_includes_text="",
        scope_excludes_text="",
        rate_limit_text="",
        max_concurrency_text="",
        custom_headers_text="",
        program_policy_text="",
        tool_results_text="",
        burp_config_export_text="",
        burp_screenshot_audit_text="",
        loaded_burp_tools_text="",
        saved_program_policy_text="",
        program_screenshot_audit_text="",
        response_delta_text="",
        evidence_timeline_entries=[],
        bapp_findings_text="",
        logger_evidence_text="",
        collaborator_evidence_text="",
        privacy_mode_override="",
        selected_profile="bug-bounty-safe",
        review_scope_include_classes=[],
        review_scope_exclude_classes=[],
        burp_dashboard_issue={},
        burp_related_scanner_issues=[],
        batch_id="",
        batch_index=0,
        batch_total=0,
    )


def _rule_context() -> dict:
    return {
        "aggregate": {
            "tool_availability_summary": "stub-tools",
            "manual_tooling": ["curl"],
            "manual_commands": ["curl -i https://example.com/"],
            "payload_recommendations": ["<baseline>"],
            "bcheck_recommendations": ["passive-check"],
            "impact_paths": ["impact-path"],
            "burp_settings_recommendations": ["keep baseline"],
            "project_readiness_summary": "ready",
            "project_readiness_checks": ["ok"],
            "burp_action_checklist": ["baseline first"],
            "suggestion_queue": ["next step"],
            "confidence_by_class": ["idor: 0.7"],
            "confirmation_playbooks": ["collect a stable diff"],
        },
        "complexity": {
            "level": "medium",
            "eta": "about 45 seconds",
            "recommendation": "test one hypothesis at a time",
        },
        "features": {
            "observations": ["json response"],
            "param_names": ["user_id"],
            "response_content_type": "application/json",
            "request_content_type": "application/json",
        },
        "matched_recipes": [
            {
                "vuln_class": "access-control",
                "title": "IDOR Check",
                "summary": "Check identifier-based access boundaries.",
                "severity": "high",
                "evidence": ["identifier-like parameter names matched"],
            }
        ],
        "review_scope": {
            "allowed_classes": ["access-control"],
            "suppressed_classes": [],
        },
    }


def _fallback() -> dict:
    return {
        "analysis": "deterministic analysis",
        "primary_next_action": "keep the baseline stable",
        "request_plan": ["baseline", "compare"],
        "tool_availability_summary": "stub-tools",
        "potential_vulnerabilities": ["[idor] object access boundary"],
        "nuclei_tags": "idor,access-control",
        "seclists_path": "/usr/share/seclists/example.txt",
        "questions_for_user": ["Which account owns this object?"],
        "source_links": ["https://portswigger.net/web-security/access-control/idor"],
        "manual_tooling": ["curl"],
        "manual_commands": ["curl -i https://example.com/"],
        "payload_recommendations": ["<baseline>"],
        "bcheck_recommendations": ["passive-check"],
        "impact_paths": ["impact-path"],
        "burp_settings_recommendations": ["keep baseline"],
        "project_readiness_summary": "ready",
        "project_readiness_checks": ["ok"],
        "burp_action_checklist": ["baseline first"],
        "burp_screenshot_review_status": "No screenshot vision review was performed.",
        "suggestion_queue": ["next step"],
        "confidence_by_class": ["idor: 0.7"],
        "history_correlation": [],
        "confirmation_playbooks": ["collect a stable diff"],
    }


class PhaseOneAndTwoPipelineTests(unittest.TestCase):
    def test_phase1_feature_signals_cover_api_internal_and_template_markers(self):
        features = rule_engine.extract_features(_payload())
        signals = features["signals"]

        self.assertIn("request_has_identifier_params", signals)
        self.assertIn("request_has_url_input_params", signals)
        self.assertIn("request_has_template_input_params", signals)
        self.assertIn("request_has_template_syntax_markers", signals)
        self.assertIn("path_has_api_version", signals)
        self.assertIn("path_looks_internal", signals)

    def test_phase2_enforces_planner_schema_rejects_invalid(self):
        candidate = {
            "analysis": "analysis",
            "primary_next_action": "next",
            "request_plan": ["Target parameter: id", "Compare baseline and mutated request"],
            "potential_vulnerabilities": ["[idor] object access issue"],
            "questions_for_user": ["Which role should access id?"],
            "planner": {"vuln_type": "idor", "confidence": 0.88},
        }
        normalized, error = model_execution_service.enforce_candidate_planner_schema(candidate)

        self.assertFalse(normalized)
        self.assertIn("Invalid planner schema", error)

    def test_phase2_falls_back_when_provider_returns_invalid_planner(self):
        payload = _payload()
        invalid_planner_candidate = {
            "analysis": "mcp analysis",
            "primary_next_action": "send one request",
            "request_plan": ["Target parameter: id"],
            "potential_vulnerabilities": ["[idor] object access issue"],
            "questions_for_user": ["Which account should own this id?"],
            "planner": {"vuln_type": "idor", "confidence": 0.8},
        }
        with (
            patch.object(ai_client, "get_profile", return_value={"memory_top_k": 0, "kb_top_k": 0}),
            patch.object(ai_client, "build_rule_context", return_value=_rule_context()),
            patch.object(ai_client, "build_endpoint_fingerprint", return_value={"signature": "sig"}),
            patch.object(ai_client, "find_similar_history", return_value=[]),
            patch.object(ai_client, "summarize_similar_findings", return_value={"total_hits": 0}),
            patch.object(ai_client, "describe_history_correlation", return_value=["No history."]),
            patch.object(ai_client, "search_notes_detailed", return_value={"context": "No context found.", "hits": []}),
            patch.object(ai_client, "summarize_collaborator_evidence", return_value={"confidence_notes": []}),
            patch.object(ai_client, "_review_burp_settings_screenshots", return_value={"status": "", "summary": ""}),
            patch.object(ai_client, "_fallback_analysis", return_value=_fallback()),
            patch.object(ai_client, "_configured_model_providers", return_value=["mcp"]),
            patch.object(
                ai_client,
                "_call_mcp_provider",
                return_value=(invalid_planner_candidate, "MCP returned candidate."),
            ),
        ):
            result = ai_client.analyze_traffic(payload)

        self.assertEqual(result["analysis_backend"], "deterministic")
        self.assertTrue(result["fallback_used"])
        self.assertTrue(any("Invalid planner schema" in entry for entry in result["model_execution_trace"]))

    def test_rule_context_prefers_selected_scanner_anchor_class_over_related_siblings(self):
        payload = _payload()
        payload.annotations = ["audit_issue_selected", "scanner_context"]
        payload.source_tool = "burp-suite-montoya-scanner-scanner_results-audit-issue"
        payload.burp_dashboard_issue = {
            "name": "Cross-site scripting (stored)",
            "detail": "The tbComment parameter is copied into the HTML document as plain text between tags.",
            "url": "https://example.com/Comments.aspx?id=2",
        }
        payload.bapp_findings_text = (
            "Selected Burp audit issue(s) for https://example.com/Comments.aspx:\n"
            "- Cross-site scripting (stored) | severity: High | confidence: Certain\n"
            "Auto-collected Burp audit issues for https://example.com/Comments.aspx:\n"
            "- SQL injection | severity: High | confidence: Firm\n"
        )

        context = rule_engine.build_rule_context(payload)

        self.assertEqual("xss", context["matched_recipes"][0]["vuln_class"])


if __name__ == "__main__":
    unittest.main()
