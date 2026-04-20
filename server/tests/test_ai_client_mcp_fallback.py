import unittest
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server import ai_client
from server.mcp_client import MCPConfigurationError


def _payload() -> SimpleNamespace:
    return SimpleNamespace(
        raw_request="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        raw_response="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok",
        target_url="https://example.com/",
        http_method="GET",
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
            "confidence_by_class": ["xss: 0.7"],
            "confirmation_playbooks": ["collect a stable diff"],
        },
        "complexity": {
            "level": "medium",
            "eta": "about 45 seconds",
            "recommendation": "test one hypothesis at a time",
        },
        "features": {
            "observations": ["html response"],
            "param_names": [],
            "response_content_type": "text/html",
            "request_content_type": "",
        },
        "matched_recipes": [],
        "review_scope": {
            "allowed_classes": ["xss"],
            "suppressed_classes": [],
        },
    }


def _fallback() -> dict:
    return {
        "analysis": "deterministic analysis",
        "primary_next_action": "keep the baseline stable",
        "request_plan": ["baseline", "compare"],
        "tool_availability_summary": "stub-tools",
        "potential_vulnerabilities": ["[xss] reflected output"],
        "nuclei_tags": "xss",
        "seclists_path": "/usr/share/seclists/example.txt",
        "questions_for_user": ["What reflected?"],
        "source_links": ["https://portswigger.net/web-security/cross-site-scripting"],
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
        "confidence_by_class": ["xss: 0.7"],
        "history_correlation": [],
        "confirmation_playbooks": ["collect a stable diff"],
    }


class AnalyzeTrafficMcpFallbackTests(unittest.TestCase):
    def test_skip_model_reason_uses_provider_fallback_without_crashing(self):
        payload = _payload()
        with (
            patch.object(ai_client, "get_profile", return_value={"memory_top_k": 0, "kb_top_k": 0}),
            patch.object(ai_client, "build_rule_context", return_value=_rule_context()),
            patch.object(ai_client, "build_endpoint_fingerprint", return_value={"signature": "sig", "memory_partition_key": "generic:default:example-com"}),
            patch.object(ai_client, "find_similar_history", return_value=[]),
            patch.object(ai_client, "summarize_similar_findings", return_value={"total_hits": 0}),
            patch.object(ai_client, "describe_history_correlation", return_value=["No history."]),
            patch.object(ai_client, "search_notes_detailed", return_value={"context": "No context found.", "hits": []}),
            patch.object(ai_client, "_query_guidance_packs", return_value={"context": "", "hits": []}),
            patch.object(ai_client, "_query_review_examples", return_value={"summary": "", "items": []}),
            patch.object(ai_client, "summarize_collaborator_evidence", return_value={"confidence_notes": []}),
            patch.object(ai_client, "_review_burp_settings_screenshots", return_value={"status": "", "summary": ""}),
            patch.object(ai_client, "_skip_model_reason", return_value="low-signal request skipped model refinement"),
            patch.object(ai_client, "_build_analysis_prompt", return_value="prompt"),
            patch.object(ai_client, "inventory_summary_text", return_value="inventory-summary"),
            patch("server.core.repeater_guidance_service.build_repeater_escalation_plan", return_value={"repeater_mutation_plan": [], "issue_chain_strategy": []}),
            patch("server.core.burp_capability_service.recommend_burp_capabilities", return_value={"recommendations": [], "starter_assets": {}}),
        ):
            result = ai_client.analyze_traffic(payload)

        self.assertEqual(result["analysis_backend"], "deterministic")
        self.assertTrue(result["fallback_used"])
        self.assertIn("Model refinement skipped", result["analysis"])
        self.assertEqual(result["provider_failover"]["final_status"], "deterministic-fallback")

    def test_partial_mcp_response_uses_deterministic_fallback(self):
        payload = _payload()
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
            patch.object(ai_client, "_call_mcp_provider", return_value=({"analysis": "mcp analysis"}, "MCP returned only analysis.")),
            patch("server.core.repeater_guidance_service.build_repeater_escalation_plan", return_value={"repeater_mutation_plan": [], "issue_chain_strategy": []}),
            patch("server.core.burp_capability_service.recommend_burp_capabilities", return_value={"recommendations": [], "starter_assets": {}}),
        ):
            result = ai_client.analyze_traffic(payload)

        self.assertEqual(result["analysis_backend"], "mcp+deterministic")
        self.assertTrue(result["fallback_used"])
        self.assertEqual(result["request_plan"], ["baseline", "compare"])
        self.assertIn("Model execution:", result["analysis"])
        self.assertTrue(any("MCP PARTIAL" in entry for entry in result["model_execution_trace"]))
        self.assertEqual(result["provider_failover"]["final_status"], "partial-with-deterministic-backfill")
        self.assertEqual(result["provider_failover"]["outcomes"][0]["status"], "partial")

    def test_mcp_configuration_error_stays_on_mcp_only_and_falls_back_to_deterministic(self):
        payload = _payload()
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
            patch.object(ai_client, "_configured_model_providers", return_value=["mcp", "ollama"]),
            patch.object(ai_client, "_call_mcp_provider", side_effect=MCPConfigurationError("MCP server command is missing.")),
            patch.object(ai_client, "_call_ollama_provider") as mocked_ollama,
            patch("server.core.repeater_guidance_service.build_repeater_escalation_plan", return_value={"repeater_mutation_plan": [], "issue_chain_strategy": []}),
            patch("server.core.burp_capability_service.recommend_burp_capabilities", return_value={"recommendations": [], "starter_assets": {}}),
        ):
            result = ai_client.analyze_traffic(payload)

        self.assertEqual(result["analysis_backend"], "deterministic")
        self.assertTrue(result["fallback_used"])
        self.assertEqual(result["primary_next_action"], "keep the baseline stable")
        self.assertTrue(any("MCP SKIPPED" in entry for entry in result["model_execution_trace"]))
        self.assertTrue(any("OLLAMA SKIPPED" in entry for entry in result["model_execution_trace"]))
        self.assertFalse(result["provider_failover"]["mcp_fallback_triggered"])
        self.assertEqual(result["provider_failover"]["outcomes"][0]["status"], "skipped")
        self.assertEqual(result["provider_failover"]["outcomes"][1]["status"], "skipped")
        mocked_ollama.assert_not_called()


if __name__ == "__main__":
    unittest.main()
