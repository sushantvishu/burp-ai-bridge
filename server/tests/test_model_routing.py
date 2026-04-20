import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.core.model_routing_service import choose_ollama_model_for_request


class ModelRoutingTests(unittest.TestCase):
    def test_high_signal_scanner_flow_routes_to_deep_model(self):
        payload = SimpleNamespace(
            source_tool="scanner",
            annotations=["scanner_results_context"],
            collaborator_evidence_text="dns interaction observed",
            logger_evidence_text="403 -> 200",
            response_delta_text="stable body delta",
            evidence_timeline_entries=["baseline", "callback"],
            bapp_findings_text="Scanner issue details",
        )
        rule_context = {"matched_recipes": [{"vuln_class": "ssrf"}]}
        fallback = {"confidence_by_class": ["ssrf: 0.84 confidence - callback observed"]}
        with (
            patch("server.core.model_routing_service.read_runtime_model_override", return_value={}),
            patch("server.core.model_routing_service.get_active_ollama_model", return_value="llama3.2:3b"),
            patch("server.core.model_routing_service.OLLAMA_DEEP_MODEL", "llama3.1:latest"),
        ):
            route = choose_ollama_model_for_request(
                payload,
                profile_name="deep-escalation-llama32-7b",
                rule_context=rule_context,
                fallback=fallback,
            )

        self.assertEqual(route["model"], "llama3.1:latest")
        self.assertEqual(route["route"], "auto-deep")
        self.assertGreaterEqual(route["score"], 4)

    def test_scanner_context_without_observed_evidence_stays_on_primary_model(self):
        payload = SimpleNamespace(
            source_tool="scanner",
            annotations=["scanner_results_context"],
            collaborator_evidence_text="",
            logger_evidence_text="",
            response_delta_text="",
            evidence_timeline_entries=[],
            bapp_findings_text="Scanner issue details",
        )
        rule_context = {"matched_recipes": [{"vuln_class": "ssrf"}]}
        fallback = {"confidence_by_class": ["ssrf: 0.92 confidence - scanner marker only"]}
        with (
            patch("server.core.model_routing_service.read_runtime_model_override", return_value={}),
            patch("server.core.model_routing_service.get_active_ollama_model", return_value="llama3.2:3b"),
            patch("server.core.model_routing_service.OLLAMA_DEEP_MODEL", "qwen3:8b"),
            patch("server.core.model_routing_service.MODEL_ROUTING_DEEP_SCORE_THRESHOLD", 4),
            patch("server.core.model_routing_service.MODEL_ROUTING_DEEP_MIN_SIGNAL_COUNT", 2),
        ):
            route = choose_ollama_model_for_request(
                payload,
                profile_name="",
                rule_context=rule_context,
                fallback=fallback,
            )

        self.assertEqual(route["model"], "llama3.2:3b")
        self.assertNotEqual(route["route"], "auto-deep")
        self.assertTrue(any("no observed evidence" in reason.lower() for reason in route["reasons"]))

    def test_manual_override_prevents_auto_routing(self):
        payload = SimpleNamespace(
            source_tool="scanner",
            annotations=["scanner_results_context"],
            collaborator_evidence_text="dns interaction observed",
            logger_evidence_text="403 -> 200",
            response_delta_text="stable body delta",
            evidence_timeline_entries=["baseline", "callback"],
            bapp_findings_text="Scanner issue details",
        )
        with (
            patch("server.core.model_routing_service.read_runtime_model_override", return_value={"active_model": "llama3.2:3b"}),
            patch("server.core.model_routing_service.get_active_ollama_model", return_value="llama3.2:3b"),
        ):
            route = choose_ollama_model_for_request(payload, profile_name="deep-escalation-llama32-7b", rule_context={}, fallback={})

        self.assertEqual(route["model"], "llama3.2:3b")
        self.assertEqual(route["route"], "manual-override")

    def test_fast_time_budget_disables_deep_routing_for_scanner_issue(self):
        payload = SimpleNamespace(
            source_tool="scanner",
            annotations=["scanner_results_context", "time_budget_fast"],
            collaborator_evidence_text="dns interaction observed",
            logger_evidence_text="403 -> 200",
            response_delta_text="stable body delta",
            evidence_timeline_entries=["baseline", "callback"],
            bapp_findings_text="Scanner issue details",
        )
        with (
            patch("server.core.model_routing_service.read_runtime_model_override", return_value={}),
            patch("server.core.model_routing_service.get_active_ollama_model", return_value="llama3.2:3b"),
            patch("server.core.model_routing_service.OLLAMA_FAST_MODEL", "qwen3:1.7b"),
            patch("server.core.model_routing_service.OLLAMA_DEEP_MODEL", "qwen3:8b"),
        ):
            route = choose_ollama_model_for_request(payload, profile_name="", rule_context={}, fallback={})

        self.assertEqual(route["model"], "llama3.2:3b")
        self.assertEqual(route["route"], "budget-fast-primary")
        self.assertTrue(any("fast time budget" in reason.lower() for reason in route["reasons"]))

    def test_deep_time_budget_forces_deeper_model(self):
        payload = SimpleNamespace(
            source_tool="scanner",
            annotations=["scanner_results_context", "time_budget_deep"],
            collaborator_evidence_text="",
            logger_evidence_text="",
            response_delta_text="",
            evidence_timeline_entries=[],
            bapp_findings_text="",
        )
        with (
            patch("server.core.model_routing_service.read_runtime_model_override", return_value={}),
            patch("server.core.model_routing_service.get_active_ollama_model", return_value="llama3.2:3b"),
            patch("server.core.model_routing_service.OLLAMA_DEEP_MODEL", "qwen3:8b"),
        ):
            route = choose_ollama_model_for_request(payload, profile_name="", rule_context={}, fallback={})

        self.assertEqual(route["model"], "qwen3:8b")
        self.assertEqual(route["route"], "budget-deep")
        self.assertTrue(any("deep time budget" in reason.lower() for reason in route["reasons"]))

    def test_scanner_follow_up_with_workflow_notes_routes_to_deep_model(self):
        payload = SimpleNamespace(
            source_tool="scanner",
            annotations=["scanner_results_context", "audit_issue_selected", "operator_followup"],
            collaborator_evidence_text="",
            logger_evidence_text="",
            response_delta_text="",
            evidence_timeline_entries=[],
            issue_workflow_notes=[
                "Latest exact change summary: Keep the same insertion point and compare reflected output encoding.",
                "Transcript [2026-04-11 20:10:10] AI Bridge: Confirm the reflection context before broader payload changes.",
            ],
            bapp_findings_text="Selected Burp audit issue(s) for https://example.com/comments: Input returned in response (reflected).",
        )
        with (
            patch("server.core.model_routing_service.read_runtime_model_override", return_value={}),
            patch("server.core.model_routing_service.get_active_ollama_model", return_value="llama3.2:3b"),
            patch("server.core.model_routing_service.OLLAMA_DEEP_MODEL", "qwen3:8b"),
        ):
            route = choose_ollama_model_for_request(payload, profile_name="", rule_context={}, fallback={})

        self.assertEqual(route["model"], "qwen3:8b")
        self.assertEqual(route["route"], "scanner-follow-up-deep")
        self.assertTrue(any("follow-up" in reason.lower() for reason in route["reasons"]))

    def test_scanner_follow_up_with_persistent_notebook_routes_to_deep_model(self):
        payload = SimpleNamespace(
            source_tool="scanner",
            annotations=["scanner_results_context", "audit_issue_selected", "operator_followup"],
            collaborator_evidence_text="",
            logger_evidence_text="",
            response_delta_text="",
            evidence_timeline_entries=[],
            issue_workflow_notes=[],
            investigation_notebook_text=(
                "Investigation anchor\n"
                "- Source: Scanner Audit Issue\n"
                "- Target: https://example.com/comments?id=1\n"
                "\nPersistent notebook timeline\n"
                "- [2026-04-11 22:15:00] Operator follow-up: Tell me the next exact reflected-XSS check.\n"
                "- [2026-04-11 22:15:05] AI guidance update: Primary next action: Keep the same reflection point and compare output encoding."
            ),
            bapp_findings_text="Selected Burp audit issue(s) for https://example.com/comments: Input returned in response (reflected).",
        )
        with (
            patch("server.core.model_routing_service.read_runtime_model_override", return_value={}),
            patch("server.core.model_routing_service.get_active_ollama_model", return_value="llama3.2:3b"),
            patch("server.core.model_routing_service.OLLAMA_DEEP_MODEL", "qwen3:8b"),
        ):
            route = choose_ollama_model_for_request(payload, profile_name="", rule_context={}, fallback={})

        self.assertEqual(route["model"], "qwen3:8b")
        self.assertEqual(route["route"], "scanner-follow-up-deep")
        self.assertTrue(any("notebook" in reason.lower() for reason in route["reasons"]))


if __name__ == "__main__":
    unittest.main()
