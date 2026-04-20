import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.core import analysis_service
from server.core.model_routing_service import choose_ollama_model_for_request
from server.core.runtime_model_service import scheduler_policy_snapshot


class PhaseThreeAndFourTests(unittest.TestCase):
    def test_bounded_workflow_loop_respects_step_cap_and_stops_on_repeat(self):
        payload = SimpleNamespace(source_tool="scanner", raw_request="GET / HTTP/1.1", target_url="https://example.com")
        base_bundle = {
            "advisory": {
                "analysis": "base analysis",
                "primary_next_action": "Capture baseline diff.",
            },
            "run": {"phases": {}, "phase_results": {}},
        }
        observations = [
            {
                "workflow_status": "planned",
                "next_tab_name": "variant-1",
                "next_tab_signal": "200/403 diff",
                "strongest_delta_score": 0.0,
                "report_ready": False,
                "next_tab_has_request": True,
                "observation_fingerprint": "obs:a",
            },
            {
                "workflow_status": "planned",
                "next_tab_name": "variant-1",
                "next_tab_signal": "200/403 diff",
                "strongest_delta_score": 0.0,
                "report_ready": False,
                "next_tab_has_request": True,
                "observation_fingerprint": "obs:a",
            },
        ]

        with (
            patch.object(analysis_service, "analyze_exchange", return_value=base_bundle),
            patch("server.core.issue_workflow_service.build_workflow_observation", side_effect=observations),
        ):
            bounded = analysis_service.analyze_exchange_bounded(payload, step_cap=4)

        loop = bounded["run"]["phases"]["workflow_loop"]
        self.assertEqual(loop["step_count"], 2)
        self.assertEqual(loop["stop_reason"], "no-new-observation")
        self.assertLessEqual(loop["step_count"], loop["step_cap"])

    def test_model_routing_uses_fast_model_for_low_signal_triage(self):
        payload = SimpleNamespace(
            source_tool="repeater",
            annotations=[],
            collaborator_evidence_text="",
            logger_evidence_text="",
            response_delta_text="",
            evidence_timeline_entries=[],
            bapp_findings_text="",
        )
        with (
            patch("server.core.model_routing_service.read_runtime_model_override", return_value={}),
            patch("server.core.model_routing_service.get_active_ollama_model", return_value="llama3.2:3b"),
            patch("server.core.model_routing_service.OLLAMA_FAST_MODEL", "qwen3:1.7b"),
            patch("server.core.model_routing_service.MODEL_ROUTING_FAST_SCORE_THRESHOLD", 1),
        ):
            route = choose_ollama_model_for_request(payload, profile_name="bug-bounty-safe", rule_context={}, fallback={})

        self.assertEqual(route["route"], "triage-fast")
        self.assertEqual(route["model"], "qwen3:1.7b")
        self.assertEqual(route["request_type"], "repeater")

    def test_model_routing_does_not_use_deep_without_high_signal_case(self):
        payload = SimpleNamespace(
            source_tool="repeater",
            annotations=[],
            collaborator_evidence_text="dns observed",
            logger_evidence_text="delta observed",
            response_delta_text="status changed",
            evidence_timeline_entries=["note1"],
            bapp_findings_text="extra findings",
        )
        rule_context = {"matched_recipes": [{"vuln_class": "xss"}]}
        fallback = {"confidence_by_class": ["xss: 0.92 confidence - strong reflection"]}
        with (
            patch("server.core.model_routing_service.read_runtime_model_override", return_value={}),
            patch("server.core.model_routing_service.get_active_ollama_model", return_value="llama3.2:3b"),
            patch("server.core.model_routing_service.OLLAMA_DEEP_MODEL", "llama3.2:8b"),
            patch("server.core.model_routing_service.MODEL_ROUTING_DEEP_SCORE_THRESHOLD", 4),
            patch("server.core.model_routing_service.MODEL_ROUTING_DEEP_MIN_SIGNAL_COUNT", 2),
        ):
            route = choose_ollama_model_for_request(
                payload,
                profile_name="bug-bounty-safe",
                rule_context=rule_context,
                fallback=fallback,
            )

        self.assertNotEqual(route["route"], "auto-deep")
        self.assertNotEqual(route["model"], "llama3.2:8b")

    def test_scheduler_policy_snapshot_exposes_sequential_settings(self):
        policy = scheduler_policy_snapshot()
        self.assertIn("sequential_only", policy)
        self.assertIn("provider_order", policy)
        self.assertIn("routing", policy)
        self.assertIn("deep_requires_scanner_context", policy["routing"])
        self.assertIn("deep_requires_observed_evidence", policy["routing"])
        self.assertIn("deep_allows_scanner_followup_context", policy["routing"])
        self.assertIn("deep_allows_investigation_notebook_context", policy["routing"])


if __name__ == "__main__":
    unittest.main()
