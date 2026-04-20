import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server import local_guidance_db
from server import burp_asset_feedback
from server.core import benchmark_service
from server.core import burp_capability_service
from server import submission_regression


class IntelligenceExtensionTests(unittest.TestCase):
    def test_guidance_decay_applies_for_partition_with_negative_history(self):
        with (
            patch.object(local_guidance_db, "read_negative_reasoning", return_value=[
                {"memory_partition_key": "target:a", "vuln_classes": ["idor"]},
                {"memory_partition_key": "target:a", "vuln_classes": ["idor"]},
            ]),
            patch.object(local_guidance_db, "read_review_examples", return_value=[
                {"memory_partition_key": "target:a", "vuln_classes": ["idor"], "outcome_label": "scanner-review"},
            ]),
        ):
            decay = local_guidance_db.guidance_decay_scores(partition_key="target:a", vuln_classes=["idor"])

        self.assertGreaterEqual(decay["workflow-payload"], 1)
        self.assertGreaterEqual(decay["validation-impact"], 1)

    def test_submission_regression_wording_comparison_reads_seed_examples(self):
        comparison = submission_regression.build_wording_comparison("idor", platform="bugcrowd")

        self.assertEqual(comparison["vuln_class"], "idor")
        self.assertTrue(comparison["just_right"])

    def test_runtime_benchmark_summarizes_history_workflow_and_learning(self):
        with (
            patch.object(benchmark_service, "read_history_records", return_value=[
                {
                    "raw_request": "GET /a HTTP/1.1",
                    "raw_response": "HTTP/1.1 200 OK",
                    "tool_results_text": "baseline",
                    "created_at": "2026-04-07T00:00:00+00:00",
                    "started_at": "2026-04-07T00:00:00+00:00",
                    "completed_at": "2026-04-07T00:00:20+00:00",
                    "result": {"model_strategy": {"active_model": "llama3.1:latest"}, "fallback_used": False},
                    "analysis_run": {"input_context": {"target_url": "https://example.com", "source_tool": "scanner"}},
                },
                {
                    "raw_request": "GET /b HTTP/1.1",
                    "raw_response": "HTTP/1.1 403 Forbidden",
                    "tool_results_text": "variant",
                    "created_at": "2026-04-07T00:01:00+00:00",
                    "started_at": "2026-04-07T00:01:00+00:00",
                    "completed_at": "2026-04-07T00:01:10+00:00",
                    "result": {"model_strategy": {"active_model": "qwen3:1.7b"}, "fallback_used": False},
                    "analysis_run": {"input_context": {"target_url": "https://example.com", "source_tool": "repeater"}},
                },
                {
                    "raw_request": "GET /c HTTP/1.1",
                    "raw_response": "HTTP/1.1 200 OK",
                    "tool_results_text": "follow-up",
                    "created_at": "2026-04-07T00:02:00+00:00",
                    "started_at": "2026-04-07T00:02:00+00:00",
                    "completed_at": "2026-04-07T00:02:09+00:00",
                    "result": {"model_strategy": {"active_model": "qwen3:1.7b"}, "fallback_used": False},
                    "analysis_run": {"input_context": {"target_url": "https://example.com", "source_tool": "repeater"}},
                },
                {
                    "raw_request": "GET /d HTTP/1.1",
                    "raw_response": "HTTP/1.1 500 Internal Server Error",
                    "tool_results_text": "rollback",
                    "created_at": "2026-04-07T00:03:00+00:00",
                    "started_at": "2026-04-07T00:03:00+00:00",
                    "completed_at": "2026-04-07T00:03:08+00:00",
                    "result": {"model_strategy": {"active_model": "qwen3:1.7b"}, "fallback_used": False},
                    "analysis_run": {"input_context": {"target_url": "https://example.com", "source_tool": "proxy"}},
                },
            ]),
            patch.object(benchmark_service, "read_provider_diagnostics", return_value=[]),
            patch.object(benchmark_service, "read_issue_workflow_states", return_value=[
                {"strongest_delta": {"score": 3.0}}
            ]),
            patch.object(benchmark_service, "read_repeater_learning", return_value=[
                {"suggested_step_success": True}
            ]),
            patch.object(benchmark_service, "BENCHMARK_SNAPSHOT_ENABLED", False),
        ):
            result = benchmark_service.build_runtime_benchmark(limit=20)

        self.assertIn("llama3.1:latest", result["latency_by_model"])
        self.assertIn("memory_by_model", result)
        self.assertIn("rollout_comparison", result)
        self.assertIn("model_matrix", result)
        self.assertIn("diagnostics", result)
        self.assertEqual(result["suggested_step_success_rate"]["workflow_success_count"], 1)

    def test_burp_starter_assets_and_capability_recommendations_include_production_metadata(self):
        assets = burp_capability_service.burp_starter_assets("idor")

        self.assertEqual(assets["manifest_version"]["custom_scan_checks"], "2026-04-10")
        self.assertTrue(assets["recommended_import_order"])
        self.assertTrue(assets["usage_notes"])
        self.assertEqual(assets["custom_scan_checks"][0]["scan_mode"], "passive")
        self.assertEqual(assets["bambda_packs"][0]["recommended_burp_feature"], "Logger or Repeater editor tagging")

        with patch.object(burp_capability_service, "inspect_burp_mcp_capabilities", return_value={"server_name": "burp-mcp", "capability_map": {}}):
            recommendations = burp_capability_service.recommend_burp_capabilities(
                {"raw_request": "GET /api/users/123 HTTP/1.1", "target_url": "https://example.com/api/users/123"},
                impact={"dashboard_issue": {"vuln_hint": "idor"}},
            )

        custom_scan_entry = next(item for item in recommendations["recommendations"] if item["tool"] == "Custom Scan Check")
        bambda_entry = next(item for item in recommendations["recommendations"] if item["tool"] == "Bambda")
        self.assertEqual(custom_scan_entry["recommended_asset_type"], "custom_scan_check")
        self.assertEqual(custom_scan_entry["recommended_asset_id"], "idor-bola-check")
        self.assertEqual(bambda_entry["recommended_asset_type"], "bambda")
        self.assertEqual(bambda_entry["recommended_asset_id"], "object-identifier-markers")

    def test_burp_starter_assets_apply_target_specific_feedback_ranking(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            feedback_path = Path(temp_dir) / "burp_asset_feedback.jsonl"
            with patch.object(burp_asset_feedback, "BURP_ASSET_FEEDBACK_PATH", feedback_path):
                burp_asset_feedback.append_asset_feedback(
                    asset_type="custom_scan_check",
                    asset_id="idor-bola-check",
                    label="useful",
                    target_url="https://tenant.example.com/api/invoices/42",
                    vuln_class="idor",
                    selected_profile="bug-bounty-safe",
                )
                burp_asset_feedback.append_asset_feedback(
                    asset_type="custom_scan_check",
                    asset_id="mass-assignment-check",
                    label="false_positive",
                    target_url="https://tenant.example.com/api/invoices/42",
                    vuln_class="idor",
                    selected_profile="bug-bounty-safe",
                )
                with patch.object(burp_capability_service, "asset_feedback_scores", side_effect=burp_asset_feedback.asset_feedback_scores):
                    assets = burp_capability_service.burp_starter_assets(
                        "idor",
                        payload_like={
                            "target_url": "https://tenant.example.com/api/invoices/42",
                            "selected_profile": "bug-bounty-safe",
                        },
                    )

        self.assertTrue(assets["feedback_applied"])
        self.assertEqual(assets["custom_scan_checks"][0]["id"], "idor-bola-check")
        self.assertGreater(assets["custom_scan_checks"][0]["feedback_score"], 0)


if __name__ == "__main__":
    unittest.main()
