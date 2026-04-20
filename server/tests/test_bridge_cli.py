import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server import bridge_cli


class BridgeCliTests(unittest.TestCase):
    def test_load_env_file_sets_missing_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text("OLLAMA_MODEL=test-model\nOBSERVABILITY_AUTH_TOKEN=secret\n", encoding="utf-8")
            old_model = os.environ.get("OLLAMA_MODEL")
            old_token = os.environ.pop("OBSERVABILITY_AUTH_TOKEN", None)
            try:
                os.environ["OLLAMA_MODEL"] = "old-model"
                bridge_cli.load_env_file(str(env_path))
                self.assertEqual(os.environ["OLLAMA_MODEL"], "test-model")
                self.assertEqual(os.environ["OBSERVABILITY_AUTH_TOKEN"], "secret")
            finally:
                if old_model is not None:
                    os.environ["OLLAMA_MODEL"] = old_model
                else:
                    os.environ.pop("OLLAMA_MODEL", None)
                if old_token is not None:
                    os.environ["OBSERVABILITY_AUTH_TOKEN"] = old_token
                else:
                    os.environ.pop("OBSERVABILITY_AUTH_TOKEN", None)

    def test_fetch_observability_builds_expected_request(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.text = "ok"
        with patch.object(bridge_cli.requests, "get", return_value=response) as mocked_get:
            bridge_cli.fetch_observability(
                base_url="http://127.0.0.1:8000",
                resource="audit",
                output_format="json",
                token="secret",
                request_id="req-1",
                query={"limit": 10, "event_type": "job_submit"},
            )

        mocked_get.assert_called_once()
        args, kwargs = mocked_get.call_args
        self.assertIn("/api/audit/events", args[0])
        self.assertIn("event_type=job_submit", args[0])
        self.assertEqual(kwargs["headers"]["X-Bridge-Admin-Token"], "secret")
        self.assertEqual(kwargs["headers"]["X-Request-ID"], "req-1")

    def test_doctor_prints_effective_settings_snapshot(self):
        args = bridge_cli.build_parser().parse_args(["doctor", "--output", "json"])
        with patch.object(bridge_cli, "load_env_file"), patch.object(
            bridge_cli,
            "effective_settings_snapshot",
            return_value={"provider_order": ["mcp", "ollama"], "default_runtime_strategy": "mcp-grounded-llama32"},
        ):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = bridge_cli.main(["doctor", "--output", "json"])

        self.assertEqual(exit_code, 0)
        self.assertIn("mcp-grounded-llama32", buffer.getvalue())

    def test_serve_reuses_running_bridge_when_port_is_busy(self):
        with patch.object(bridge_cli, "load_env_file"), patch.object(
            bridge_cli,
            "port_is_listening",
            return_value=True,
        ), patch.object(
            bridge_cli,
            "bridge_healthcheck",
            return_value={"ollama": {"status": "ready"}},
        ):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = bridge_cli.main(["serve"])

        self.assertEqual(exit_code, 0)
        self.assertIn("already running", buffer.getvalue())

    def test_stop_reports_when_no_listener_exists(self):
        with patch.object(bridge_cli, "load_env_file"), patch.object(
            bridge_cli,
            "listening_pids_for_port",
            return_value=[],
        ), patch.object(
            bridge_cli,
            "port_is_listening",
            return_value=False,
        ):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = bridge_cli.main(["stop"])

        self.assertEqual(exit_code, 0)
        self.assertIn("No listening process found", buffer.getvalue())

    def test_policy_command_prints_template_summary(self):
        buffer = io.StringIO()
        with patch.object(bridge_cli, "load_env_file"), patch.object(
            bridge_cli.importlib,
            "import_module",
        ) as mocked_import:
            mocked_import.return_value.list_program_policy_templates.return_value = [
                {"name": "hackerone", "summary": "policy summary"}
            ]
            with redirect_stdout(buffer):
                exit_code = bridge_cli.main(["policy"])

        self.assertEqual(exit_code, 0)
        self.assertIn("hackerone", buffer.getvalue())

    def test_fetch_submission_report_builds_expected_request(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.text = "# report"
        with patch.object(bridge_cli.requests, "get", return_value=response) as mocked_get:
            bridge_cli.fetch_submission_report(
                base_url="http://127.0.0.1:8000",
                job_id="job-1",
                platform="bugcrowd",
                snapshot_id="snap-2",
                output_format="markdown",
                token="secret",
                request_id="req-2",
            )

        mocked_get.assert_called_once()
        args, kwargs = mocked_get.call_args
        self.assertIn("/api/history/jobs/job-1/submission-report.md", args[0])
        self.assertIn("platform=bugcrowd", args[0])
        self.assertIn("snapshot_id=snap-2", args[0])
        self.assertEqual(kwargs["headers"]["X-Bridge-Admin-Token"], "secret")

    def test_review_benchmark_and_bundle_commands_call_expected_endpoints(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"ok": True}
        response.text = "# bundle"
        with patch.object(bridge_cli, "load_env_file"), patch.object(bridge_cli.requests, "get", return_value=response) as mocked_get:
            bridge_cli.main(["review", "job-1", "--platform", "bugcrowd"])
            bridge_cli.main(["benchmark", "--limit", "25"])
            bridge_cli.main(["bundle", "job-1", "--output", "markdown"])

        urls = [call.args[0] for call in mocked_get.call_args_list]
        self.assertTrue(any("/api/history/jobs/job-1/operator-review" in url for url in urls))
        self.assertTrue(any("/api/runtime/benchmark?limit=25" in url for url in urls))
        self.assertTrue(any("/api/history/jobs/job-1/evidence-bundle.md" in url for url in urls))

    def test_review_import_command_uses_submission_regression_importer(self):
        importer = Mock()
        importer.import_submission_regressions_into_review_dataset.return_value = {
            "imported_count": 2,
            "skipped_count": 0,
            "items": [],
            "skipped_job_ids": [],
            "summary": "Imported 2 regression example(s) into the review dataset.",
        }
        with patch.object(bridge_cli, "load_env_file"), patch.object(
            bridge_cli.importlib,
            "import_module",
            return_value=importer,
        ):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = bridge_cli.main(["review-import", "--outcome", "accepted"])

        self.assertEqual(exit_code, 0)
        importer.import_submission_regressions_into_review_dataset.assert_called_once()
        self.assertIn("Imported 2 regression example(s)", buffer.getvalue())

    def test_asset_feedback_command_records_feedback(self):
        feedback_module = Mock()
        feedback_module.append_asset_feedback.return_value = {
            "asset_type": "custom_scan_check",
            "asset_id": "idor-bola-check",
            "label": "useful",
            "memory_partition_key": "generic:bug-bounty-safe:tenant-example-com",
        }
        with patch.object(bridge_cli, "load_env_file"), patch.object(
            bridge_cli.importlib,
            "import_module",
            return_value=feedback_module,
        ):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = bridge_cli.main([
                    "asset-feedback",
                    "--asset-type",
                    "custom_scan_check",
                    "--asset-id",
                    "idor-bola-check",
                    "--label",
                    "useful",
                ])

        self.assertEqual(exit_code, 0)
        feedback_module.append_asset_feedback.assert_called_once()
        self.assertIn("Recorded useful feedback", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
