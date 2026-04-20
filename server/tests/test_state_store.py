import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.state import store


class StateStoreRetentionTests(unittest.TestCase):
    def test_phase_snapshots_are_pruned_to_max_records(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            phase_path = Path(temp_dir) / "phase_snapshots.jsonl"
            first = {
                "job_id": "job-1",
                "created_at": "2026-03-30T00:00:00+00:00",
                "target_url": "https://example.com/1",
                "analysis_run": {
                    "phase_results": {
                        "ingest": {"target_url": "https://example.com/1"},
                        "validate": {"validation_status": "needs-confirmation"},
                    }
                },
            }
            second = {
                "job_id": "job-2",
                "created_at": "2026-03-30T00:01:00+00:00",
                "target_url": "https://example.com/2",
                "analysis_run": {
                    "phase_results": {
                        "impact": {"reportable": False},
                        "report": {"backend": "deterministic"},
                    }
                },
            }

            with (
                patch.object(store, "PHASE_SNAPSHOT_PATH", phase_path),
                patch.object(store, "PHASE_SNAPSHOT_JSONL_MAX_RECORDS", 3),
            ):
                store.append_phase_snapshots(first)
                store.append_phase_snapshots(second)
                retained = store.read_phase_snapshots()

                self.assertEqual(len(retained), 3)
                self.assertEqual([item["phase"] for item in retained], ["validate", "impact", "report"])

    def test_provider_diagnostics_use_separate_retention_limit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            diagnostics_path = Path(temp_dir) / "provider_diagnostics.jsonl"
            with (
                patch.object(store, "PROVIDER_DIAGNOSTICS_PATH", diagnostics_path),
                patch.object(store, "PROVIDER_DIAGNOSTICS_JSONL_MAX_RECORDS", 2),
            ):
                for index in range(3):
                    store.append_provider_diagnostics({
                        "job_id": f"job-{index}",
                        "request_id": f"req-{index}",
                        "status": "completed",
                        "analysis_run": {"provider_trace": [], "fallback_reason": ""},
                        "result": {"provider_failover": {}, "analysis_backend": "ollama"},
                    })

                retained = store.read_provider_diagnostics()

        self.assertEqual(len(retained), 2)
        self.assertEqual([item["job_id"] for item in retained], ["job-1", "job-2"])

    def test_issue_workflow_state_is_pruned_and_latest_record_is_returned(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workflow_path = Path(temp_dir) / "issue_workflow_state.jsonl"
            with (
                patch.object(store, "ISSUE_WORKFLOW_STATE_PATH", workflow_path),
                patch.object(store, "ISSUE_WORKFLOW_STATE_JSONL_MAX_RECORDS", 2),
            ):
                store.append_issue_workflow_state({"workflow_id": "wf-1", "issue_id": "issue-1", "status": "planned"})
                store.append_issue_workflow_state({"workflow_id": "wf-1", "issue_id": "issue-1", "status": "diff-scored"})
                store.append_issue_workflow_state({"workflow_id": "wf-2", "issue_id": "issue-2", "status": "planned"})

                retained = store.read_issue_workflow_states()
                latest = store.get_issue_workflow_state(issue_id="issue-2")

        self.assertEqual(len(retained), 2)
        self.assertEqual(retained[0]["workflow_id"], "wf-1")
        self.assertEqual(retained[1]["workflow_id"], "wf-2")
        self.assertEqual(latest["status"], "planned")


if __name__ == "__main__":
    unittest.main()
