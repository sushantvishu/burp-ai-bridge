import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server import memory_retrieval, repeater_learning, review_dataset, storage_protection, submission_regression
from server.core import severity_service


class MemoryLearningAndReviewDatasetTests(unittest.TestCase):
    def test_review_dataset_extracts_real_scanner_style_examples(self):
        record = {
            "job_id": "job-1",
            "request_id": "req-1",
            "status": "completed",
            "target_url": "https://tenant.example.com/api/invoices/42",
            "http_method": "GET",
            "selected_profile": "bug-bounty-safe",
            "analysis_run": {
                "hypotheses": [{"vuln_class": "idor"}],
                "phases": {
                    "ingest": {
                        "dashboard_issue": {
                            "found": True,
                            "issue_name": "Insecure direct object reference",
                            "severity": "high",
                            "confidence": "firm",
                        }
                    },
                    "validate": {"validation_status": "confirmed"},
                    "impact": {"reportable": True, "business_impact_class": "high-impact"},
                },
            },
            "result": {"primary_next_action": "Capture one role-separated diff."},
        }

        example = review_dataset.build_review_example(record)

        self.assertEqual(example["outcome_label"], "confirmed-reportable")
        self.assertIn("idor", example["vuln_classes"])
        self.assertIn("tenant-example-com", example["memory_partition_key"])

    def test_repeater_learning_summarizes_useful_families_for_same_target_partition(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            learning_path = Path(temp_dir) / "repeater_variant_learning.jsonl"
            payload = {
                "request_id": "req-1",
                "target_url": "https://tenant.example.com/api/invoices/42",
                "selected_profile": "bug-bounty-safe",
            }
            plan = {
                "dashboard_issue": {"issue_id": "issue-1", "vuln_hint": "idor"},
                "related_scanner_issues": [],
            }
            diff = {
                "ranked_items": [
                    {
                        "tab_name": "tenant-switch-variant",
                        "summary": "Swap tenant object id",
                        "request_ref": "proxy-1",
                        "issue_id": "issue-1",
                        "expected_signal": "403/200 object boundary diff",
                        "score": 3.4,
                        "high_signal": True,
                    }
                ]
            }
            with patch.object(repeater_learning, "REPEATER_LEARNING_PATH", learning_path):
                repeater_learning.learn_from_repeater_diff(payload, plan=plan, diff_score=diff)
                summary = repeater_learning.summarize_repeater_learning(payload_like=payload, vuln_classes=["idor"])

        self.assertIn("authorization-boundary", summary["preferred_families"])
        self.assertTrue(summary["summary"])

    def test_storage_protection_hashes_raw_http_messages_when_enabled(self):
        record = {
            "raw_request": "GET /secret HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "raw_response": "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecret",
            "target_url": "https://example.com/secret",
        }
        with patch.object(storage_protection, "PERSISTENCE_REPLAY_PROTECTION_MODE", "hash-raw"):
            protected = storage_protection.protect_record_for_storage(record)

        self.assertIn("<protected-http-message:", protected["raw_request"])
        self.assertNotIn("GET /secret", protected["raw_request"])

    def test_partitioned_history_prefers_same_target_partition(self):
        current = {
            "signature": "GET|/api/invoices/{id}|-|json|json|idor",
            "method": "GET",
            "normalized_path": "/api/invoices/{id}",
            "path_tokens": ["api", "invoices", "{id}"],
            "param_names": [],
            "vuln_classes": ["idor"],
            "request_content_family": "json",
            "response_content_family": "json",
            "has_auth": True,
            "has_cookies": True,
            "memory_partition_key": "generic:bug-bounty-safe:tenant-example-com",
        }
        same = {
            "fingerprint": {**current},
            "feedback_score": 0,
            "confirmed_classes": ["idor"],
            "discarded_classes": [],
            "created_at": "2026-04-06T00:00:00+00:00",
            "target_url": "https://tenant.example.com/api/invoices/1",
        }
        different = {
            "fingerprint": {**current, "memory_partition_key": "generic:bug-bounty-safe:other-example-com"},
            "feedback_score": 0,
            "confirmed_classes": ["idor"],
            "discarded_classes": [],
            "created_at": "2026-04-06T00:00:01+00:00",
            "target_url": "https://other.example.com/api/invoices/1",
        }
        with patch.object(memory_retrieval, "load_endpoint_cache", return_value={"entries": [different, same]}):
            results = memory_retrieval.find_similar_history(current, limit=2)

        self.assertEqual(results[0]["target_url"], "https://tenant.example.com/api/invoices/1")
        self.assertTrue(results[0]["same_partition"])

    def test_severity_service_returns_confidence_calibration_and_gate(self):
        result = severity_service.assess_submission_severity(
            {"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"},
            validation={
                "validation_status": "confirmed",
                "hypothesis": {"vuln_class": "idor"},
                "evidence_score": 2.1,
                "evidence_count": 1,
                "missing_evidence": ["Need one role-separated diff."],
            },
            impact={
                "reportable": True,
                "reportability": "high",
                "business_impact_class": "high-impact",
                "confirmation_state": "confirmed",
                "dashboard_issue": {"severity": "high"},
                "evidence_score": 2.1,
                "evidence_count": 1,
                "evidence_gaps": ["Need one role-separated diff."],
            },
        )

        self.assertEqual(result["severity"], "medium")
        self.assertEqual(result["evidence_gate"]["max_allowed_severity"], "medium")
        self.assertTrue(result["confidence_calibration"]["missing_artifacts"])

    def test_submission_regressions_can_be_imported_into_review_dataset(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            review_path = Path(temp_dir) / "review_dataset.jsonl"
            with patch.object(review_dataset, "REVIEW_DATASET_PATH", review_path):
                imported = submission_regression.import_submission_regressions_into_review_dataset(
                    outcome="accepted",
                    limit=10,
                )
                examples = review_dataset.read_review_examples()

        self.assertGreaterEqual(imported["imported_count"], 1)
        self.assertTrue(any(item["job_id"].startswith("submission-regression:") for item in examples))
        self.assertTrue(any(item["outcome_label"] == "confirmed-reportable" for item in examples))


if __name__ == "__main__":
    unittest.main()
