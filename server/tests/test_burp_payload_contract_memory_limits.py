import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.analysis_jobs import AnalysisJobManager
from server.capabilities.burp import normalize_burp_payload_contract
from server.core.analysis_service import coerce_payload
from server.main import AssessmentRequest


def _heavy_issue_payload() -> dict:
    requests = []
    for index in range(6):
        requests.append(
            {
                "id": f"req-{index}",
                "request": {
                    "method": "GET",
                    "url": f"https://example.com/api/users/{index}",
                    "raw": "A" * 10000,
                },
                "response": {
                    "statusCode": 200,
                    "raw": "B" * 10000,
                },
                "requestText": "R" * 9000,
                "responseText": "S" * 9000,
                "summary": f"scanner request {index}",
            }
        )
    return {
        "title": "Insecure direct object reference",
        "description": "D" * 5000,
        "requestResponses": requests,
    }


class BurpPayloadContractMemoryLimitTests(unittest.TestCase):
    def test_normalize_burp_payload_contract_compacts_scanner_requests(self):
        normalized = normalize_burp_payload_contract(
            {
                "raw_request": "GET / HTTP/1.1",
                "target_url": "https://example.com/api/users/1",
                "dashboard_issue": _heavy_issue_payload(),
            }
        )

        issue = normalized["burp_dashboard_issue"]
        scanner_requests = issue.get("scanner_requests") or []
        self.assertEqual(len(scanner_requests), 4)
        first = scanner_requests[0]
        self.assertTrue(first.get("has_request"))
        self.assertTrue(first.get("has_response"))
        self.assertNotIn("request", first)
        self.assertNotIn("response", first)
        self.assertLessEqual(len(issue.get("detail") or ""), 2400)

    def test_analysis_job_submit_stores_compact_scanner_requests(self):
        payload = AssessmentRequest(
            raw_request="GET / HTTP/1.1",
            target_url="https://example.com/api/users/1",
            burp_dashboard_issue=_heavy_issue_payload(),
            source_tool="scanner",
        )
        manager = AnalysisJobManager(max_workers=1)
        manager._executor = Mock()
        manager._executor.submit = Mock(return_value=None)

        with (
            patch("server.analysis_jobs.build_deterministic_context", return_value={"complexity": {"level": "low", "eta": "fast", "recommendation": "ok"}}),
            patch("server.analysis_jobs.build_history_fingerprint", return_value={"signature": "sig"}),
        ):
            job = manager.submit(payload)

        stored = manager.get(job["job_id"])
        self.assertIsNotNone(stored)
        issue = stored.get("burp_dashboard_issue") or {}
        scanner_requests = issue.get("scanner_requests") or []
        self.assertEqual(len(scanner_requests), 4)
        self.assertNotIn("request", scanner_requests[0])
        self.assertNotIn("response", scanner_requests[0])

    def test_analysis_job_manager_rejects_submit_after_shutdown(self):
        payload = AssessmentRequest(
            raw_request="GET / HTTP/1.1",
            target_url="https://example.com/api/users/1",
            source_tool="scanner",
        )
        manager = AnalysisJobManager(max_workers=1)
        manager.shutdown()

        with (
            patch("server.analysis_jobs.build_deterministic_context", return_value={"complexity": {"level": "low", "eta": "fast", "recommendation": "ok"}}),
            patch("server.analysis_jobs.build_history_fingerprint", return_value={"signature": "sig"}),
        ):
            with self.assertRaisesRegex(RuntimeError, "shutting down"):
                manager.submit(payload)

    def test_coerce_payload_preserves_investigation_notebook_text(self):
        payload = coerce_payload(
            {
                "raw_request": "GET /comments?id=1 HTTP/1.1",
                "target_url": "https://example.com/comments?id=1",
                "source_tool": "scanner",
                "investigation_notebook_text": (
                    "Investigation anchor\n"
                    "- Source: Scanner Audit Issue\n"
                    "- Target: https://example.com/comments?id=1\n"
                    "\nPersistent notebook timeline\n"
                    "- [2026-04-11 22:15:00] Operator follow-up: First follow-up\n"
                    "- [2026-04-11 22:15:05] AI guidance update: Compare output encoding."
                ),
            }
        )

        self.assertIn("Persistent notebook timeline", payload.investigation_notebook_text)


if __name__ == "__main__":
    unittest.main()
