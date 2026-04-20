import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server import burp_direct_sender


class BurpDirectSenderTests(unittest.TestCase):
    def test_submit_selected_request_posts_bounded_bridge_payload(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"job_id": "job-1", "snapshot_id": "snap-1"}
        with patch.object(burp_direct_sender.requests, "post", return_value=response) as mocked_post:
            result = burp_direct_sender.submit_selected_request(
                base_url="http://127.0.0.1:8000",
                raw_request="GET / HTTP/1.1",
                raw_response="HTTP/1.1 200 OK",
                target_url="https://example.com",
                http_method="GET",
                source_tool="repeater",
                timeout=15,
            )

        mocked_post.assert_called_once()
        args, kwargs = mocked_post.call_args
        self.assertEqual(args[0], "http://127.0.0.1:8000/api/burp/submit-job")
        self.assertEqual(kwargs["timeout"], 15)
        self.assertTrue(kwargs["json"]["use_burp_mcp_context"])
        self.assertEqual(kwargs["json"]["source_tool"], "repeater")
        self.assertEqual(result["snapshot_id"], "snap-1")

    def test_open_plan_in_repeater_posts_to_repeater_endpoint(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"opened_count": 2}
        with patch.object(burp_direct_sender.requests, "post", return_value=response) as mocked_post:
            result = burp_direct_sender.open_plan_in_repeater(
                base_url="http://127.0.0.1:8000",
                raw_request="GET / HTTP/1.1",
                target_url="https://example.com",
                source_tool="scanner",
                timeout=10,
                dispatch=True,
            )

        mocked_post.assert_called_once()
        args, kwargs = mocked_post.call_args
        self.assertEqual(args[0], "http://127.0.0.1:8000/api/burp/open-repeater-plan")
        self.assertEqual(kwargs["params"]["dispatch"], "true")
        self.assertEqual(kwargs["json"]["source_tool"], "scanner")
        self.assertEqual(result["opened_count"], 2)

    def test_sync_selected_repeater_tabs_posts_combined_observation_payload(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"workflow_id": "wf-1", "workflow_status": "diff-scored"}
        with patch.object(burp_direct_sender.requests, "post", return_value=response) as mocked_post:
            result = burp_direct_sender.sync_selected_repeater_tabs(
                base_url="http://127.0.0.1:8000",
                raw_request="GET /account?id=1 HTTP/1.1",
                baseline_response_text="HTTP/1.1 403 Forbidden",
                target_url="https://example.com/account",
                source_tool="repeater",
                repeater_variant_observations=[{"tab_name": "variant-1", "response_text": "HTTP/1.1 200 OK"}],
                timeout=12,
                include_plan=True,
            )

        mocked_post.assert_called_once()
        args, kwargs = mocked_post.call_args
        self.assertEqual(args[0], "http://127.0.0.1:8000/api/burp/repeater-sync")
        self.assertEqual(kwargs["params"]["include_plan"], "true")
        self.assertEqual(kwargs["json"]["baseline_response_text"], "HTTP/1.1 403 Forbidden")
        self.assertEqual(kwargs["json"]["repeater_variant_observations"][0]["tab_name"], "variant-1")
        self.assertEqual(result["workflow_id"], "wf-1")

    def test_refresh_panel_state_posts_compact_refresh_payload(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"workflow_id": "wf-1", "best_next_tab": {"tab_name": "variant-2"}}
        with patch.object(burp_direct_sender.requests, "post", return_value=response) as mocked_post:
            result = burp_direct_sender.refresh_panel_state(
                base_url="http://127.0.0.1:8000",
                target_url="https://example.com/account",
                issue_id="issue-104",
                snapshot_id="snap-104",
                timeout=9,
                include_plan=True,
                include_companion_actions=True,
            )

        mocked_post.assert_called_once()
        args, kwargs = mocked_post.call_args
        self.assertEqual(args[0], "http://127.0.0.1:8000/api/burp/panel-state")
        self.assertEqual(kwargs["params"]["issue_id"], "issue-104")
        self.assertEqual(kwargs["params"]["snapshot_id"], "snap-104")
        self.assertEqual(kwargs["params"]["include_plan"], "true")
        self.assertEqual(kwargs["params"]["include_companion_actions"], "true")
        self.assertTrue(kwargs["json"]["use_burp_mcp_context"])
        self.assertEqual(result["best_next_tab"]["tab_name"], "variant-2")


if __name__ == "__main__":
    unittest.main()
