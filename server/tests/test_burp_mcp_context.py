import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server import burp_mcp_context
from server import burp_mcp_adapter
from server.mcp_client import MCPCallResult, MCPServerInspectionResult, candidate_mcp_urls


class BurpMcpContextTests(unittest.TestCase):
    def setUp(self):
        burp_mcp_adapter._INSPECTION_CACHE.clear()
        burp_mcp_adapter._TOOL_CALL_CACHE.clear()
        burp_mcp_adapter._LAST_CALL_AT.clear()

    def test_augment_payload_hydrates_proxy_issue_project_options_and_repeater(self):
        def fake_call(config, arguments):
            if config.tool_name == "get_proxy_http_history":
                return MCPCallResult(
                    tool_name=config.tool_name,
                    protocol_version="2025-06-18",
                    content_text='{"url":"https://example.com/profile","method":"GET","statusCode":200,"id":"hist-1","request":{"content":"GET /profile HTTP/1.1"}}',
                )
            if config.tool_name == "get_scanner_issues":
                return MCPCallResult(
                    tool_name=config.tool_name,
                    protocol_version="2025-06-18",
                    content_text='[{"id":"issue-1","name":"Insecure direct object reference","severity":"high","confidence":"firm","url":"https://example.com/profile","requestRefs":["hist-1"]},{"id":"issue-2","name":"Reflected XSS","severity":"medium","confidence":"firm","url":"https://example.com/profile","requestRefs":["hist-1"]}]',
                )
            if config.tool_name == "output_project_options":
                return MCPCallResult(
                    tool_name=config.tool_name,
                    protocol_version="2025-06-18",
                    content_text='{"project_options":{"connections":{}}}',
                )
            if config.tool_name == "get_repeater_requests":
                return MCPCallResult(
                    tool_name=config.tool_name,
                    protocol_version="2025-06-18",
                    content_text='{"url":"https://example.com/profile","method":"GET","statusCode":200,"id":"rep-1"}',
                )
            return MCPCallResult(tool_name=config.tool_name, protocol_version="2025-06-18", content_text="")

        with (
            patch.object(
                burp_mcp_adapter,
                "inspect_mcp_server",
                return_value=MCPServerInspectionResult(
                    protocol_version="2025-06-18",
                    server_name="burp-mcp",
                    server_version="1.0",
                    available_tools=["get_proxy_http_history", "get_scanner_issues", "output_project_options", "get_repeater_requests"],
                ),
            ),
            patch.object(burp_mcp_adapter, "call_mcp_tool", side_effect=fake_call),
        ):
            payload = burp_mcp_context.augment_payload_with_burp_mcp({
                "target_url": "https://example.com/profile",
                "source_tool": "repeater",
                "use_burp_mcp_context": True,
            })

        self.assertTrue(payload["proxy_history_entries"])
        self.assertEqual(payload["raw_request"], "GET /profile HTTP/1.1")
        self.assertEqual(payload["burp_dashboard_issue"]["issue_id"], "issue-1")
        self.assertEqual(payload["burp_dashboard_issue"]["name"], "Insecure direct object reference")
        self.assertEqual(payload["burp_related_scanner_issues"][0]["name"], "Reflected XSS")
        self.assertTrue(payload["repeater_requests"])
        self.assertIn("project_options", payload["burp_config_export_text"])
        self.assertTrue(payload["burp_mcp_context_applied"])

    def test_augment_payload_pins_existing_issue_by_issue_id(self):
        def fake_call(config, arguments):
            if config.tool_name == "get_scanner_issues":
                return MCPCallResult(
                    tool_name=config.tool_name,
                    protocol_version="2025-06-18",
                    content_text='[{"id":"issue-1","name":"CSRF","severity":"medium","confidence":"firm","url":"https://example.com/profile","detail":"Issue one."},{"id":"issue-2","name":"Stored XSS","severity":"medium","confidence":"firm","url":"https://example.com/profile","detail":"Issue two.","requestRefs":["hist-2"]}]',
                )
            return MCPCallResult(tool_name=config.tool_name, protocol_version="2025-06-18", content_text="")

        with (
            patch.object(
                burp_mcp_adapter,
                "inspect_mcp_server",
                return_value=MCPServerInspectionResult(
                    protocol_version="2025-06-18",
                    server_name="burp-mcp",
                    server_version="1.0",
                    available_tools=["get_scanner_issues"],
                ),
            ),
            patch.object(burp_mcp_adapter, "call_mcp_tool", side_effect=fake_call),
        ):
            payload = burp_mcp_context.augment_payload_with_burp_mcp({
                "target_url": "https://example.com/profile",
                "source_tool": "scanner",
                "use_burp_mcp_context": True,
                "burp_dashboard_issue": {"issue_id": "issue-2", "name": "Stored XSS"},
            })

        self.assertEqual(payload["burp_dashboard_issue"]["issue_id"], "issue-2")
        self.assertEqual(payload["burp_dashboard_issue"]["detail"], "Issue two.")

    def test_adapter_caches_repeated_inspection_and_tool_calls(self):
        call_count = {"inspect": 0, "tool": 0}

        def fake_call(config, arguments):
            call_count["tool"] += 1
            return MCPCallResult(
                tool_name=config.tool_name,
                protocol_version="2025-06-18",
                content_text='{"url":"https://example.com/profile","method":"GET","statusCode":200,"id":"hist-1"}',
            )

        def fake_inspect(config):
            call_count["inspect"] += 1
            return MCPServerInspectionResult(
                protocol_version="2025-06-18",
                server_name="burp-mcp",
                server_version="1.0",
                available_tools=["get_proxy_http_history"],
            )

        with (
            patch.object(burp_mcp_adapter, "inspect_mcp_server", side_effect=fake_inspect),
            patch.object(burp_mcp_adapter, "call_mcp_tool", side_effect=fake_call),
        ):
            first = burp_mcp_adapter.call_burp_mcp_capability("proxy_history", target_url="https://example.com/profile")
            second = burp_mcp_adapter.call_burp_mcp_capability("proxy_history", target_url="https://example.com/profile")

        self.assertEqual(call_count["inspect"], 1)
        self.assertEqual(call_count["tool"], 1)
        self.assertEqual(first["tool_name"], "get_proxy_http_history")
        self.assertEqual(second["tool_name"], "get_proxy_http_history")

    def test_candidate_mcp_urls_includes_root_and_sse_variant(self):
        urls = candidate_mcp_urls("http://127.0.0.1:9876")
        self.assertEqual(urls, ["http://127.0.0.1:9876", "http://127.0.0.1:9876/sse"])


if __name__ == "__main__":
    unittest.main()
