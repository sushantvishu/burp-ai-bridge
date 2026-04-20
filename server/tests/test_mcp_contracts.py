import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.mcp_server import app as mcp_app
from server.settings import MCP_PROTOCOL_VERSION


class McpContractTests(unittest.TestCase):
    def test_initialize_exposes_protocol_and_server_info(self):
        response = mcp_app.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "initialize",
                "params": {"protocolVersion": MCP_PROTOCOL_VERSION},
            }
        )

        self.assertEqual(response["result"]["protocolVersion"], MCP_PROTOCOL_VERSION)
        self.assertEqual(response["result"]["serverInfo"]["name"], "burp-ai-bridge-mcp")
        self.assertEqual(response["result"]["serverInfo"]["version"], "1.0")

    def test_tools_list_contains_expected_schema_contracts(self):
        response = mcp_app.handle_message({"jsonrpc": "2.0", "id": 11, "method": "tools/list", "params": {}})
        tools = {item["name"]: item for item in response["result"]["tools"]}

        self.assertIn("analyze_security_exchange", tools)
        self.assertIn("prepare_burp_export_payload", tools)
        self.assertIn("query_phase_history", tools)
        self.assertIn("explain_analysis_run", tools)
        self.assertIn("normalize_burp_payload", tools)
        self.assertIn("describe_burp_payload_contract", tools)
        self.assertIn("review_browser_verification", tools)
        self.assertIn("get_program_policy_template", tools)
        self.assertIn("build_bug_bounty_submission", tools)

        analyze_schema = tools["analyze_security_exchange"]["inputSchema"]
        self.assertIn("raw_request", analyze_schema["properties"])
        self.assertIn("burp_dashboard_issue", analyze_schema["properties"])
        self.assertIn("browser_allowed_workflows", analyze_schema["properties"])
        self.assertIn("raw_request", analyze_schema["required"])

        prepare_schema = tools["prepare_burp_export_payload"]["inputSchema"]
        self.assertEqual(prepare_schema["required"], ["payload"])
        self.assertEqual(prepare_schema["properties"]["payload"]["type"], "object")

        phase_schema = tools["query_phase_history"]["inputSchema"]
        self.assertIn("job_id", phase_schema["properties"])
        self.assertIn("phase", phase_schema["properties"])
        self.assertEqual(phase_schema["properties"]["limit"]["maximum"], 100)

        reasoning_schema = tools["explain_analysis_run"]["inputSchema"]
        self.assertEqual(reasoning_schema["required"], ["job_id"])

        browser_schema = tools["review_browser_verification"]["inputSchema"]
        self.assertIn("browser_verification_allowed", browser_schema["properties"])

        submission_schema = tools["build_bug_bounty_submission"]["inputSchema"]
        self.assertEqual(submission_schema["required"], ["job_id"])


if __name__ == "__main__":
    unittest.main()
