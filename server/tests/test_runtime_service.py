import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.core import runtime_service
from server.mcp_client import MCPConfigurationError, MCPServerInspectionResult


class RuntimeServiceTests(unittest.TestCase):
    def test_get_runtime_health_reports_ready_dependencies(self):
        response = Mock()
        response.json.return_value = {
            "models": [{"name": "qwen2.5-coder:3b"}, {"name": "llama3.2:3b"}],
        }
        response.raise_for_status.return_value = None

        with (
            patch.object(runtime_service, "get_active_ollama_model", return_value="llama3.2:3b"),
            patch.object(runtime_service, "configured_model_providers", return_value=["mcp", "ollama"]),
            patch.object(runtime_service, "inspect_burp_mcp_server", return_value={
                "enabled": True,
                "transport": "auto",
                "url": "http://127.0.0.1:9876",
                "command": "",
                "status": "ready",
                "detail": "Burp MCP responded.",
                "available_tools": ["get_proxy_http_history"],
                "server_name": "burp-mcp",
                "server_version": "1.0",
            }),
            patch.object(
                runtime_service,
                "inspect_mcp_server",
                return_value=MCPServerInspectionResult(
                    protocol_version="2025-06-18",
                    server_name="burp-ai-bridge-mcp",
                    server_version="1.0",
                    available_tools=["analyze_security_exchange", "rank_impact_paths"],
                ),
            ),
            patch.object(runtime_service.requests, "get", return_value=response),
        ):
            health = runtime_service.get_runtime_health()

        self.assertEqual(health["mcp"]["status"], "ready")
        self.assertEqual(health["burp_mcp"]["status"], "ready")
        self.assertIn("analyze_security_exchange", health["mcp"]["available_tools"])
        self.assertEqual(health["ollama"]["status"], "ready")
        self.assertIn("qwen2.5-coder:3b", health["ollama"]["detected_models"])

    def test_get_runtime_health_reports_mcp_misconfiguration_and_ollama_unreachable(self):
        with (
            patch.object(runtime_service, "get_active_ollama_model", return_value="llama3.2:3b"),
            patch.object(runtime_service, "configured_model_providers", return_value=["mcp", "ollama"]),
            patch.object(runtime_service, "inspect_burp_mcp_server", return_value={
                "enabled": True,
                "transport": "auto",
                "url": "http://127.0.0.1:9876",
                "command": "",
                "status": "unreachable",
                "detail": "connection refused",
                "available_tools": [],
                "server_name": "",
                "server_version": "",
            }),
            patch.object(
                runtime_service,
                "inspect_mcp_server",
                side_effect=MCPConfigurationError("MCP_SERVER_COMMAND is empty."),
            ),
            patch.object(
                runtime_service.requests,
                "get",
                side_effect=requests.RequestException("connection refused"),
            ),
        ):
            health = runtime_service.get_runtime_health()

        self.assertEqual(health["mcp"]["status"], "misconfigured")
        self.assertEqual(health["burp_mcp"]["status"], "unreachable")
        self.assertEqual(health["ollama"]["status"], "unreachable")

    def test_get_runtime_readiness_separates_runtime_and_input_state(self):
        payload = {
            "request_id": "req-7",
            "raw_request": "GET / HTTP/1.1",
            "target_url": "https://example.com",
            "custom_headers_text": "",
        }
        with (
            patch.object(runtime_service, "coerce_payload", return_value=SimpleNamespace(**payload)),
            patch.object(runtime_service, "get_runtime_health", return_value={
                "configured_provider_order": ["mcp", "ollama"],
                "active_provider_order": ["mcp", "ollama"],
                "mcp": {"enabled": True, "status": "degraded", "detail": "tool missing"},
                "ollama": {"enabled": True, "status": "ready", "detail": "reachable"},
            }),
            patch.object(runtime_service, "summarize_burp_context", return_value={
                "dashboard_issue": {"found": False},
                "proxy_history_count": 0,
                "logger_entry_count": 0,
                "repeater_request_count": 0,
                "enabled_tool_count": 0,
                "config_warning_count": 0,
            }),
            patch.object(runtime_service, "get_dashboard_issue_context", return_value={"found": False}),
            patch.object(runtime_service, "get_project_config_snapshot", return_value={"enabled_tools": [], "scope_includes": [], "scope_excludes": [], "config_warnings": []}),
        ):
            readiness = runtime_service.get_runtime_readiness(payload)

        self.assertEqual(readiness["request_id"], "req-7")
        self.assertEqual(readiness["recommended_analysis_endpoint"], "/api/analyze/jobs")
        self.assertTrue(readiness["input_ready"])
        self.assertIn(readiness["status"], {"ready", "degraded"})

    def test_get_provider_diagnostics_history_filters_by_request_id(self):
        with patch.object(runtime_service, "read_provider_diagnostics", return_value=[
            {
                "job_id": "job-1",
                "request_id": "req-1",
                "created_at": "2026-03-30T00:00:00+00:00",
                "analysis_backend": "ollama",
                "provider_failover": {"final_status": "complete", "outcomes": [{"provider": "ollama"}]},
            },
            {
                "job_id": "job-2",
                "request_id": "req-2",
                "created_at": "2026-03-29T00:00:00+00:00",
                "analysis_backend": "mcp+deterministic",
                "provider_failover": {"final_status": "deterministic-fallback", "outcomes": [{"provider": "mcp"}]},
            },
        ]):
            history = runtime_service.get_provider_diagnostics_history(request_id="req-1", provider="ollama")

        self.assertEqual(history["count"], 1)
        self.assertEqual(history["items"][0]["request_id"], "req-1")
        self.assertEqual(history["backend_counts"]["ollama"], 1)


if __name__ == "__main__":
    unittest.main()
