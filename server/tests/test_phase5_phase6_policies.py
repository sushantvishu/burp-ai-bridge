import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.core import burp_action_service, runtime_service
from server.providers import command_template_service
from server import memory_retrieval
from server.state import store


class PhaseFiveAndSixPolicyTests(unittest.TestCase):
    def test_execution_safety_blocks_out_of_scope_and_caps_limits(self):
        payload = SimpleNamespace(
            raw_request="GET / HTTP/1.1",
            target_url="https://out.example.net/admin",
            scope_includes_text="https://in-scope.example.com",
            scope_excludes_text="",
            rate_limit_text="50 req/sec",
            max_concurrency_text="25",
            program_policy_text="",
            source_tool="scanner",
        )

        safety = runtime_service.evaluate_execution_safety(payload)

        self.assertTrue(safety["blocked"])
        self.assertFalse(safety["safe_to_expand"])
        self.assertIn("scope", " ".join(safety["blocked_reasons"]).lower())
        self.assertLessEqual(
            safety["limits"]["rate_limit_effective"],
            safety["limits"]["hard_max_rate_limit"],
        )
        self.assertLessEqual(
            safety["limits"]["max_concurrency_effective"],
            safety["limits"]["hard_max_concurrency"],
        )

    def test_burp_action_metadata_explains_blocked_expansion(self):
        payload = SimpleNamespace(
            raw_request="GET /accounts HTTP/1.1",
            target_url="https://out.example.net/accounts",
            scope_includes_text="https://in-scope.example.com",
            scope_excludes_text="",
            program_policy_text="",
            source_tool="repeater",
        )
        advisory = {
            "primary_next_action": "Capture baseline first.",
            "request_plan": ["baseline"],
            "burp_action_checklist": ["baseline first"],
            "payload_recommendations": [],
            "fallback_used": False,
            "analysis_backend": "deterministic",
        }
        with (
            patch.object(burp_action_service, "rank_impact_paths", return_value={"policy_gate": {"applies": False, "allowed": True}}),
            patch.object(burp_action_service, "build_repeater_escalation_plan", return_value={
                "scanner_focus": {},
                "repeater_mutation_plan": [{"instruction": "mutate id"}],
                "repeater_variant_requests": [{"tab_name": "variant-1"}],
                "issue_chain_strategy": ["test variant"],
                "kb_hints": [],
                "memory_hints": [],
                "preferred_request_ref": "req-1",
            }),
            patch.object(burp_action_service, "recommend_burp_capabilities", return_value={"recommendations": [], "starter_assets": {}, "curated_bapp_categories": [], "external_tool_recommendations": []}),
            patch.object(burp_action_service, "get_dashboard_issue_context", return_value={}),
            patch.object(burp_action_service, "get_related_dashboard_issue_contexts", return_value=[]),
            patch.object(burp_action_service, "summarize_burp_context", return_value={}),
        ):
            result = burp_action_service.next_burp_action(payload, advisory=advisory)

        self.assertFalse(result["safe_to_expand"])
        self.assertTrue(result["execution_safety"]["blocked"])
        self.assertTrue(result["blocked_expansions"])
        self.assertEqual(result["repeater_variant_requests"], [])

    def test_command_templates_return_blocked_note_when_kill_switch_phrase_present(self):
        payload = SimpleNamespace(
            target_url="https://example.com/api",
            scope_includes_text="https://example.com",
            scope_excludes_text="",
            rate_limit_text="",
            max_concurrency_text="",
            program_policy_text="manual only - kill switch active",
            saved_program_policy_text="",
        )
        features = {"signals": set(), "method": "GET"}
        helpers = {
            "base_target_url": lambda target: target,
            "header_flags_for_tool": lambda tool, _payload: "",
            "rate_limit_flags_for_tool": lambda tool, _payload: "",
            "scope_note": lambda _payload: "",
        }
        commands = command_template_service.build_command_templates(
            payload,
            features,
            [],
            "",
            "",
            helpers,
        )

        self.assertTrue(commands)
        self.assertIn("Execution blocked", commands[0])

    def test_memory_cache_promotes_confirmed_and_deduplicates_same_signature(self):
        base_fingerprint = {
            "signature": "GET|/api/users/{id}|id|json|json|access-control",
            "method": "GET",
            "normalized_path": "/api/users/{id}",
            "path_tokens": ["api", "users", "{id}"],
            "param_names": ["id"],
            "vuln_classes": ["access-control"],
            "request_content_family": "json",
            "response_content_family": "json",
            "has_auth": True,
            "has_cookies": True,
            "memory_partition_key": "generic:bug-bounty-safe:example-com",
        }
        low_value = {
            "job_id": "job-low",
            "status": "completed",
            "target_url": "https://example.com/api/users/1",
            "created_at": "2026-04-01T00:00:00+00:00",
            "result": {"analysis": "low", "fallback_used": True, "potential_vulnerabilities": []},
            "analysis_run": {"hypotheses": [], "evidence": [], "phases": {"validate": {"validation_status": "needs-confirmation"}, "impact": {"reportable": False}}},
            "fingerprint": base_fingerprint,
        }
        high_value = {
            "job_id": "job-high",
            "status": "completed",
            "target_url": "https://example.com/api/users/2",
            "created_at": "2026-04-02T00:00:00+00:00",
            "result": {"analysis": "confirmed", "fallback_used": False, "potential_vulnerabilities": ["[access-control] idor"]},
            "analysis_run": {
                "hypotheses": [{"vuln_class": "access-control", "status": "confirmed", "confidence": 0.92}],
                "evidence": [{"source": "repeater", "summary": "403 -> 200", "confidence": 0.88}],
                "phases": {"validate": {"validation_status": "confirmed"}, "impact": {"reportable": True}},
            },
            "fingerprint": base_fingerprint,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "endpoint_cache.json"
            with (
                patch.object(memory_retrieval, "ENDPOINT_CACHE_PATH", cache_path),
                patch.object(memory_retrieval, "read_history_records", return_value=[low_value, high_value]),
                patch.object(memory_retrieval, "_feedback_summary", return_value={}),
            ):
                cache = memory_retrieval._build_cache()

        self.assertEqual(len(cache["entries"]), 1)
        self.assertEqual(cache["entries"][0]["job_id"], "job-high")
        self.assertTrue(cache["entries"][0]["memory_promotion"]["promoted"])

    def test_state_store_snapshot_keeps_promoted_hypotheses_and_evidence_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_path = Path(temp_dir) / "analysis_run_state.jsonl"
            record = {
                "job_id": "job-1",
                "status": "completed",
                "target_url": "https://example.com/api/users/1",
                "analysis_run": {
                    "hypotheses": [
                        {"id": "h1", "vuln_class": "xss", "status": "suspected", "confidence": 0.4},
                        {"id": "h2", "vuln_class": "access-control", "status": "confirmed", "confidence": 0.9},
                    ],
                    "evidence": [
                        {"source": "bapp", "summary": "Auto-collected Burp audit issues ... large", "confidence": 0.9},
                        {"source": "repeater", "summary": "403 -> 200 on object id swap", "evidence_type": "role-compare", "confidence": 0.86},
                    ],
                    "phase_results": {"ingest": {"ok": True}},
                },
            }
            with (
                patch.object(store, "ANALYSIS_RUN_STATE_PATH", snapshot_path),
                patch.object(store, "ANALYSIS_RUN_STATE_JSONL_MAX_RECORDS", 10),
            ):
                store.append_analysis_snapshot(record)
                rows = store.read_analysis_snapshots()

        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]["hypotheses"]), 1)
        self.assertEqual(rows[0]["hypotheses"][0]["vuln_class"], "access-control")
        self.assertEqual(len(rows[0]["evidence"]), 1)
        self.assertIn("403 -> 200", rows[0]["evidence"][0]["summary"])


if __name__ == "__main__":
    unittest.main()
