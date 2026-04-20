import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.core import analysis_service
from server.core import burp_context_service
from server.core import browser_verification_service
from server.core import burp_snapshot_service
from server.core import repeater_dispatch_service
from server.core import repeater_guidance_service
from server.core import escalation_service
from server.core import history_service
from server.core import impact_service
from server.core import issue_workflow_service
from server.core import program_policy_service
from server.core import recommendation_service
from server.core import report_service
from server.core import severity_service
from server.core import submission_report_service
from server.core import validation_service
from server.api.handlers import prepare_burp_export
from server import memory_retrieval
from server import bcheck_learning
from server.mcp_server import app as mcp_app
from server.providers import deterministic_guidance_service


class CoreServicesAndMcpServerTests(unittest.TestCase):
    def test_analyze_exchange_returns_advisory_and_run(self):
        advisory = {
            "analysis": "analysis text",
            "analysis_backend": "ollama",
            "model_execution_trace": ["OLLAMA USED: complete response"],
            "fallback_used": False,
            "primary_next_action": "use repeater",
            "potential_vulnerabilities": ["[xss] reflected output"],
            "confirmation_playbooks": ["collect one clean diff"],
            "questions_for_user": ["which parameter reflects?"],
            "impact_paths": ["show reflected execution in admin context"],
            "tool_availability_summary": "curl",
            "confidence_by_class": ["xss: 0.73 confidence - reflected output matched"],
        }
        rule_context = {
            "features": {
                "observations": ["response reflects user-controlled input"],
            },
            "matched_recipes": [{"title": "Reflected XSS Review"}],
        }
        payload = {"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com", "http_method": "GET"}

        with (
            patch.object(analysis_service, "analyze_security_advisory", return_value=advisory),
            patch.object(analysis_service, "build_deterministic_context", return_value=rule_context),
            patch.object(analysis_service, "search_local_knowledge", return_value={"context": "kb", "hits": [{"title": "KB Note", "file": "kb.md", "tags": ["xss"], "score": 0.8, "text": "reflective patterns"}]}),
            patch.object(analysis_service, "build_whitebox_enrichment", return_value={"enabled": True, "summary": "matched", "signals": ["auth-related source file matched the white-box query."], "files": ["app/auth.py"]}),
        ):
            result = analysis_service.analyze_exchange(payload)

        self.assertIn("advisory", result)
        self.assertIn("run", result)
        self.assertEqual(result["advisory"]["primary_next_action"], "use repeater")
        self.assertEqual(result["run"]["phases"]["hypothesize"]["count"], 1)
        self.assertEqual(result["run"]["hypotheses"][0]["vuln_class"], "xss")
        self.assertEqual(result["run"]["phases"]["enrich"]["kb_hits"][0]["title"], "KB Note")
        self.assertTrue(result["run"]["phases"]["enrich"]["whitebox"]["enabled"])
        self.assertIn("validation_status", result["run"]["phases"]["validate"])
        self.assertIn("reportable", result["run"]["phases"]["impact"])
        self.assertIn("local-kb", [item["source"] for item in result["run"]["evidence"]])
        self.assertIn("whitebox", [item["source"] for item in result["run"]["evidence"]])

    def test_mcp_server_lists_tools_and_calls_analysis_tool(self):
        list_response = mcp_app.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        tool_names = [item["name"] for item in list_response["result"]["tools"]]
        self.assertIn("analyze_security_exchange", tool_names)
        self.assertIn("rank_impact_paths", tool_names)
        self.assertIn("next_burp_action", tool_names)
        self.assertIn("summarize_hypotheses", tool_names)
        self.assertIn("validate_hypothesis", tool_names)
        self.assertIn("query_similar_history", tool_names)
        self.assertIn("recommend_bchecks", tool_names)
        self.assertIn("review_project_readiness", tool_names)
        self.assertIn("build_report_evidence", tool_names)
        self.assertIn("build_structured_report", tool_names)
        self.assertIn("update_hypothesis_status", tool_names)
        self.assertIn("query_local_knowledge", tool_names)
        self.assertIn("list_history_records", tool_names)
        self.assertIn("get_issue_context", tool_names)
        self.assertIn("get_recent_proxy_history", tool_names)
        self.assertIn("get_logger_deltas", tool_names)
        self.assertIn("get_repeater_request", tool_names)
        self.assertIn("get_project_config_snapshot", tool_names)
        self.assertIn("describe_burp_payload_contract", tool_names)
        self.assertIn("normalize_burp_payload", tool_names)
        self.assertIn("prepare_burp_export_payload", tool_names)
        self.assertIn("query_phase_history", tool_names)
        self.assertIn("explain_analysis_run", tool_names)
        self.assertIn("get_burp_exporter_config", tool_names)
        self.assertIn("inspect_burp_mcp_capabilities", tool_names)
        self.assertIn("call_burp_mcp_capability", tool_names)
        self.assertIn("get_burp_session_snapshot", tool_names)

        with patch.object(
            mcp_app.TOOLS["analyze_security_exchange"],
            "handler",
            return_value={"advisory": {"analysis": "ok"}, "run": {"phases": {}}},
        ):
            call_response = mcp_app.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "analyze_security_exchange",
                        "arguments": {"raw_request": "GET / HTTP/1.1"},
                    },
                }
            )

        self.assertFalse(call_response["result"]["isError"])
        self.assertEqual(call_response["result"]["structuredContent"]["advisory"]["analysis"], "ok")
        self.assertEqual(
            json.loads(call_response["result"]["content"][0]["text"])["advisory"]["analysis"],
            "ok",
        )

    def test_validate_hypothesis_labels_missing_evidence(self):
        payload = {"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"}
        advisory = {
            "analysis_backend": "mcp+ollama",
            "fallback_used": False,
            "primary_next_action": "compare one clean baseline in Repeater",
            "questions_for_user": ["which tenant boundary changed?"],
            "confirmation_playbooks": ["collect one role-separated diff"],
        }
        run = {
            "hypotheses": [
                {
                    "id": "hyp-1",
                    "vuln_class": "idor",
                    "summary": "[idor] object access changed across users",
                    "confidence": 0.82,
                    "status": "suspected",
                }
            ],
            "evidence": [
                {"source": "timeline", "summary": "same object returned 200 for another user"},
                {"source": "local-kb", "summary": "similar IDOR pattern"},
            ],
        }

        result = validation_service.validate_hypothesis(payload, advisory=advisory, run=run)

        self.assertEqual(result["validation_status"], "needs-confirmation")
        self.assertEqual(result["hypothesis"]["id"], "hyp-1")
        self.assertTrue(result["recommended_actions"])

    def test_build_structured_report_combines_evidence_validation_and_impact(self):
        evidence_bundle = {
            "job_id": "job-20",
            "target_url": "https://example.com",
            "primary_next_action": "use repeater",
            "report_summary": "stored analysis",
            "reporting_checklist": ["baseline first"],
            "hypothesis_summaries": [{"vuln_class": "xss", "summary": "reflected", "confidence": 0.8, "status": "suspected"}],
            "evidence_artifacts": [{"source": "rule-engine", "summary": "reflection detected"}],
            "analysis_backend": "mcp+ollama",
            "fallback_used": False,
            "source_links": ["https://portswigger.net/web-security/xss"],
        }
        with (
            patch.object(report_service, "build_report_evidence", return_value=evidence_bundle),
            patch.object(report_service, "validate_hypothesis", return_value={"validation_status": "needs-confirmation"}),
            patch.object(report_service, "rank_impact_paths", return_value={"reportable": True, "escalation_profile": "rendering-sink", "baseline_confirmation": "Confirm sink", "safe_vapt_escalation_steps": ["step"], "business_impact_expansion_paths": ["path"], "required_evidence_for_upgrade": ["evidence"], "stop_conditions": ["stop"], "likely_severity_promotions": ["promote"], "policy_gate": {}}),
        ):
            result = report_service.build_structured_report(
                "job-20",
                payload_like={"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"},
                advisory={"analysis_backend": "mcp+ollama"},
                run={"hypotheses": [], "evidence": []},
            )

        self.assertEqual(result["job_id"], "job-20")
        self.assertEqual(result["validation_assessment"]["validation_status"], "needs-confirmation")
        self.assertTrue(result["impact_assessment"]["reportable"])
        self.assertEqual(result["escalation_guidance"]["escalation_profile"], "rendering-sink")
        self.assertEqual(result["labeled_reporting_steps"][0]["label"], "high-signal")

    def test_build_structured_report_uses_persisted_record_when_payload_missing(self):
        evidence_bundle = {
            "job_id": "job-21",
            "target_url": "https://example.com",
            "primary_next_action": "use repeater",
            "report_summary": "stored analysis",
            "reporting_checklist": ["baseline first"],
            "hypothesis_summaries": [],
            "evidence_artifacts": [],
            "analysis_backend": "mcp+ollama",
            "fallback_used": False,
            "source_links": [],
        }
        record = {
            "raw_request": "GET / HTTP/1.1",
            "target_url": "https://example.com",
            "result": {"analysis_backend": "mcp+ollama"},
            "analysis_run": {"hypotheses": [], "evidence": []},
        }
        with (
            patch.object(report_service, "build_report_evidence", return_value=evidence_bundle),
            patch.object(report_service, "get_job_record", return_value=record),
            patch.object(report_service, "validate_hypothesis", return_value={"validation_status": "needs-confirmation"}),
            patch.object(report_service, "rank_impact_paths", return_value={"reportable": False}),
        ):
            result = report_service.build_structured_report("job-21")

        self.assertEqual(result["validation_assessment"]["validation_status"], "needs-confirmation")
        self.assertFalse(result["impact_assessment"]["reportable"])

    def test_build_structured_report_uses_snapshot_override_when_requested(self):
        evidence_bundle = {
            "job_id": "job-22",
            "request_id": "req-22",
            "snapshot_id": "snap-1",
            "target_url": "https://example.com",
            "primary_next_action": "use repeater",
            "report_summary": "stored analysis",
            "reporting_checklist": ["baseline first"],
            "hypothesis_summaries": [],
            "evidence_artifacts": [],
            "analysis_backend": "mcp+ollama",
            "fallback_used": False,
            "source_links": [],
            "burp_session_snapshot": {"snapshot_id": "snap-1"},
        }
        snapshot = {
            "snapshot_id": "snap-override",
            "created_at": "2026-03-31T00:00:00+00:00",
            "proxy_history": {"count": 2},
        }
        with (
            patch.object(report_service, "build_report_evidence", return_value=evidence_bundle),
            patch.object(report_service, "get_burp_session_snapshot", return_value=snapshot),
            patch.object(report_service, "validate_hypothesis", return_value={"validation_status": "needs-confirmation"}),
            patch.object(report_service, "rank_impact_paths", return_value={"reportable": False}),
        ):
            result = report_service.build_structured_report(
                "job-22",
                payload_like={"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"},
                advisory={"analysis_backend": "mcp+ollama"},
                run={"hypotheses": [], "evidence": []},
                snapshot_id="snap-override",
            )

        self.assertEqual(result["snapshot_id"], "snap-override")
        self.assertEqual(result["burp_session_snapshot"]["snapshot_id"], "snap-override")

    def test_program_policy_templates_expose_platform_specific_guidance(self):
        template = program_policy_service.get_program_policy_template("bugcrowd")

        self.assertEqual(template["name"], "bugcrowd")
        self.assertTrue(template["browser_verification_rules"])
        self.assertTrue(template["report_expectations"])

    def test_browser_verification_plan_requires_explicit_allowed_workflows(self):
        payload = {
            "raw_request": "GET /profile HTTP/1.1",
            "target_url": "https://example.com/profile",
            "browser_verification_allowed": False,
        }
        validation = {
            "validation_status": "needs-confirmation",
            "hypothesis": {"vuln_class": "xss"},
        }
        impact = {
            "reportability": "medium",
            "recommended_path": "Confirm rendered output",
            "safest_next_proof": "Confirm the rendering context.",
        }
        plan = browser_verification_service.build_browser_verification_plan(
            payload,
            advisory={"fallback_used": False},
            run={"hypotheses": [], "evidence": []},
            validation=validation,
            impact=impact,
        )

        self.assertTrue(plan["eligible"])
        self.assertFalse(plan["allowed"])
        self.assertIn("explicit opt-in", plan["reason"])
        self.assertEqual(plan["labeled_steps"][0]["label"], "out-of-scope-risk")

    def test_submission_report_combines_policy_browser_and_severity_outputs(self):
        structured_report = {
            "job_id": "job-30",
            "request_id": "req-30",
            "snapshot_id": "snap-30",
            "title": "AI Bridge Report for https://example.com",
            "summary": "stored analysis",
            "reporting_checklist": ["Capture one baseline response."],
            "hypothesis_summaries": [{"vuln_class": "idor", "summary": "[idor] cross-account read"}],
            "evidence_artifacts": [{"source": "proxy", "summary": "200/403 diff"}],
            "impact_assessment": {"reportability": "high", "business_impact_class": "high-impact", "safest_next_proof": "Keep one role comparison."},
            "validation_assessment": {"validation_status": "confirmed"},
            "escalation_guidance": {"escalation_profile": "authorization-boundary", "baseline_confirmation": "Keep one role comparison.", "required_evidence_for_upgrade": ["Role diff"]},
            "burp_session_snapshot": {"snapshot_id": "snap-30"},
        }
        severity = {
            "severity": "high",
            "confidence": 0.81,
            "candidate_taxonomy": "Access Control / IDOR",
            "rationale": "rationale",
            "promotion_triggers": [],
            "downgrade_reasons": [],
            "reportability_gate": {
                "already_proven": ["Cross-account object access is confirmed."],
                "still_inferred": ["The wider tenant blast radius is still inferred."],
                "unsafe_to_claim_yet": ["Do not claim tenant-wide exposure without one more object proof."],
            },
            "submission_value_score": {
                "score": 0.84,
                "components": {"reproducibility": 0.9},
                "summary": "Strong submission candidate with good triage value.",
            },
        }
        browser_plan = {
            "allowed": True,
            "verification_goal": "Confirm the same object across two allowed roles.",
            "allowed_workflows": ["profile settings"],
            "suggested_steps": ["Review only these allowed workflows before opening the browser: profile settings."],
            "stop_conditions": ["Stop before destructive state changes."],
        }
        record = {
            "job_id": "job-30",
            "target_url": "https://example.com",
            "scope_includes_text": "customer profile settings",
            "result": {},
            "analysis_run": {},
        }
        with (
            patch.object(submission_report_service, "get_job_record", return_value=record),
            patch.object(submission_report_service, "build_structured_report", return_value=structured_report),
            patch.object(submission_report_service, "assess_submission_severity", return_value=severity),
            patch.object(submission_report_service, "build_browser_verification_plan", return_value=browser_plan),
        ):
            report = submission_report_service.build_bug_bounty_submission("job-30", platform="bugcrowd")

        self.assertEqual(report["template_name"], "bugcrowd")
        self.assertEqual(report["severity_assessment"]["severity"], "high")
        self.assertTrue(report["browser_verification_appendix"]["allowed"])
        self.assertEqual(report["escalation_guidance"]["escalation_profile"], "authorization-boundary")
        self.assertEqual(report["impact_upgrade_planner"]["likely_severity_if_confirmed"], "high")
        self.assertEqual(report["submission_value_score"]["score"], 0.84)
        self.assertEqual(report["program_specific_impact_wording"]["platform"], "bugcrowd")
        self.assertIn("Capture one baseline response.", report["markdown"])
        self.assertIn("## Impact Upgrade Planner", report["markdown"])
        self.assertEqual(report["snapshot_id"], "snap-30")

    def test_submission_report_passes_snapshot_override_to_structured_report(self):
        record = {
            "job_id": "job-31",
            "target_url": "https://example.com",
            "result": {},
            "analysis_run": {},
        }
        structured_report = {
            "job_id": "job-31",
            "request_id": "req-31",
            "snapshot_id": "snap-override",
            "title": "AI Bridge Report for https://example.com",
            "summary": "stored analysis",
            "reporting_checklist": [],
            "hypothesis_summaries": [],
            "evidence_artifacts": [],
            "impact_assessment": {"reportability": "medium", "business_impact_class": "security-impact", "safest_next_proof": "baseline"},
            "validation_assessment": {"validation_status": "needs-confirmation"},
            "burp_session_snapshot": {"snapshot_id": "snap-override"},
        }
        with (
            patch.object(submission_report_service, "get_job_record", return_value=record),
            patch.object(submission_report_service, "build_structured_report", return_value=structured_report) as mocked_build,
            patch.object(submission_report_service, "assess_submission_severity", return_value={"severity": "medium", "confidence": 0.6, "candidate_taxonomy": "General", "rationale": "r", "promotion_triggers": [], "downgrade_reasons": []}),
            patch.object(submission_report_service, "build_browser_verification_plan", return_value={"allowed": False, "verification_goal": "", "allowed_workflows": [], "suggested_steps": [], "stop_conditions": []}),
        ):
            report = submission_report_service.build_bug_bounty_submission("job-31", platform="hackerone", snapshot_id="snap-override")

        mocked_build.assert_called_once_with(
            "job-31",
            payload_like=record,
            advisory=record.get("result") or {},
            run=record.get("analysis_run") or {},
            snapshot_id="snap-override",
        )
        self.assertEqual(report["snapshot_id"], "snap-override")

    def test_severity_assessment_stays_medium_for_unconfirmed_high_impact_findings(self):
        severity = severity_service.assess_submission_severity(
            {"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com"},
            validation={
                "validation_status": "needs-confirmation",
                "hypothesis": {"vuln_class": "idor"},
                "evidence_score": 1.8,
            },
            impact={
                "reportable": False,
                "reportability": "medium",
                "business_impact_class": "high-impact",
                "confirmation_state": "needs-confirmation",
                "dashboard_issue": {"severity": "high"},
                "evidence_score": 1.8,
            },
        )

        self.assertEqual(severity["severity"], "medium")
        self.assertTrue(severity["downgrade_reasons"])

    def test_recommendation_services_use_rule_context_aggregate(self):
        aggregate = {
            "bcheck_recommendations": ["Passive cookie hardening check"],
            "project_readiness_summary": "ready",
            "project_readiness_checks": ["capture one clean baseline response"],
            "burp_action_checklist": ["send the baseline to Repeater"],
        }
        rule_context = {"aggregate": aggregate, "matched_recipes": [{"title": "Session Review"}]}
        payload = {"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com", "review_scope_include_classes": ["session-management"]}

        with patch.object(recommendation_service, "build_rule_context", return_value=rule_context):
            bchecks = recommendation_service.recommend_bchecks_for_exchange(payload)
            readiness = recommendation_service.review_project_readiness(payload)

        self.assertEqual(bchecks["recommended_bchecks"][0], "Passive cookie hardening check")
        self.assertEqual(readiness["project_readiness_summary"], "ready")
        self.assertEqual(readiness["labeled_project_readiness_checks"][0]["label"], "high-signal")

    def test_recommendation_service_selects_one_official_bcheck_and_builds_one_best_next_step(self):
        aggregate = {"bcheck_recommendations": ["Passive cookie hardening check"]}
        rule_context = {
            "aggregate": aggregate,
            "matched_recipes": [{"title": "IDOR Review", "vuln_class": "idor"}],
            "features": {"path": "/api/invoices/42", "method": "GET", "signals": set(), "observations": []},
            "review_scope": {"allowed_classes": ["idor"], "suppressed_classes": []},
        }
        with (
            patch.object(recommendation_service, "build_rule_context", return_value=rule_context),
            patch.object(recommendation_service, "get_dashboard_issue_context", return_value={"issue_id": "issue-104", "vuln_hint": "idor"}),
            patch.object(recommendation_service, "summarize_issue_family_memory", return_value={"preferred_bcheck_ids": [], "suppressed_bcheck_ids": [], "bcheck_learning_summary": {"score_by_bcheck": {}}}),
            patch.object(recommendation_service, "recommend_bchecks", return_value=[
                {
                    "name": "IDOR Boundary Check",
                    "relative_path": "other/auth/idor-boundary.bcheck",
                    "source_url": "https://github.com/PortSwigger/BChecks/blob/main/other/auth/idor-boundary.bcheck",
                    "scan_mode": "passive",
                    "execution_context": "request",
                    "requires_collaborator": False,
                    "methods": ["GET"],
                    "vuln_classes": ["idor"],
                    "usage_hint": "Run it only on the current object family.",
                    "why": "matches target class idor",
                    "score": 9,
                    "description": "desc",
                    "author": "PortSwigger",
                    "language": "v2-beta",
                    "tags": ["idor"],
                    "collection": "other",
                }
            ]),
        ):
            result = recommendation_service.recommend_bchecks_for_exchange(
                {"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com/api/invoices/42"}
            )

        self.assertEqual(result["selected_official_bcheck"]["name"], "IDOR Boundary Check")
        self.assertEqual(result["one_best_next_step"]["source"], "official-bcheck-selector")
        self.assertTrue(result["curated_reference_links"])

    def test_build_report_evidence_uses_persisted_analysis_run(self):
        record = {
            "job_id": "job-1",
            "request_id": "req-1",
            "target_url": "https://example.com",
            "http_method": "GET",
            "result": {
                "analysis": "stored analysis",
                "primary_next_action": "use repeater",
                "burp_action_checklist": ["baseline first"],
                "confirmation_playbooks": ["collect diff"],
                "source_links": ["https://portswigger.net/web-security/xss"],
                "analysis_backend": "ollama",
                "fallback_used": False,
            },
            "analysis_run": {
                "hypotheses": [
                    {
                        "vuln_class": "xss",
                        "summary": "[xss] reflected output",
                        "confidence": 0.8,
                        "status": "suspected",
                        "next_checks": ["compare reflected output"],
                    }
                ],
                "evidence": [
                    {
                        "source": "rule-engine",
                        "summary": "response reflects user-controlled input",
                        "confidence": 0.65,
                        "delta": "",
                        "notes": "",
                        "timestamp": "2026-03-29T00:00:00+00:00",
                    }
                ],
            },
        }
        with patch.object(history_service, "get_job_record", return_value=record):
            evidence_bundle = history_service.build_report_evidence("job-1")

        self.assertEqual(evidence_bundle["job_id"], "job-1")
        self.assertEqual(evidence_bundle["request_id"], "req-1")
        self.assertEqual(evidence_bundle["hypothesis_summaries"][0]["vuln_class"], "xss")
        self.assertEqual(evidence_bundle["evidence_artifacts"][0]["source"], "rule-engine")
        self.assertEqual(evidence_bundle["evidence_artifacts"][0]["timestamp"], "2026-03-29T00:00:00+00:00")

    def test_normalize_burp_payload_contract_accepts_external_aliases(self):
        normalized = analysis_service.coerce_payload(
            {
                "request": "GET /alias HTTP/1.1",
                "response": "HTTP/1.1 200 OK",
                "url": "https://example.com/alias",
                "method": "GET",
                "dashboard_issue": {
                    "id": "issue-1",
                    "title": "Insecure direct object reference",
                    "description": "Role B sees Role A content.",
                },
                "proxy_history": [{"message": "baseline", "url": "https://example.com/alias"}],
                "logger_deltas": [{"message": "delta seen", "request_id": "logger-1"}],
                "repeater_tabs": [{"message": "comparison tab", "request_id": "rep-1"}],
                "project_options": {"profile": "bug-bounty-safe", "loaded_tools": ["Proxy", "Repeater"]},
            }
        )

        self.assertEqual(normalized.raw_request, "GET /alias HTTP/1.1")
        self.assertEqual(normalized.target_url, "https://example.com/alias")
        self.assertEqual(normalized.burp_dashboard_issue["issue_id"], "issue-1")
        self.assertEqual(normalized.burp_dashboard_issue["name"], "Insecure direct object reference")
        self.assertEqual(normalized.proxy_history_entries[0]["summary"], "baseline")
        self.assertEqual(normalized.logger_entries[0]["request_ref"], "logger-1")
        self.assertEqual(normalized.repeater_requests[0]["request_ref"], "rep-1")
        self.assertEqual(normalized.project_config_snapshot["selected_profile"], "bug-bounty-safe")

    def test_normalize_burp_payload_contract_accepts_burp_context_envelope(self):
        normalized = analysis_service.coerce_payload(
            {
                "burp_context": {
                    "request_text": "GET /wrapped HTTP/1.1",
                    "response_text": "HTTP/1.1 200 OK",
                    "url": "https://example.com/wrapped",
                    "method": "GET",
                    "issue_context": {
                        "selected_issue": {
                            "title": "Reflected input",
                            "severity": "medium",
                        }
                    },
                    "http_history": {"entries": [{"message": "baseline wrapped", "request_id": "hist-1"}]},
                    "project_options": {"config": {"profile": "bug-bounty-safe"}},
                }
            }
        )

        self.assertEqual(normalized.raw_request, "GET /wrapped HTTP/1.1")
        self.assertEqual(normalized.target_url, "https://example.com/wrapped")
        self.assertEqual(normalized.burp_dashboard_issue["name"], "Reflected input")
        self.assertEqual(normalized.proxy_history_entries[0]["request_ref"], "hist-1")
        self.assertEqual(normalized.project_config_snapshot["selected_profile"], "bug-bounty-safe")

    def test_prepare_burp_export_payload_summarizes_transport_ready_bundle(self):
        prepared = prepare_burp_export(
            {
                "burp_context": {
                    "request_text": "GET /export HTTP/1.1",
                    "url": "https://example.com/export",
                    "method": "GET",
                    "issue_context": {"title": "Scanner issue"},
                    "http_history": [{"message": "baseline"}],
                    "logger_deltas": [{"message": "delta"}],
                }
            }
        )

        self.assertEqual(prepared["payload"]["target_url"], "https://example.com/export")
        self.assertTrue(prepared["summary"]["dashboard_issue_found"])
        self.assertEqual(prepared["summary"]["proxy_history_count"], 1)
        self.assertEqual(prepared["summary"]["logger_entry_count"], 1)
        self.assertEqual(prepared["next_step"]["mcp_tool"], "analyze_security_exchange")

    def test_burp_context_service_summarizes_dashboard_proxy_logger_and_repeater(self):
        payload = {
            "raw_request": "GET /users/123 HTTP/1.1",
            "raw_response": "HTTP/1.1 200 OK",
            "target_url": "https://example.com/users/123",
            "http_method": "GET",
            "burp_dashboard_issue": {
                "name": "Insecure direct object reference",
                "severity": "high",
                "confidence": "firm",
                "detail": "User profile response changes across accounts.",
                "request_refs": ["proxy-1"],
            },
            "proxy_history_entries": [
                {"summary": "GET /users/123 returned 200", "method": "GET", "url": "https://example.com/users/123", "timestamp": "2026-03-29T00:00:00+00:00"},
            ],
            "logger_entries": [
                {"summary": "Role B saw Role A data", "request_ref": "logger-1", "timestamp": "2026-03-29T00:00:01+00:00"},
            ],
            "repeater_requests": [
                {"summary": "Cross-account comparison request", "method": "GET", "url": "https://example.com/users/123", "request_ref": "repeater-1"},
            ],
            "project_config_snapshot": {
                "enabled_tools": ["Proxy", "Repeater", "Logger"],
                "warnings": ["Scanner issue still needs manual confirmation."],
            },
        }

        summary = burp_context_service.summarize_burp_context(payload)
        issue = burp_context_service.get_dashboard_issue_context(payload)

        self.assertTrue(issue["found"])
        self.assertEqual(issue["vuln_hint"], "authorization")
        self.assertEqual(summary["proxy_history_count"], 1)
        self.assertEqual(summary["logger_entry_count"], 1)
        self.assertEqual(summary["repeater_request_count"], 1)
        self.assertEqual(summary["enabled_tool_count"], 3)

    def test_rank_impact_paths_keeps_unconfirmed_dashboard_issue_non_reportable(self):
        payload = {
            "raw_request": "GET /users/123 HTTP/1.1",
            "target_url": "https://example.com/users/123",
            "burp_dashboard_issue": {
                "name": "Insecure direct object reference",
                "severity": "high",
                "confidence": "firm",
                "detail": "User profile data is returned across accounts.",
            },
        }
        advisory = {
            "analysis_backend": "mcp+ollama",
            "fallback_used": False,
            "primary_next_action": "compare one clean baseline in Repeater",
            "questions_for_user": ["which account boundary changed?"],
            "confirmation_playbooks": ["collect one role-separated diff"],
            "impact_paths": ["unauthorized cross-account profile access"],
            "potential_vulnerabilities": ["[idor] profile exposure"],
        }
        run = {
            "hypotheses": [
                {
                    "id": "hyp-1",
                    "vuln_class": "authorization",
                    "summary": "[idor] profile exposure",
                    "confidence": 0.86,
                    "status": "suspected",
                }
            ],
            "evidence": [
                {"source": "burp-dashboard", "summary": "scanner finding"},
                {"source": "proxy", "summary": "200 response on second account"},
            ],
        }

        result = impact_service.rank_impact_paths(payload, advisory=advisory, run=run)

        self.assertFalse(result["reportable"])
        self.assertEqual(result["reportability"], "medium")
        self.assertEqual(result["confirmation_state"], "needs-confirmation")
        self.assertEqual(result["business_impact_class"], "high-impact")
        self.assertTrue(result["safe_vapt_escalation_steps"])
        self.assertEqual(result["escalation_profile"], "authorization-boundary")
        self.assertTrue(result["required_evidence_for_upgrade"])
        self.assertEqual(result["dashboard_issue"]["vuln_hint"], "authorization")

    def test_rank_impact_paths_marks_confirmed_dashboard_issue_reportable_with_typed_evidence(self):
        payload = {
            "raw_request": "GET /users/123 HTTP/1.1",
            "target_url": "https://example.com/users/123",
            "burp_dashboard_issue": {
                "name": "Insecure direct object reference",
                "severity": "high",
                "confidence": "firm",
                "detail": "User profile data is returned across accounts.",
            },
        }
        advisory = {
            "analysis_backend": "mcp+ollama",
            "fallback_used": False,
            "primary_next_action": "capture the role-separated diff",
            "questions_for_user": [],
            "confirmation_playbooks": ["preserve the role-separated diff"],
            "impact_paths": ["unauthorized cross-account profile access"],
            "potential_vulnerabilities": ["[idor] profile exposure"],
        }
        run = {
            "hypotheses": [
                {
                    "id": "hyp-1",
                    "vuln_class": "authorization",
                    "summary": "[idor] profile exposure",
                    "confidence": 0.91,
                    "status": "confirmed",
                }
            ],
            "evidence": [
                {"source": "burp-dashboard", "evidence_type": "scanner", "summary": "scanner finding"},
                {"source": "repeater", "evidence_type": "role-compare", "summary": "role A vs role B diff"},
                {"source": "logger", "evidence_type": "manual-diff", "summary": "stable 200/403 delta"},
            ],
        }

        result = impact_service.rank_impact_paths(payload, advisory=advisory, run=run)

        self.assertTrue(result["reportable"])
        self.assertEqual(result["confirmation_state"], "confirmed")
        self.assertGreaterEqual(result["evidence_score"], 2.5)

    def test_rank_impact_paths_gates_high_risk_ssrf_without_explicit_policy_allowance(self):
        payload = {
            "raw_request": "POST /fetch HTTP/1.1",
            "target_url": "https://example.com/fetch",
            "burp_dashboard_issue": {
                "name": "Server-side request forgery",
                "severity": "medium",
                "confidence": "tentative",
                "detail": "The server fetches attacker-supplied URLs.",
            },
        }
        advisory = {
            "analysis_backend": "ollama",
            "fallback_used": False,
            "primary_next_action": "Confirm one approved callback.",
            "questions_for_user": ["Can you confirm one approved callback?"],
            "confirmation_playbooks": ["Keep one approved callback only."],
            "impact_paths": ["Server fetch to attacker-controlled URL."],
            "potential_vulnerabilities": ["[ssrf] outbound fetch in preview flow"],
        }
        run = {
            "hypotheses": [
                {
                    "id": "hyp-1",
                    "vuln_class": "ssrf",
                    "summary": "[ssrf] outbound fetch in preview flow",
                    "confidence": 0.66,
                    "status": "suspected",
                }
            ],
            "evidence": [
                {"source": "collaborator", "evidence_type": "callback", "summary": "Approved callback observed"},
            ],
        }

        result = impact_service.rank_impact_paths(payload, advisory=advisory, run=run)

        self.assertTrue(result["policy_gate"]["applies"])
        self.assertFalse(result["policy_gate"]["allowed"])
        self.assertIn("gated", result["policy_gate"]["reason"].lower())
        self.assertIn("baseline", result["safest_next_proof"].lower())
        self.assertFalse(result["business_impact_expansion_paths"])

    def test_rank_impact_paths_allows_high_risk_ssrf_when_policy_explicitly_allows_it(self):
        payload = {
            "raw_request": "POST /fetch HTTP/1.1",
            "target_url": "https://example.com/fetch",
            "program_policy_text": "SSRF allowed. Collaborator allowed for one approved callback.",
            "burp_dashboard_issue": {
                "name": "Server-side request forgery",
                "severity": "medium",
                "confidence": "tentative",
                "detail": "The server fetches attacker-supplied URLs.",
            },
        }
        advisory = {
            "analysis_backend": "ollama",
            "fallback_used": False,
            "primary_next_action": "Confirm one approved callback.",
            "questions_for_user": ["Can you confirm one approved callback?"],
            "confirmation_playbooks": ["Keep one approved callback only."],
            "impact_paths": ["Server fetch to attacker-controlled URL."],
            "potential_vulnerabilities": ["[ssrf] outbound fetch in preview flow"],
        }
        run = {
            "hypotheses": [
                {
                    "id": "hyp-1",
                    "vuln_class": "ssrf",
                    "summary": "[ssrf] outbound fetch in preview flow",
                    "confidence": 0.66,
                    "status": "suspected",
                }
            ],
            "evidence": [
                {"source": "collaborator", "evidence_type": "callback", "summary": "Approved callback observed"},
            ],
        }

        result = impact_service.rank_impact_paths(payload, advisory=advisory, run=run)

        self.assertTrue(result["policy_gate"]["applies"])
        self.assertTrue(result["policy_gate"]["allowed"])
        self.assertEqual(result["safest_next_proof"], "Confirm one approved callback.")
        self.assertTrue(result["business_impact_expansion_paths"])

    def test_escalation_service_returns_profiles_for_multiple_bug_bounty_classes(self):
        auth_guidance = escalation_service.build_escalation_guidance(
            {"target_url": "https://example.com/a"},
            advisory={"potential_vulnerabilities": ["[idor] cross-tenant read"]},
            selected={"vuln_class": "idor", "status": "suspected"},
        )
        redirect_guidance = escalation_service.build_escalation_guidance(
            {"target_url": "https://example.com/login"},
            advisory={"potential_vulnerabilities": ["[open-redirect] login redirect trusts returnUrl"]},
            selected={"vuln_class": "open-redirect", "status": "suspected"},
        )
        upload_guidance = escalation_service.build_escalation_guidance(
            {"target_url": "https://example.com/upload"},
            advisory={"potential_vulnerabilities": ["[file-upload] profile image upload accepts unexpected types"]},
            selected={"vuln_class": "file-upload", "status": "suspected"},
        )

        self.assertEqual(auth_guidance["escalation_profile"], "authorization-boundary")
        self.assertIn("role-separated", auth_guidance["baseline_confirmation"].lower())
        self.assertEqual(redirect_guidance["escalation_profile"], "redirect-trust")
        self.assertTrue(redirect_guidance["required_evidence_for_upgrade"])
        self.assertEqual(upload_guidance["escalation_profile"], "upload-surface")
        self.assertTrue(upload_guidance["stop_conditions"])

    def test_query_similar_history_returns_stored_hypotheses(self):
        payload = {"raw_request": "GET / HTTP/1.1", "target_url": "https://example.com", "http_method": "GET"}
        history_record = {
            "job_id": "job-2",
            "target_url": "https://example.com/profile",
            "created_at": "2026-03-29T00:00:00+00:00",
            "result": {
                "potential_vulnerabilities": ["[idor] user profile exposure"],
                "analysis_backend": "mcp+ollama",
            },
            "analysis_run": {
                "hypotheses": [
                    {
                        "id": "hyp-1",
                        "vuln_class": "idor",
                        "summary": "[idor] user profile exposure",
                        "confidence": 0.9,
                    }
                ],
                "evidence": [{"source": "timeline", "summary": "403 turned 200"}],
            },
        }
        with (
            patch.object(history_service, "build_deterministic_context", return_value={"features": {}, "matched_recipes": []}),
            patch.object(history_service, "build_history_fingerprint", return_value={"signature": "sig"}),
            patch.object(
                history_service,
                "find_history_matches",
                return_value=[
                    {
                        "job_id": "job-2",
                        "target_url": "https://example.com/profile",
                        "created_at": "2026-03-29T00:00:00+00:00",
                        "similarity": 0.91,
                        "shared_vuln_classes": ["idor"],
                        "feedback_labels": ["useful"],
                    }
                ],
            ),
            patch.object(history_service, "describe_history_matches", return_value=["Found a prior exact endpoint match."]),
            patch.object(history_service, "read_history_records", return_value=[history_record]),
        ):
            result = history_service.query_similar_history(payload, limit=3)

        self.assertEqual(result["matches"][0]["hypotheses"][0]["vuln_class"], "idor")
        self.assertEqual(result["matches"][0]["evidence_count"], 1)

    def test_update_hypothesis_status_returns_updated_state(self):
        before_record = {
            "job_id": "job-3",
            "analysis_run": {
                "hypotheses": [
                    {"id": "hyp-1", "summary": "Possible IDOR", "status": "suspected"},
                ]
            },
        }
        after_record = {
            "job_id": "job-3",
            "analysis_run": {
                "hypotheses": [
                    {
                        "id": "hyp-1",
                        "summary": "Possible IDOR",
                        "status": "confirmed",
                        "status_notes": "Verified with a second account.",
                        "status_updated_at": "2026-03-29T00:00:00+00:00",
                    },
                ]
            },
        }
        with (
            patch.object(history_service, "get_job_record", side_effect=[before_record, after_record]),
            patch.object(history_service, "append_hypothesis_transition"),
        ):
            result = history_service.update_hypothesis_status("job-3", "hyp-1", "confirmed", "Verified with a second account.")

        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["notes"], "Verified with a second account.")

    def test_memory_summary_promotes_confirmed_kb_signals_and_suppresses_discarded(self):
        summary = memory_retrieval.summarize_similar_findings(
            [
                {
                    "fingerprint": {"vuln_classes": ["idor"]},
                    "feedback_score": 4,
                    "feedback_labels": ["useful"],
                    "target_url": "https://example.com/a",
                    "confirmed_classes": ["idor"],
                    "discarded_classes": [],
                    "kb_signal_tags": ["idor", "access-control"],
                    "kb_signal_titles": ["Auth Bypass Template"],
                    "exact_signature": True,
                },
                {
                    "fingerprint": {"vuln_classes": ["xss"]},
                    "feedback_score": -3,
                    "feedback_labels": ["false_positive"],
                    "target_url": "https://example.com/b",
                    "confirmed_classes": [],
                    "discarded_classes": ["xss"],
                    "kb_signal_tags": ["xss"],
                    "kb_signal_titles": ["Reflective XSS Notes"],
                    "exact_signature": False,
                },
            ]
        )

        self.assertIn("idor", summary["preferred_vuln_classes"])
        self.assertIn("xss", summary["deprioritized_vuln_classes"])
        self.assertIn("Auth Bypass Template", summary["preferred_kb_titles"])
        self.assertIn("Reflective XSS Notes", summary["deprioritized_kb_titles"])

    def test_list_history_records_returns_paginated_items(self):
        records = [
            {
                "job_id": "job-10",
                "created_at": "2026-03-29T01:00:00+00:00",
                "target_url": "https://example.com/ten",
                "http_method": "GET",
                "status": "completed",
                "result": {"analysis_backend": "mcp+ollama", "fallback_used": False, "potential_vulnerabilities": ["[idor] issue"]},
                "analysis_run": {"hypotheses": [{"id": "hyp-1"}], "evidence": [{"source": "rule"}]},
            },
            {
                "job_id": "job-11",
                "created_at": "2026-03-29T02:00:00+00:00",
                "target_url": "https://example.com/eleven",
                "http_method": "POST",
                "status": "completed",
                "result": {"analysis_backend": "deterministic", "fallback_used": True, "potential_vulnerabilities": ["[xss] issue"]},
                "analysis_run": {"hypotheses": [{"id": "hyp-2"}, {"id": "hyp-3"}], "evidence": [{"source": "rule"}, {"source": "kb"}]},
            },
        ]
        with patch.object(
            history_service,
            "paginate_history_records",
            return_value={"cursor": 0, "limit": 1, "total": 2, "count": 1, "next_cursor": 1, "items": [records[1]]},
        ):
            page = history_service.list_history_records(cursor=0, limit=1)

        self.assertEqual(page["items"][0]["job_id"], "job-11")
        self.assertEqual(page["items"][0]["hypothesis_count"], 2)
        self.assertEqual(page["next_cursor"], 1)

    def test_query_phase_history_returns_persisted_phase_snapshots(self):
        with patch.object(
            history_service,
            "read_phase_snapshots",
            return_value=[
                {
                    "job_id": "job-55",
                    "created_at": "2026-03-30T00:00:00+00:00",
                    "target_url": "https://example.com/a",
                    "phase": "validate",
                    "result": {"validation_status": "needs-confirmation"},
                    "input_context": {"target_url": "https://example.com/a"},
                }
            ],
        ):
            result = history_service.query_phase_history(job_id="job-55", phase="validate", limit=10)

        self.assertEqual(result["count"], 1)
        self.assertEqual(result["items"][0]["phase"], "validate")

    def test_explain_analysis_run_summarizes_reasoning(self):
        with patch.object(
            history_service,
            "get_job_record",
            return_value={
                "job_id": "job-77",
                "target_url": "https://example.com/r",
                "result": {"primary_next_action": "capture the baseline", "fallback_used": True},
                "analysis_run": {
                    "hypotheses": [{"id": "hyp-1", "vuln_class": "xss", "summary": "reflected", "evidence_for": ["reflection found"]}],
                    "evidence": [{"source": "logger", "evidence_type": "manual-diff", "summary": "stable length delta", "confidence": 0.72}],
                    "phase_results": {
                        "validate": {"validation_status": "needs-confirmation", "missing_evidence": ["which role reflects?"]},
                        "impact": {"reportable": False, "reportability": "medium", "confirmation_state": "needs-confirmation"},
                        "report": {"backend": "mcp+ollama", "fallback_used": True},
                    },
                },
            },
        ):
            result = history_service.explain_analysis_run("job-77")

        self.assertEqual(result["top_hypothesis"]["vuln_class"], "xss")
        self.assertTrue(result["downgrade_reasons"])
        self.assertEqual(result["next_decision"]["reportability"], "medium")

    def test_payload_guidance_stays_bounded(self):
        sanitized = deterministic_guidance_service.sanitize_payload_examples(
            ["javascript:alert(1)", "http://127.0.0.1", "/etc/passwd", "probe123"]
        )

        self.assertIn("<benign confirmation variant>", sanitized)
        self.assertIn("probe123", sanitized)
        self.assertNotIn("javascript:alert(1)", sanitized)

    def test_burp_session_snapshot_bundles_issue_history_and_editor_context(self):
        with (
            patch.object(burp_snapshot_service, "augment_payload_with_burp_mcp", side_effect=lambda payload: payload),
            patch.object(burp_snapshot_service, "inspect_burp_mcp_capabilities", return_value={
                "server_name": "burp-mcp",
                "server_version": "1.0",
                "permitted_tools": ["get_proxy_http_history"],
                "blocked_tools": [],
                "read_only_only": True,
            }),
            patch.object(burp_snapshot_service, "call_burp_mcp_capability", side_effect=[
                {"content_text": "GET /editor HTTP/1.1", "structured_content": {}},
                {"content_text": '[{"id":"hist-1","url":"https://example.com/a"}]', "structured_content": {}},
            ]),
            patch.object(burp_snapshot_service, "append_burp_session_snapshot"),
        ):
            snapshot = burp_snapshot_service.build_burp_session_snapshot({
                "target_url": "https://example.com/a",
                "http_method": "GET",
                "source_tool": "repeater",
                "raw_request": "GET /a HTTP/1.1",
                "burp_dashboard_issue": {"name": "Insecure direct object reference", "severity": "high", "confidence": "firm"},
                "proxy_history_entries": [{"summary": "baseline", "request_ref": "hist-1"}],
            })

        self.assertEqual(snapshot["source_tool"], "repeater")
        self.assertEqual(snapshot["active_editor_request"], "GET /editor HTTP/1.1")
        self.assertTrue(snapshot["evidence_bundle"])

    def test_repeater_guidance_builds_scanner_anchored_mutation_plan(self):
        payload = {
            "raw_request": "GET /api/invoices/104?view=summary HTTP/1.1\r\nHost: example.com\r\nCookie: session=test\r\n\r\n",
            "target_url": "https://example.com/api/invoices/104?view=summary",
            "http_method": "GET",
            "source_tool": "scanner",
            "burp_dashboard_issue": {
                "issue_id": "issue-104",
                "name": "Insecure direct object reference",
                "severity": "high",
                "confidence": "firm",
                "detail": "Unauthorized access to another tenant invoice details.",
                "request_refs": ["proxy-104"],
                "highlights": [{"start_offset": 18, "end_offset": 21, "location": "path", "label": "object-id"}],
            },
            "burp_related_scanner_issues": [
                {
                    "issue_id": "issue-105",
                    "name": "Stored cross-site scripting",
                    "severity": "medium",
                    "confidence": "firm",
                    "detail": "The same invoice comment renders in an admin queue.",
                    "url": "https://example.com/api/invoices/104/comments",
                }
            ],
            "repeater_requests": [{"request_ref": "rep-1", "summary": "baseline tab"}],
        }
        advisory = {
            "primary_next_action": "Capture one role-separated diff.",
            "confirmation_playbooks": ["Compare the same invoice across two permitted identities."],
        }
        impact = {
            "baseline_confirmation": "Capture one role-separated diff.",
            "safe_vapt_escalation_steps": ["Compare the same object."],
            "policy_gate": {"applies": False, "allowed": True},
        }
        with (
            patch.object(repeater_guidance_service, "search_local_knowledge", return_value={"hits": [{"title": "IDOR note"}]}),
            patch.object(repeater_guidance_service, "build_deterministic_context", return_value={"features": {}, "matched_recipes": []}),
            patch.object(repeater_guidance_service, "build_history_fingerprint", return_value={"signature": "sig"}),
            patch.object(repeater_guidance_service, "find_history_matches", return_value=[]),
            patch.object(repeater_guidance_service, "summarize_history_matches", return_value={"note": "", "preferred_kb_titles": []}),
        ):
            result = repeater_guidance_service.build_repeater_escalation_plan(payload, advisory=advisory, impact=impact)

        self.assertEqual(result["scanner_focus"]["request_refs"][0], "proxy-104")
        self.assertEqual(result["repeater_mutation_plan"][0]["location"], "path")
        self.assertEqual(result["scanner_focus"]["highlights"][0]["start_offset"], 18)
        self.assertIn("<other-tenant-or-role-owned-value>", result["repeater_variant_requests"][0]["request_text"])
        self.assertIn("Stored cross-site scripting", result["issue_chain_strategy"][0] + " ".join(result["issue_chain_strategy"][1:]))
        self.assertEqual(result["preferred_request_ref"], "rep-1")

    def test_open_repeater_plan_dispatches_baseline_and_variants_when_capability_allowed(self):
        payload = {
            "raw_request": "GET /api/invoices/104 HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "target_url": "https://example.com/api/invoices/104",
            "source_tool": "scanner",
        }
        plan = {
            "dashboard_issue": {"issue_id": "issue-104", "issue_name": "Insecure direct object reference"},
            "related_scanner_issues": [],
            "preferred_request_ref": "proxy-104",
            "analysis_backend": "mcp+deterministic",
            "repeater_variant_requests": [
                {"name": "variant-1", "request_text": "GET /api/invoices/999 HTTP/1.1\r\nHost: example.com\r\n\r\n", "summary": "Swap id", "expected_signal": "200/403 diff"}
            ],
            "issue_chain_strategy": ["Confirm baseline first."],
        }
        inspection = {"capability_map": {"send_to_repeater": {"allowed": True, "tool_name": "open_in_repeater"}}}
        with (
            patch.object(repeater_dispatch_service, "burp_repeater_plan", return_value=plan),
            patch.object(repeater_dispatch_service, "inspect_burp_mcp_capabilities", return_value=inspection),
            patch.object(repeater_dispatch_service, "call_burp_mcp_capability", return_value={"tool_name": "open_in_repeater"}),
        ):
            result = repeater_dispatch_service.open_repeater_plan(payload, advisory={"analysis_backend": "mcp+deterministic"})

        self.assertEqual(result["opened_count"], 2)
        self.assertIn("baseline-control", result["tabs"][0]["tab_name"])
        self.assertEqual(result["tabs"][0]["issue_id"], "issue-104")
        self.assertEqual(result["results"][0]["status"], "opened")

    def test_issue_workflow_and_best_next_tab_use_diff_scores(self):
        payload = {
            "raw_request": "GET /api/invoices/104 HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "raw_response": "HTTP/1.1 403 Forbidden\r\nContent-Length: 12\r\n\r\nforbidden",
            "target_url": "https://example.com/api/invoices/104",
            "source_tool": "scanner",
            "repeater_variant_observations": [
                {
                    "tab_name": "Insecure direct object reference - issue-104 - variant-1",
                    "response_text": "HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n{\"invoiceId\":999,\"owner\":\"tenant-b\"}",
                }
            ],
        }
        plan = {
            "dashboard_issue": {"issue_id": "issue-104", "issue_name": "Insecure direct object reference"},
            "related_scanner_issues": [],
            "analysis_backend": "mcp+deterministic",
            "issue_chain_strategy": ["Confirm the access-control delta first."],
            "repeater_variant_requests": [
                {"name": "variant-1", "request_text": "GET /api/invoices/999 HTTP/1.1\r\nHost: example.com\r\n\r\n", "summary": "Swap id", "expected_signal": "200/403 diff"},
                {"name": "variant-2", "request_text": "GET /api/invoices/export HTTP/1.1\r\nHost: example.com\r\n\r\n", "summary": "List view", "expected_signal": "List exposure"},
            ],
        }
        with (
            patch.object(issue_workflow_service, "burp_repeater_plan", return_value=plan),
            patch.object(issue_workflow_service, "append_issue_workflow_state"),
            patch.object(issue_workflow_service, "get_issue_workflow_state", return_value={}),
            patch.object(issue_workflow_service, "summarize_issue_family_memory", return_value={"summary": "No issue-family memory matched this issue yet."}),
        ):
            workflow = issue_workflow_service.build_workflow_from_observations(payload, plan=plan)
            next_tab = issue_workflow_service.best_next_tab(payload, plan=plan, workflow=workflow)

        self.assertEqual(workflow["status"], "high-signal-delta")
        self.assertEqual(workflow["strongest_delta"]["tab_name"], "Insecure direct object reference - issue-104 - variant-1")
        self.assertEqual(workflow["issue_family_memory"]["summary"], "No issue-family memory matched this issue yet.")
        self.assertIn("variant-2", next_tab["tab_name"])

    def test_bcheck_learning_records_results_and_summarizes_issue_family(self):
        payload = {
            "raw_request": "GET /api/invoices/42 HTTP/1.1",
            "target_url": "https://example.com/api/invoices/42",
            "burp_dashboard_issue": {"issue_id": "issue-104", "vuln_hint": "idor"},
        }
        selected = {
            "name": "IDOR Boundary Check",
            "relative_path": "other/auth/idor-boundary.bcheck",
            "source_url": "https://github.com/PortSwigger/BChecks/blob/main/other/auth/idor-boundary.bcheck",
            "score": 8,
            "usage_hint": "Run only on the same object family.",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            learning_path = Path(temp_dir) / "bcheck_results.jsonl"
            with patch.object(bcheck_learning, "BCHECK_RESULT_PATH", learning_path):
                bcheck_learning.append_bcheck_result(payload, selected_bcheck=selected, outcome_label="useful", notes="helped")
                summary = bcheck_learning.summarize_bcheck_learning(payload_like=payload, issue_id="issue-104", vuln_classes=["idor"])

        self.assertIn("other/auth/idor-boundary.bcheck", summary["preferred_bcheck_ids"])


if __name__ == "__main__":
    unittest.main()
