import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.core.investigation_intelligence_service import build_investigation_intelligence


class InvestigationIntelligenceServiceTests(unittest.TestCase):
    def test_reporting_intent_stays_in_confirmation_when_evidence_is_thin(self):
        payload = SimpleNamespace(
            target_url="https://example.com/comments?id=1",
            response_delta_text="",
            logger_evidence_text="",
            collaborator_evidence_text="",
            evidence_timeline_entries=[],
            issue_workflow_notes=["Transcript [2026-04-12 09:10:00] You: Help me write the report wording."],
            bapp_findings_text="",
        )
        prompt_sections = {
            "follow_up_request": "Help me prepare the report wording and severity.",
            "issue_workflow_notes_summary": "- Prior note: no signal yet beyond scanner context.",
            "investigation_notebook_summary": "Investigation anchor\n- Target: https://example.com/comments?id=1",
            "scanner_issue_context": "Selected Burp scanner issue: reflected input returned in the response body.",
            "response_delta_summary": "No explicit response delta supplied.",
            "tool_results_summary": "No manual tool results supplied.",
            "logger_evidence_summary": "No Logger++ evidence supplied.",
            "collaborator_evidence_summary": "No Collaborator evidence supplied.",
            "evidence_timeline_summary": "No evidence timeline supplied.",
            "bapp_findings_summary": "No BApp findings supplied.",
        }
        rule_context = {
            "matched_recipes": [{"title": "Reflected XSS Review", "vuln_class": "xss"}],
            "features": {"observations": ["Response status: 200"]},
        }

        result = build_investigation_intelligence(
            payload,
            rule_context=rule_context,
            prompt_sections=prompt_sections,
            provider_candidate={"planner": {"vuln_type": "xss", "confidence": 0.88}},
        )

        self.assertEqual(result["phase_state"]["phase"], "confirmation")
        self.assertEqual(result["phase_state"]["desired_phase"], "reporting")
        self.assertEqual(result["phase_state"]["max_supported_phase"], "confirmation")
        self.assertEqual(result["contradiction_assessment"]["status"], "contradictions-present")
        self.assertEqual(result["evidence_sufficiency"]["ready_for_phase"], "confirmation")

    def test_dead_end_history_without_new_signal_creates_contradiction(self):
        payload = SimpleNamespace(
            target_url="https://example.com/api/invoices/104",
            response_delta_text="",
            logger_evidence_text="",
            collaborator_evidence_text="",
            evidence_timeline_entries=[],
            issue_workflow_notes=["Latest investigation status: no signal after the previous variant."],
            bapp_findings_text="",
        )
        prompt_sections = {
            "follow_up_request": "Try the same branch again.",
            "issue_workflow_notes_summary": "- Latest note: dead end, same result, no delta.",
            "investigation_notebook_summary": "Persistent notebook timeline\n- [2026-04-12 10:00:00] AI guidance update: same result, no signal.",
            "scanner_issue_context": "Selected Burp scanner issue: invoice access control suspicion.",
            "response_delta_summary": "No explicit response delta supplied.",
            "tool_results_summary": "",
            "logger_evidence_summary": "No Logger++ evidence supplied.",
            "collaborator_evidence_summary": "No Collaborator evidence supplied.",
            "evidence_timeline_summary": "No evidence timeline supplied.",
            "bapp_findings_summary": "No BApp findings supplied.",
        }
        rule_context = {
            "matched_recipes": [{"title": "IDOR Review", "vuln_class": "idor"}],
            "features": {"observations": ["Path: /api/invoices/104"]},
        }

        result = build_investigation_intelligence(
            payload,
            rule_context=rule_context,
            prompt_sections=prompt_sections,
        )

        contradictions = result["contradiction_assessment"]
        self.assertGreaterEqual(contradictions["count"], 1)
        self.assertTrue(any(item["code"] == "dead-end-without-new-signal" for item in contradictions["items"]))
        self.assertEqual(result["evidence_sufficiency"]["status"], "blocked")
        self.assertEqual(result["branch_guard"]["status"], "repeat-branch-blocked")
        self.assertIn("authorization:confirmation", result["branch_guard"]["deprioritized_branches"])
        self.assertIn("cache artifact", result["branch_guard"]["next_best_hypothesis"])

    def test_observed_signals_support_impact_phase_and_stronger_sufficiency(self):
        payload = SimpleNamespace(
            target_url="https://example.com/api/invoices/104",
            response_delta_text="Role B sees invoice 104 with the same endpoint.",
            logger_evidence_text="403 baseline became 200 with a role-separated variant.",
            collaborator_evidence_text="",
            evidence_timeline_entries=["baseline 403", "variant 200 with object data"],
            issue_workflow_notes=["Transcript [2026-04-12 11:05:00] You: assess the impact path now."],
            bapp_findings_text="",
        )
        prompt_sections = {
            "follow_up_request": "Assess the impact path and the strongest reportable next step.",
            "issue_workflow_notes_summary": "- Prior note: one clean role-separated diff is attached.",
            "investigation_notebook_summary": "Persistent notebook timeline\n- [2026-04-12 11:04:00] AI guidance update: role-separated invoice access is stable.",
            "scanner_issue_context": "Selected Burp scanner issue: insecure direct object reference.",
            "response_delta_summary": "403 baseline became 200 with the same invoice object visible.",
            "tool_results_summary": "",
            "logger_evidence_summary": "Logger++ confirms a stable 403/200 transition with the same object id.",
            "collaborator_evidence_summary": "No Collaborator evidence supplied.",
            "evidence_timeline_summary": "- baseline 403\n- variant 200 with invoice fields",
            "bapp_findings_summary": "No BApp findings supplied.",
        }
        rule_context = {
            "matched_recipes": [{"title": "IDOR Review", "vuln_class": "idor"}],
            "features": {"observations": ["Path: /api/invoices/104", "Response status: 200"]},
        }

        result = build_investigation_intelligence(
            payload,
            rule_context=rule_context,
            prompt_sections=prompt_sections,
            provider_candidate={"planner": {"vuln_type": "idor", "confidence": 0.91}},
        )

        self.assertEqual(result["phase_state"]["phase"], "impact")
        self.assertEqual(result["phase_state"]["max_supported_phase"], "impact")
        self.assertIn(result["evidence_sufficiency"]["status"], {"impact-ready", "report-ready"})
        self.assertGreaterEqual(result["evidence_sufficiency"]["evidence_score"], 2.0)

    def test_xss_state_machine_keeps_confirmation_rails_tight(self):
        payload = SimpleNamespace(
            target_url="https://example.com/comments?id=1",
            response_delta_text="The reflected marker now appears in an attribute context.",
            logger_evidence_text="Status stayed 200 while response length changed by 41 bytes.",
            collaborator_evidence_text="",
            evidence_timeline_entries=["baseline text reflection", "attribute-context reflection"],
            issue_workflow_notes=["Transcript [2026-04-12 11:20:00] You: what is the next exact confirmation step?"],
            bapp_findings_text="",
        )
        prompt_sections = {
            "follow_up_request": "Confirm the exact XSS context before moving to impact.",
            "issue_workflow_notes_summary": "- Prior note: keep the same sink and compare one bounded marker.",
            "investigation_notebook_summary": "Persistent notebook timeline\n- [2026-04-12 11:19:00] AI guidance update: reflected marker moved into attribute context.",
            "scanner_issue_context": "Selected Burp scanner issue: reflected cross-site scripting.",
            "response_delta_summary": "The reflected marker moved into an attribute context with the same endpoint.",
            "tool_results_summary": "",
            "logger_evidence_summary": "Logger++ confirms the response length changed while status remained 200.",
            "collaborator_evidence_summary": "No Collaborator evidence supplied.",
            "evidence_timeline_summary": "- baseline text reflection\n- attribute-context reflection",
            "bapp_findings_summary": "No BApp findings supplied.",
        }
        rule_context = {
            "matched_recipes": [{"title": "Reflected XSS Review", "vuln_class": "xss"}],
            "features": {"observations": ["Response status: 200", "Reflection moved into an attribute context."]},
        }

        result = build_investigation_intelligence(
            payload,
            rule_context=rule_context,
            prompt_sections=prompt_sections,
            provider_candidate={"planner": {"vuln_type": "xss", "confidence": 0.83}},
        )

        state_machine = result["vulnerability_state_machine"]
        self.assertEqual(state_machine["vuln_class"], "xss")
        self.assertEqual(state_machine["current_state"], "impact")
        self.assertIn("Document the highest-value viewer workflow.", state_machine["allowed_moves"])
        self.assertIn("General exploit chains.", state_machine["blocked_moves"])

    def test_counter_hypothesis_requires_role_separated_artifact_when_authz_is_weak(self):
        payload = SimpleNamespace(
            target_url="https://example.com/api/invoices/104",
            response_delta_text="",
            logger_evidence_text="",
            collaborator_evidence_text="",
            evidence_timeline_entries=[],
            issue_workflow_notes=["Transcript [2026-04-12 11:35:00] You: can I claim cross-tenant impact now?"],
            bapp_findings_text="",
        )
        prompt_sections = {
            "follow_up_request": "Assess whether this is enough to call it IDOR impact.",
            "issue_workflow_notes_summary": "- Prior note: same invoice route, but no role-separated artifact yet.",
            "investigation_notebook_summary": "Persistent notebook timeline\n- [2026-04-12 11:34:00] AI guidance update: suspected object-boundary issue, still no unauthorized object diff.",
            "scanner_issue_context": "Selected Burp scanner issue: insecure direct object reference suspicion.",
            "response_delta_summary": "No explicit response delta supplied.",
            "tool_results_summary": "",
            "logger_evidence_summary": "No Logger++ evidence supplied.",
            "collaborator_evidence_summary": "No Collaborator evidence supplied.",
            "evidence_timeline_summary": "No evidence timeline supplied.",
            "bapp_findings_summary": "No BApp findings supplied.",
        }
        rule_context = {
            "matched_recipes": [{"title": "IDOR Review", "vuln_class": "idor"}],
            "features": {"observations": ["Path: /api/invoices/104"]},
        }

        result = build_investigation_intelligence(
            payload,
            rule_context=rule_context,
            prompt_sections=prompt_sections,
            provider_candidate={"planner": {"vuln_type": "access-control", "confidence": 0.79}},
        )

        counter_hypothesis = result["counter_hypothesis"]
        self.assertEqual(counter_hypothesis["lead_hypothesis"], "authorization")
        self.assertEqual(counter_hypothesis["status"], "not-rejected")
        self.assertIn("role-scoped", counter_hypothesis["alternative_explanation"])
        self.assertTrue(counter_hypothesis["missing_rejection_evidence"])

    def test_confidence_calibration_uses_local_history_outcomes(self):
        payload = SimpleNamespace(
            target_url="https://example.com/api/invoices/104",
            selected_profile="bug-bounty-safe",
            response_delta_text="403->200 with invoice fields visible.",
            logger_evidence_text="Stable role-separated diff.",
            collaborator_evidence_text="",
            evidence_timeline_entries=[],
            issue_workflow_notes=[],
            bapp_findings_text="",
        )
        prompt_sections = {
            "follow_up_request": "Rank the next best confirmation step.",
            "issue_workflow_notes_summary": "",
            "investigation_notebook_summary": "Persistent notebook timeline",
            "scanner_issue_context": "Selected Burp scanner issue: insecure direct object reference.",
            "response_delta_summary": "403->200 with invoice fields visible to another account.",
            "tool_results_summary": "",
            "logger_evidence_summary": "Stable role-separated diff.",
            "collaborator_evidence_summary": "No Collaborator evidence supplied.",
            "evidence_timeline_summary": "No evidence timeline supplied.",
            "bapp_findings_summary": "No BApp findings supplied.",
        }
        rule_context = {
            "matched_recipes": [{"title": "IDOR Review", "vuln_class": "idor"}],
            "features": {"observations": ["Path: /api/invoices/104"]},
            "aggregate": {"impact_paths": ["unauthorized cross-tenant invoice access", "admin export visibility"]},
        }

        with (
            patch("server.core.investigation_intelligence_service.query_review_examples", return_value={
                "count": 2,
                "items": [
                    {"outcome_label": "confirmed-reportable"},
                    {"outcome_label": "confirmed-bounded"},
                ],
                "summary": "Matched prior confirmed examples.",
            }),
            patch("server.core.investigation_intelligence_service.summarize_negative_reasoning", return_value={
                "count": 1,
                "deprioritized_families": ["header-routing"],
            }),
            patch("server.core.investigation_intelligence_service.summarize_repeater_learning", return_value={
                "preferred_families": ["authorization-boundary"],
                "deprioritized_families": ["header-routing"],
                "success_rates": {"authorization-boundary": 0.8, "header-routing": 0.1},
            }),
        ):
            result = build_investigation_intelligence(
                payload,
                rule_context=rule_context,
                prompt_sections=prompt_sections,
                provider_candidate={"planner": {"vuln_type": "idor", "confidence": 0.61}},
            )

        calibration = result["confidence_calibration"]
        self.assertEqual(calibration["status"], "boosted")
        self.assertGreater(calibration["calibrated_confidence"], calibration["base_confidence"])
        self.assertIn("authorization-boundary", calibration["preferred_mutation_families"])
        self.assertIn("header-routing", calibration["deprioritized_mutation_families"])

    def test_cross_issue_cluster_merges_related_scanner_issues_on_same_path_family(self):
        payload = SimpleNamespace(
            target_url="https://example.com/api/invoices/104?id=104",
            response_delta_text="403->200 with invoice fields visible.",
            logger_evidence_text="",
            collaborator_evidence_text="",
            evidence_timeline_entries=[],
            issue_workflow_notes=[],
            bapp_findings_text="",
            burp_dashboard_issue={
                "name": "Insecure direct object reference",
                "severity": "high",
                "confidence": "firm",
                "url": "https://example.com/api/invoices/104?id=104",
                "detail": "Invoice object becomes visible across accounts.",
            },
            burp_related_scanner_issues=[
                {
                    "name": "Sensitive data exposure",
                    "severity": "medium",
                    "confidence": "firm",
                    "url": "https://example.com/api/invoices/105?id=105",
                    "detail": "Invoice response includes additional billing fields.",
                },
                {
                    "name": "Stored cross-site scripting",
                    "severity": "medium",
                    "confidence": "firm",
                    "url": "https://example.com/comments?id=104",
                    "detail": "Separate sibling issue on comments.",
                },
            ],
        )
        prompt_sections = {
            "follow_up_request": "Keep following the same invoice case.",
            "issue_workflow_notes_summary": "",
            "investigation_notebook_summary": "Persistent notebook timeline",
            "scanner_issue_context": "Selected Burp scanner issue: insecure direct object reference.",
            "response_delta_summary": "403->200 with invoice fields visible to another account.",
            "tool_results_summary": "",
            "logger_evidence_summary": "No Logger++ evidence supplied.",
            "collaborator_evidence_summary": "No Collaborator evidence supplied.",
            "evidence_timeline_summary": "No evidence timeline supplied.",
            "bapp_findings_summary": "No BApp findings supplied.",
        }
        rule_context = {
            "matched_recipes": [{"title": "IDOR Review", "vuln_class": "idor"}],
            "features": {"observations": ["Path: /api/invoices/104"]},
            "aggregate": {"impact_paths": ["unauthorized cross-tenant invoice access"]},
        }

        result = build_investigation_intelligence(
            payload,
            rule_context=rule_context,
            prompt_sections=prompt_sections,
            provider_candidate={"planner": {"vuln_type": "idor", "confidence": 0.74}},
        )

        cluster = result["cross_issue_cluster"]
        self.assertEqual(cluster["status"], "clustered")
        self.assertGreaterEqual(cluster["issue_count"], 2)
        self.assertIn("authorization", cluster["merged_vuln_classes"])
        self.assertIn("/api/invoices/{id}", cluster["shared_path_family"])
        self.assertTrue(cluster["supporting_issue_names"])
        self.assertTrue(cluster["joined_impact_hints"])

    def test_response_diff_semantics_classifies_auth_boundary_and_data_exposure(self):
        payload = SimpleNamespace(
            target_url="https://example.com/api/invoices/104",
            response_delta_text="403->200 and invoice fields visible to another account.",
            logger_evidence_text="Response length changed by 120 bytes.",
            collaborator_evidence_text="",
            evidence_timeline_entries=[],
            issue_workflow_notes=[],
            bapp_findings_text="",
        )
        prompt_sections = {
            "follow_up_request": "Explain what changed in the response.",
            "issue_workflow_notes_summary": "",
            "investigation_notebook_summary": "Persistent notebook timeline",
            "scanner_issue_context": "Selected Burp scanner issue: insecure direct object reference.",
            "response_delta_summary": "403->200 and invoice fields visible to another account.",
            "tool_results_summary": "",
            "logger_evidence_summary": "Response length changed by 120 bytes.",
            "collaborator_evidence_summary": "No Collaborator evidence supplied.",
            "evidence_timeline_summary": "No evidence timeline supplied.",
            "bapp_findings_summary": "No BApp findings supplied.",
        }
        rule_context = {
            "matched_recipes": [{"title": "IDOR Review", "vuln_class": "idor"}],
            "features": {"observations": ["Path: /api/invoices/104"]},
            "aggregate": {"impact_paths": ["unauthorized cross-tenant invoice access"]},
        }

        result = build_investigation_intelligence(
            payload,
            rule_context=rule_context,
            prompt_sections=prompt_sections,
            provider_candidate={"planner": {"vuln_type": "access-control", "confidence": 0.79}},
        )

        semantics = result["response_diff_semantics"]
        self.assertEqual(semantics["primary_semantic"], "auth-boundary")
        self.assertIn("data-exposure", semantics["semantics"])
        self.assertIn("403->200", semantics["status_transitions"])

    def test_response_diff_semantics_classifies_backend_fetch(self):
        payload = SimpleNamespace(
            target_url="https://example.com/fetch?url=http://callback.example",
            response_delta_text="Backend fetch observed with stable callback.",
            logger_evidence_text="Collaborator callback confirmed for the same request family.",
            collaborator_evidence_text="",
            evidence_timeline_entries=[],
            issue_workflow_notes=[],
            bapp_findings_text="",
        )
        prompt_sections = {
            "follow_up_request": "Explain the fetch delta.",
            "issue_workflow_notes_summary": "",
            "investigation_notebook_summary": "Persistent notebook timeline",
            "scanner_issue_context": "Selected Burp scanner issue: server-side request forgery.",
            "response_delta_summary": "Backend fetch observed with stable callback.",
            "tool_results_summary": "",
            "logger_evidence_summary": "Collaborator callback confirmed for the same request family.",
            "collaborator_evidence_summary": "No Collaborator evidence supplied.",
            "evidence_timeline_summary": "No evidence timeline supplied.",
            "bapp_findings_summary": "No BApp findings supplied.",
        }
        rule_context = {
            "matched_recipes": [{"title": "SSRF Review", "vuln_class": "ssrf"}],
            "features": {"observations": ["Path: /fetch"]},
            "aggregate": {"impact_paths": ["Prove backend fetch to an approved benign callback."]},
        }

        result = build_investigation_intelligence(
            payload,
            rule_context=rule_context,
            prompt_sections=prompt_sections,
            provider_candidate={"planner": {"vuln_type": "ssrf", "confidence": 0.72}},
        )

        semantics = result["response_diff_semantics"]
        self.assertEqual(semantics["primary_semantic"], "backend-fetch")
        self.assertIn("backend-fetch", semantics["evidence_markers"])

    def test_impact_path_ranking_gates_high_risk_paths_without_policy_allowance(self):
        payload = SimpleNamespace(
            target_url="https://example.com/fetch?url=http://internal.example",
            program_policy_text="Standard bug bounty rules. No explicit SSRF high-risk allowance.",
            program_platform="bugcrowd",
            response_delta_text="Backend fetch observed with stable callback.",
            logger_evidence_text="",
            collaborator_evidence_text="",
            evidence_timeline_entries=[],
            issue_workflow_notes=[],
            bapp_findings_text="",
        )
        prompt_sections = {
            "follow_up_request": "Rank the best impact path.",
            "issue_workflow_notes_summary": "",
            "investigation_notebook_summary": "Persistent notebook timeline",
            "scanner_issue_context": "Selected Burp scanner issue: server-side request forgery.",
            "response_delta_summary": "Backend fetch observed with stable callback.",
            "tool_results_summary": "",
            "logger_evidence_summary": "No Logger++ evidence supplied.",
            "collaborator_evidence_summary": "No Collaborator evidence supplied.",
            "evidence_timeline_summary": "No evidence timeline supplied.",
            "bapp_findings_summary": "No BApp findings supplied.",
        }
        rule_context = {
            "matched_recipes": [{"title": "SSRF Review", "vuln_class": "ssrf"}],
            "features": {"observations": ["Path: /fetch"]},
            "aggregate": {
                "impact_paths": [
                    "Prove backend fetch to an approved benign callback.",
                    "Try internal metadata or internal service reachability.",
                ]
            },
        }

        result = build_investigation_intelligence(
            payload,
            rule_context=rule_context,
            prompt_sections=prompt_sections,
            provider_candidate={"planner": {"vuln_type": "ssrf", "confidence": 0.72}},
        )

        ranking = result["impact_path_ranking"]
        self.assertEqual(ranking["top_path"], "Prove backend fetch to an approved benign callback.")
        self.assertNotIn("Prove backend fetch to an approved benign callback.", ranking["gated_paths"])
        self.assertIn("Try internal metadata or internal service reachability.", ranking["gated_paths"])

    def test_selected_scanner_issue_anchor_overrides_generic_route_heuristics_for_xss_followups(self):
        payload = SimpleNamespace(
            target_url="https://example.com/Comments.aspx?id=2",
            response_delta_text="Stored marker now renders in an attribute context on the same comments page.",
            logger_evidence_text="Response length changed by 41 bytes while the comment still renders.",
            collaborator_evidence_text="",
            evidence_timeline_entries=["baseline stored comment", "attribute-context render"],
            issue_workflow_notes=["Transcript [2026-04-12 12:10:00] You: tell me the next impact-oriented XSS step."],
            bapp_findings_text="Selected Burp issue is stored cross-site scripting on tbComment.",
            burp_dashboard_issue={
                "name": "Cross-site scripting (stored)",
                "severity": "high",
                "confidence": "certain",
                "url": "https://example.com/Comments.aspx?id=2",
                "detail": "The tbComment parameter is copied into the HTML document as plain text between tags.",
            },
            burp_related_scanner_issues=[
                {
                    "name": "SQL injection",
                    "severity": "high",
                    "confidence": "firm",
                    "url": "https://example.com/Comments.aspx?id=2",
                    "detail": "Sibling finding on the same path that should not replace the selected XSS anchor.",
                },
                {
                    "name": "Input returned in response (stored)",
                    "severity": "info",
                    "confidence": "certain",
                    "url": "https://example.com/Comments.aspx?id=2",
                    "detail": "The same stored comment value is visible in the response body.",
                },
            ],
        )
        prompt_sections = {
            "follow_up_request": "Tell me the next impact-oriented XSS step for this Burp-marked issue.",
            "issue_workflow_notes_summary": "- Prior note: keep the same sink and move toward the viewer workflow.",
            "investigation_notebook_summary": "Persistent notebook timeline\n- [2026-04-12 12:09:00] AI guidance update: storage is confirmed and the sink moved into an attribute context.",
            "scanner_issue_context": "Selected Burp Scanner issue anchor: Cross-site scripting (stored). Keep the case anchored to this exact request family first: https://example.com/Comments.aspx?id=2.",
            "response_delta_summary": "Stored marker now renders in an attribute context on the same comments page.",
            "tool_results_summary": "",
            "logger_evidence_summary": "Response length changed by 41 bytes while the comment still renders.",
            "collaborator_evidence_summary": "No Collaborator evidence supplied.",
            "evidence_timeline_summary": "- baseline stored comment\n- attribute-context render",
            "bapp_findings_summary": "Selected Burp issue is stored cross-site scripting on tbComment.",
        }
        rule_context = {
            "matched_recipes": [{"title": "SQL Injection Review", "vuln_class": "sqli"}],
            "features": {"observations": ["Path: /Comments.aspx", "Stored content now renders in an attribute context."]},
            "aggregate": {"impact_paths": ["[sqli] Try to prove backend query influence or protected data exposure."]},
        }

        result = build_investigation_intelligence(
            payload,
            rule_context=rule_context,
            prompt_sections=prompt_sections,
            provider_candidate={"planner": {"vuln_type": "sqli", "confidence": 0.91}},
        )

        self.assertEqual("xss", result["vulnerability_state_machine"]["vuln_class"])
        self.assertIn(result["cross_issue_cluster"]["status"], {"clustered", "related"})
        self.assertIn("xss", result["cross_issue_cluster"]["merged_vuln_classes"])
        self.assertNotIn("injection", result["cross_issue_cluster"]["merged_vuln_classes"])
        self.assertNotIn("query influence", result["impact_path_ranking"]["top_path"].lower())
        self.assertTrue(
            any(token in result["impact_path_ranking"]["top_path"].lower() for token in ("viewer", "render", "cross-user", "admin")),
            result["impact_path_ranking"]["top_path"],
        )

    def test_report_bundle_is_tuned_for_burp_originated_idor_case(self):
        payload = SimpleNamespace(
            target_url="https://example.com/api/invoices/104?id=104",
            source_tool="scanner",
            use_burp_mcp_context=True,
            response_delta_text="403->200 with invoice fields visible to another account.",
            logger_evidence_text="Stable role-separated diff on the same invoice route.",
            collaborator_evidence_text="",
            evidence_timeline_entries=["baseline 403", "variant 200 with invoice fields"],
            issue_workflow_notes=["Transcript [2026-04-12 12:30:00] You: package the strongest reportable impact path."],
            bapp_findings_text="",
            burp_dashboard_issue={
                "name": "Insecure direct object reference",
                "severity": "high",
                "confidence": "firm",
                "url": "https://example.com/api/invoices/104?id=104",
                "detail": "Invoice object becomes visible across accounts.",
            },
            burp_related_scanner_issues=[
                {
                    "name": "Sensitive data exposure",
                    "severity": "medium",
                    "confidence": "firm",
                    "url": "https://example.com/api/invoices/104/export?id=104",
                    "detail": "Export response includes additional billing fields.",
                },
            ],
        )
        prompt_sections = {
            "follow_up_request": "Give me the strongest bounded impact path and the exact proof bundle still missing.",
            "issue_workflow_notes_summary": "- Prior note: role-separated invoice access is stable.",
            "investigation_notebook_summary": "Persistent notebook timeline\n- [2026-04-12 12:29:00] AI guidance update: role-separated invoice access is stable.",
            "scanner_issue_context": "Selected Burp scanner issue: insecure direct object reference.",
            "response_delta_summary": "403->200 with invoice fields visible to another account.",
            "tool_results_summary": "",
            "logger_evidence_summary": "Stable role-separated diff on the same invoice route.",
            "collaborator_evidence_summary": "No Collaborator evidence supplied.",
            "evidence_timeline_summary": "- baseline 403\n- variant 200 with invoice fields",
            "bapp_findings_summary": "No BApp findings supplied.",
        }
        rule_context = {
            "matched_recipes": [{"title": "IDOR Review", "vuln_class": "idor"}],
            "features": {"observations": ["Path: /api/invoices/104", "Response status: 200"]},
            "aggregate": {"impact_paths": ["unauthorized cross-tenant invoice access"]},
        }

        result = build_investigation_intelligence(
            payload,
            rule_context=rule_context,
            prompt_sections=prompt_sections,
            provider_candidate={"planner": {"vuln_type": "idor", "confidence": 0.88}},
        )

        bundle = result["report_bundle"]
        self.assertEqual(bundle["status"], "active")
        self.assertIn("Insecure direct object reference", bundle["title"])
        self.assertIn(bundle["phase"], {"impact", "reporting"})
        self.assertIn("invoice", bundle["top_path"].lower())
        self.assertTrue(bundle["proof_bundle"])
        self.assertTrue(bundle["burp_workflow"])
        self.assertTrue(bundle["related_case_support"])


if __name__ == "__main__":
    unittest.main()
