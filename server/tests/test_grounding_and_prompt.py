import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.core import reference_enrichment_service
from server.providers import advisory_flow_service
from server.providers import deterministic_guidance_service, prompt_builder_service


class GroundingAndPromptTests(unittest.TestCase):
    def test_curated_references_include_portswigger_and_github(self):
        links = reference_enrichment_service.curated_references_for_class("idor")
        self.assertTrue(any("portswigger.net" in link for link in links))
        self.assertTrue(any("github.com/PortSwigger/BChecks" in link for link in links))

    def test_local_resource_hints_include_reference_grounding(self):
        with (
            patch.object(deterministic_guidance_service, "search_notes_detailed", return_value={"hits": [{"title": "IDOR note"}]}),
            patch.object(deterministic_guidance_service, "query_bchecks", return_value=[{"name": "IDOR helper check"}]),
        ):
            hints = deterministic_guidance_service.build_local_resource_hints([
                {"vuln_class": "idor", "title": "Identifier access review"},
            ])

        self.assertEqual(len(hints), 1)
        self.assertIn("PortSwigger:", hints[0])
        self.assertIn("GitHub:", hints[0])

    def test_prompt_builder_includes_reference_links_and_mcp_grounding_instruction(self):
        prompt = prompt_builder_service.build_analysis_prompt({
            "target_url": "https://example.com/account",
            "http_method": "GET",
            "source_tool": "scanner",
            "use_burp_mcp_context": True,
            "annotations_text": "<none>",
            "profile_name": "mcp-grounded-llama32",
            "allowed_classes_text": "access-control",
            "suppressed_classes_text": "<none>",
            "privacy_mode": "STRICT",
            "complexity_level": "low",
            "complexity_eta": "15 to 45 seconds",
            "complexity_recommendation": "single pass",
            "operator_answers_text": "",
            "tool_help_summary": "",
            "inventory_summary": "",
            "loaded_burp_tools_summary": "",
            "program_context": "",
            "tool_results_summary": "",
            "burp_config_summary": "",
            "burp_screenshot_summary": "",
            "program_screenshot_summary": "",
            "vision_summary": "",
            "bapp_findings_summary": "",
            "logger_evidence_summary": "",
            "collaborator_evidence_summary": "",
            "evidence_timeline_summary": "",
            "follow_up_request": "",
            "follow_up_instruction_block": "",
            "scanner_issue_context": "",
            "burp_origin_context": "",
            "scanner_marked_case_summary": "Scanner-marked case mode is active.",
            "report_bundle_summary": "Title: Example finding\nPhase: impact\nReportability: impact-ready",
            "response_delta_summary": "",
            "observations_text": "",
            "fingerprint": {},
            "recipe_block": "",
            "rule_baseline": {},
            "memory_block": "",
            "kb_context": "",
            "kb_hits": [],
            "reference_links": ["https://portswigger.net/web-security/access-control/idor"],
            "local_resource_hints": ["[idor] Local resources to refine the next confirmation ladder"],
            "raw_request_summary": "GET /account?id=1 HTTP/1.1",
            "raw_response_summary": "HTTP/1.1 403 Forbidden",
        })

        self.assertIn("Use Burp MCP context: True", prompt)
        self.assertIn("Curated reference links from deterministic guidance", prompt)
        self.assertIn("treat Burp Scanner issue context", prompt)
        self.assertIn("Scanner-marked case bundle", prompt)
        self.assertIn("Live report bundle", prompt)
        self.assertIn("selected Burp issue looks likely real or likely false positive", prompt)
        self.assertIn("Do not escalate into exploit instructions", prompt)
        self.assertIn("Burp-originated requests, keep the answer anchored", prompt)
        self.assertIn("On later follow-up turns, do not reset to generic confirmation advice", prompt)
        self.assertIn("starter assets, local KB hits, guidance packs, and review examples before suggesting broader expansion.", prompt)

    def test_scanner_marked_case_bundle_prefers_burp_first_confirmation_and_impact(self):
        payload = type("Payload", (), {
            "target_url": "https://example.com/comments?id=1",
            "burp_dashboard_issue": {
                "name": "Reflected XSS",
                "severity": "medium",
                "confidence": "firm",
                "detail": "User supplied input is reflected in the response.",
            },
        })()
        rule_context = {
            "matched_recipes": [{"vuln_class": "xss", "title": "Reflected XSS review"}],
            "aggregate": {"primary_next_action": "Keep the same sink and compare one benign marker."},
        }
        intelligence = {
            "vulnerability_state_machine": {"vuln_class": "xss"},
            "impact_path_ranking": {"top_path": "Prove the same sink reaches a shared or privileged viewer path."},
        }

        with (
            patch.object(advisory_flow_service, "get_dashboard_issue_context", return_value={
                "found": True,
                "issue_name": "Reflected XSS",
                "severity": "medium",
                "confidence": "firm",
                "vuln_hint": "xss",
                "evidence_items": ["reflection point"],
            }),
            patch("server.core.repeater_guidance_service.build_repeater_escalation_plan", return_value={
                "repeater_mutation_plan": [{
                    "instruction": "Replace the reflected value with one benign render marker.",
                    "expected_signal": "The marker reaches the same reflected sink.",
                }],
                "issue_chain_strategy": ["Only after the sink is stable, test whether the same value reaches a shared viewer."],
            }),
            patch("server.core.burp_capability_service.recommend_burp_capabilities", return_value={
                "recommendations": [{
                    "tool": "Repeater",
                    "manual_step": "Keep one baseline tab and compare one bounded marker change.",
                }],
                "starter_assets": {
                    "custom_scan_checks": [{"name": "stored_xss_viewer_path_check"}],
                    "bambda_packs": [{"name": "reflection_marker_pack"}],
                },
            }),
        ):
            bundle = advisory_flow_service._build_scanner_marked_case_bundle(
                payload=payload,
                rule_context=rule_context,
                investigation_intelligence=intelligence,
            )

        self.assertEqual(bundle["status"], "active")
        self.assertEqual(bundle["vuln_class"], "xss")
        self.assertIn("likely real", bundle["confirmation_outlook"])
        self.assertIn("benign render marker", bundle["next_confirmation_instruction"])
        self.assertIn("shared or privileged viewer", bundle["next_impact_path"])
        self.assertEqual(bundle["primary_burp_tool"], "Repeater")
        self.assertIn("reflection_marker_pack", " ".join(bundle["starter_assets"]))

    def test_burp_originated_case_bundle_activates_without_scanner_issue(self):
        payload = type("Payload", (), {
            "target_url": "https://example.com/profile",
            "source_tool": "repeater",
            "use_burp_mcp_context": True,
            "annotations": ["tool_repeater"],
            "burp_dashboard_issue": {},
        })()
        rule_context = {
            "matched_recipes": [{"vuln_class": "authorization", "title": "Access control review"}],
            "aggregate": {"primary_next_action": "Keep the same object boundary and compare one role-separated variant."},
        }
        intelligence = {
            "vulnerability_state_machine": {"vuln_class": "authorization"},
            "impact_path_ranking": {"top_path": "Prioritize unauthorized object fields, adjacent export views, or privileged records on the same object family."},
        }

        with (
            patch.object(advisory_flow_service, "get_dashboard_issue_context", return_value={"found": False}),
            patch("server.core.repeater_guidance_service.build_repeater_escalation_plan", return_value={
                "repeater_mutation_plan": [{
                    "instruction": "Compare one second role-separated object identifier on the same route.",
                    "expected_signal": "The same object boundary shifts without changing the workflow.",
                }],
                "issue_chain_strategy": ["Use the same route family as the anchor case."],
            }),
            patch("server.core.burp_capability_service.recommend_burp_capabilities", return_value={
                "recommendations": [{"tool": "Repeater", "manual_step": "Keep one baseline tab and change one object identifier at a time."}],
                "starter_assets": {},
            }),
        ):
            bundle = advisory_flow_service._build_scanner_marked_case_bundle(
                payload=payload,
                rule_context=rule_context,
                investigation_intelligence=intelligence,
            )

        self.assertEqual(bundle["status"], "active")
        self.assertEqual(bundle["origin_type"], "burp-originated")
        self.assertEqual(bundle["primary_burp_tool"], "Repeater")

    def test_scanner_marked_case_override_reanchors_conflicting_fallback_fields(self):
        bundle = {
            "status": "active",
            "issue_name": "Cross-site scripting (reflected)",
            "vuln_class": "xss",
            "next_confirmation_instruction": "Keep the reflected sink fixed and compare one benign marker.",
            "next_confirmation_signal": "The marker reaches the same reflected sink.",
            "next_impact_path": "Confirm whether the same rendered value reaches a shared or privileged viewer.",
        }
        fallback = {
            "primary_next_action": "SQL Injection Review: keep one untouched baseline GET tab in Burp Repeater.",
            "potential_vulnerabilities": ["[sqli] Try to prove backend query influence."],
        }

        updated = advisory_flow_service._apply_scanner_marked_case_to_fallback(fallback, bundle)
        action, request_plan, potentials = advisory_flow_service._apply_scanner_marked_case_to_result_fields(
            bundle,
            primary_next_action=updated["primary_next_action"],
            request_plan=["Use the existing Burp issue, Collaborator evidence, and latest response."],
            potential_vulnerabilities=updated["potential_vulnerabilities"],
        )

        self.assertIn("reflected sink", updated["primary_next_action"])
        self.assertEqual(["[xss] Cross-site scripting (reflected)"], updated["potential_vulnerabilities"])
        self.assertIn("selected Burp issue as the anchor", request_plan[0])
        self.assertIn("reflected sink", action)
        self.assertEqual(["[xss] Cross-site scripting (reflected)"], potentials)


if __name__ == "__main__":
    unittest.main()
