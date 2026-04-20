from server.core.action_labels import label_actions
from server.core.analysis_service import analyze_exchange, build_analysis_run, coerce_payload
from server.core.burp_context_service import get_dashboard_issue_context, summarize_burp_context
from server.core.escalation_service import build_escalation_guidance
from server.core.impact_upgrade_service import (
    build_finding_to_impact_template,
    build_impact_upgrade_planner,
    build_program_specific_impact_wording,
    build_reportability_gate,
)
from server.core.next_try_service import build_next_try_matrix, build_reporting_impact_notes


def rank_impact_paths(payload_like, advisory: dict | None = None, run: dict | None = None) -> dict:
    payload = coerce_payload(payload_like)
    if advisory is None:
        analysis_bundle = analyze_exchange(payload)
        advisory = analysis_bundle["advisory"]
        run = analysis_bundle["run"]
    else:
        analysis_bundle = None
        if run is None or not isinstance(run, dict):
            run = build_analysis_run(payload, advisory).to_dict()

    hypotheses = [item for item in (run.get("hypotheses") or []) if isinstance(item, dict)]
    impact_paths = advisory.get("impact_paths", []) or []
    questions = advisory.get("questions_for_user", []) or []
    confirmation = advisory.get("confirmation_playbooks", []) or []
    potential_vulnerabilities = advisory.get("potential_vulnerabilities", []) or []
    evidence = [item for item in (run.get("evidence") or []) if isinstance(item, dict)]
    evidence_score = round(sum(_evidence_weight(item.get("evidence_type") or "") for item in evidence), 2)
    dashboard_issue = get_dashboard_issue_context(payload)
    burp_context_summary = summarize_burp_context(payload)

    recommended_path = impact_paths[0] if impact_paths else advisory.get("primary_next_action", "")
    normalized_hypotheses = [item for item in hypotheses if isinstance(item, dict)]
    confirmed_count = sum(1 for item in normalized_hypotheses if (item.get("status") or "").strip().lower() == "confirmed")
    selected = _select_primary_hypothesis(normalized_hypotheses, dashboard_issue)
    selected_confirmed = (selected.get("status") or "").strip().lower() == "confirmed"
    business_impact_class = _classify_business_impact(impact_paths, selected, dashboard_issue)

    reportable = selected_confirmed and evidence_score >= 2.5 and bool(impact_paths or len(evidence) >= 2 or dashboard_issue.get("found"))
    reportability = "low"
    if reportable:
        reportability = "high"
    elif dashboard_issue.get("found") or impact_paths or len(potential_vulnerabilities) >= 2 or confirmed_count > 0:
        reportability = "medium"

    escalation = build_escalation_guidance(
        payload,
        advisory=advisory,
        selected=selected,
        dashboard_issue=dashboard_issue,
        confirmed_count=confirmed_count,
    )
    policy_gate = escalation.get("policy_gate") or {}
    safest_next_proof = escalation.get("baseline_confirmation", "")
    effective_safest_next_proof = safest_next_proof
    business_impact_expansion_paths = list(escalation.get("business_impact_expansion_paths") or [])[:6]
    effective_business_impact_expansion_paths = list(business_impact_expansion_paths)
    if policy_gate.get("applies") and not policy_gate.get("allowed", True):
        safest_next_proof = "Capture one clean baseline confirmation only until the saved program policy explicitly allows higher-risk escalation."
        business_impact_expansion_paths = []
    safe_steps = list(escalation.get("safe_vapt_escalation_steps") or [])
    action_items = label_actions(
        [effective_safest_next_proof, *safe_steps[:4], *questions[:2], *confirmation[:2]],
        fallback_used=bool(advisory.get("fallback_used")),
    )
    vuln_class = (selected.get("vuln_class") or dashboard_issue.get("vuln_hint") or "general").strip().lower()
    next_try_matrix = build_next_try_matrix(
        vuln_class=vuln_class,
        title=selected.get("summary", "") or dashboard_issue.get("issue_name", vuln_class),
        primary_next_action=advisory.get("primary_next_action", ""),
        request_plan=advisory.get("request_plan", []),
        payload_recommendations=advisory.get("payload_recommendations", []),
        impact_paths=impact_paths,
        escalation_profile=escalation.get("escalation_profile", ""),
        required_evidence_for_upgrade=escalation.get("required_evidence_for_upgrade", []),
        business_impact_expansion_paths=escalation.get("business_impact_expansion_paths", []),
    )
    impact_upgrade_planner = build_impact_upgrade_planner(
        vuln_class,
        validation={
            "validation_status": "confirmed" if selected_confirmed else "needs-confirmation",
            "hypothesis": selected,
            "evidence_score": evidence_score,
        },
        impact={
            "reportable": reportable,
            "reportability": reportability,
            "business_impact_class": business_impact_class,
            "business_impact_expansion_paths": escalation.get("business_impact_expansion_paths", []),
            "required_evidence_for_upgrade": escalation.get("required_evidence_for_upgrade", []),
            "confirmation_state": "confirmed" if selected_confirmed else "needs-confirmation",
        },
        severity={"severity": escalation.get("likely_severity_promotions", ["medium"])[0].split(" ", 1)[0].lower() if escalation.get("likely_severity_promotions") else ""},
    )
    reportability_gate = build_reportability_gate(
        vuln_class,
        validation={
            "validation_status": "confirmed" if selected_confirmed else "needs-confirmation",
            "hypothesis": selected,
        },
        impact={
            "reportable": reportable,
            "reportability": reportability,
            "business_impact_expansion_paths": escalation.get("business_impact_expansion_paths", []),
            "required_evidence_for_upgrade": escalation.get("required_evidence_for_upgrade", []),
            "confirmation_state": "confirmed" if selected_confirmed else "needs-confirmation",
        },
    )

    return {
        "target_url": getattr(payload, "target_url", "") or "",
        "recommended_path": recommended_path,
        "ranked_impact_paths": impact_paths[:5],
        "evidence_gaps": questions[:3],
        "confirmation_requirements": confirmation[:3],
        "safest_next_proof": safest_next_proof,
        "effective_safest_next_proof": effective_safest_next_proof,
        "safe_vapt_escalation_steps": safe_steps,
        "labeled_safe_vapt_escalation_steps": label_actions(
            safe_steps,
            fallback_used=bool(advisory.get("fallback_used")),
        )[:8],
        "escalation_profile": escalation.get("escalation_profile", ""),
        "baseline_confirmation": safest_next_proof,
        "business_impact_expansion_paths": business_impact_expansion_paths,
        "effective_business_impact_expansion_paths": effective_business_impact_expansion_paths,
        "required_evidence_for_upgrade": list(escalation.get("required_evidence_for_upgrade") or [])[:6],
        "stop_conditions": list(escalation.get("stop_conditions") or [])[:6],
        "likely_severity_promotions": list(escalation.get("likely_severity_promotions") or [])[:6],
        "business_impact_class": business_impact_class,
        "confirmation_state": "confirmed" if selected_confirmed else "needs-confirmation",
        "reportable": reportable,
        "reportability": reportability,
        "hypothesis_count": len(hypotheses),
        "evidence_score": evidence_score,
        "evidence_count": len(evidence),
        "dashboard_issue": dashboard_issue,
        "burp_context_summary": burp_context_summary,
        "action_items": action_items[:8],
        "next_try_matrix": next_try_matrix,
        "reporting_impact_notes": build_reporting_impact_notes(
            vuln_class=vuln_class,
            required_evidence_for_upgrade=escalation.get("required_evidence_for_upgrade", []),
            business_impact_expansion_paths=escalation.get("business_impact_expansion_paths", []),
        ),
        "impact_upgrade_planner": impact_upgrade_planner,
        "finding_to_impact_template": build_finding_to_impact_template(vuln_class),
        "reportability_gate": reportability_gate,
        "program_specific_impact_wording": build_program_specific_impact_wording("", vuln_class, {"business_impact_class": business_impact_class}),
        "analysis_backend": advisory.get("analysis_backend", ""),
        "fallback_used": bool(advisory.get("fallback_used")),
        "escalation_ladder": list(escalation.get("escalation_ladder") or advisory.get("escalation_ladder") or [])[:8],
        "reference_links": list(advisory.get("source_links") or [])[:10],
        "internet_reference_candidates": list(advisory.get("internet_reference_candidates") or [])[:6],
        "internet_reference_policy": advisory.get("internet_reference_policy", ""),
        "policy_gate": policy_gate,
        "advisory": advisory if analysis_bundle is not None else None,
    }


def _select_primary_hypothesis(hypotheses: list[dict], dashboard_issue: dict) -> dict:
    if hypotheses:
        return sorted(
            hypotheses,
            key=lambda item: (
                (item.get("status") or "").strip().lower() == "confirmed",
                float(item.get("confidence", 0.0) or 0.0),
            ),
            reverse=True,
        )[0]
    return {
        "vuln_class": dashboard_issue.get("vuln_hint") or "general",
        "summary": dashboard_issue.get("issue_name") or "scanner finding",
        "status": "suspected",
        "confidence": 0.0,
    }


def _evidence_weight(evidence_type: str) -> float:
    weights = {
        "role-compare": 1.7,
        "manual-diff": 1.35,
        "callback": 1.35,
        "scanner": 0.9,
        "traffic-history": 0.8,
        "timeline": 0.7,
        "whitebox": 0.7,
        "knowledge-base": 0.45,
        "config": 0.35,
        "derived": 0.25,
        "operator-note": 0.5,
    }
    return weights.get((evidence_type or "").strip().lower(), 0.25)


def _classify_business_impact(impact_paths: list[str], selected: dict, dashboard_issue: dict) -> str:
    normalized = " ".join(impact_paths).lower()
    vuln_class = (selected.get("vuln_class") or dashboard_issue.get("vuln_hint") or "general").lower()
    severity = (dashboard_issue.get("severity") or "").lower()

    if any(token in normalized for token in ("unauthorized", "cross-tenant", "privilege", "state change", "secret")):
        return "high-impact"
    if vuln_class in {"authorization", "idor", "ssrf", "injection"}:
        return "high-impact" if severity in {"high", "critical"} else "security-impact"
    if vuln_class in {"xss", "csrf"}:
        return "security-impact"
    if impact_paths or dashboard_issue.get("found"):
        return "security-impact"
    return "informational"
