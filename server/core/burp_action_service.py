from server.core.action_labels import label_actions
from server.core.analysis_service import analyze_exchange, coerce_payload
from server.core.best_next_step_service import build_best_next_step_from_matrix, build_one_best_next_step
from server.core.burp_capability_service import recommend_burp_capabilities
from server.core.burp_context_service import (
    get_dashboard_issue_context,
    get_related_dashboard_issue_contexts,
    summarize_burp_context,
)
from server.core.impact_service import rank_impact_paths
from server.core.next_try_service import build_next_try_matrix, build_reporting_impact_notes
from server.core.repeater_guidance_service import build_repeater_escalation_plan
from server.core.recommendation_service import recommend_bchecks_for_exchange
from server.core.runtime_service import evaluate_execution_safety
from server.issue_family_memory import summarize_issue_family_memory


def _safe_expansion_payload(
    repeater_plan: dict,
    *,
    execution_safety: dict,
) -> tuple[list[dict], list[dict], list[str], list[str]]:
    if not execution_safety.get("blocked"):
        return (
            list(repeater_plan.get("repeater_mutation_plan") or [])[:6],
            list(repeater_plan.get("repeater_variant_requests") or [])[:3],
            list(repeater_plan.get("issue_chain_strategy") or [])[:5],
            [],
        )
    blocked_reasons = list(execution_safety.get("blocked_reasons") or [])
    issue_chain = [
        "Expansion is blocked by execution safety budgets. Keep testing in suggest/manual mode only.",
        *[f"Blocked: {reason}" for reason in blocked_reasons[:3]],
    ]
    return [], [], issue_chain[:5], blocked_reasons[:6]


def next_burp_action(payload_like, advisory: dict | None = None) -> dict:
    payload = coerce_payload(payload_like)
    if advisory is None:
        advisory = analyze_exchange(payload)["advisory"]

    checklist = advisory.get("burp_action_checklist", []) or []
    request_plan = advisory.get("request_plan", []) or []
    next_action = advisory.get("primary_next_action", "") or (checklist[0] if checklist else "")
    impact = rank_impact_paths(payload, advisory=advisory)
    dashboard_issue = get_dashboard_issue_context(payload)
    related_scanner_issues = get_related_dashboard_issue_contexts(payload)
    burp_context_summary = summarize_burp_context(payload)
    impact_steps = impact.get("safe_vapt_escalation_steps", []) or []
    policy_gate = impact.get("policy_gate") or advisory.get("policy_gate") or {}
    repeater_plan = build_repeater_escalation_plan(payload, advisory=advisory, impact=impact)
    execution_safety = evaluate_execution_safety(
        payload,
        policy_gate=policy_gate,
        fallback_used=bool(advisory.get("fallback_used")),
    )
    repeater_mutation_plan, repeater_variant_requests, issue_chain_strategy, blocked_expansions = _safe_expansion_payload(
        repeater_plan,
        execution_safety=execution_safety,
    )
    try:
        capability_recommendations = recommend_burp_capabilities(payload, impact=impact)
    except Exception as exc:
        capability_recommendations = {
            "recommendations": [],
            "starter_assets": {},
            "curated_bapp_categories": [],
            "external_tool_recommendations": [],
            "status": "degraded",
            "detail": f"Burp capability inspection failed: {exc}",
        }
    steps = checklist[:6] if checklist else request_plan[:6]
    if impact_steps:
        steps = [*steps, *impact_steps[:3]]
    if repeater_mutation_plan:
        steps = [*steps, *(item.get("instruction", "") for item in repeater_mutation_plan[:2])]
    if blocked_expansions:
        steps = [steps[0] if steps else next_action, *[f"Blocked expansion: {item}" for item in blocked_expansions[:2]]]
    labeled_steps = label_actions(
        [next_action, *steps],
        fallback_used=bool(advisory.get("fallback_used")),
    )
    primary_class = (
        (dashboard_issue.get("vuln_hint") or "")
        or ((advisory.get("potential_vulnerabilities") or ["[general]"])[0].split("]", 1)[0].lstrip("["))
        or "general"
    ).strip().lower()
    next_try_matrix = build_next_try_matrix(
        vuln_class=primary_class,
        title=dashboard_issue.get("issue_name", "") or next_action,
        primary_next_action=next_action,
        request_plan=request_plan,
        payload_recommendations=advisory.get("payload_recommendations", []),
        impact_paths=impact.get("ranked_impact_paths", []),
        escalation_profile=impact.get("escalation_profile", ""),
        required_evidence_for_upgrade=impact.get("required_evidence_for_upgrade", []),
        business_impact_expansion_paths=impact.get("business_impact_expansion_paths", []),
    )
    bcheck_selector = recommend_bchecks_for_exchange(payload)
    issue_family_memory = summarize_issue_family_memory(
        payload,
        issue_id=dashboard_issue.get("issue_id", ""),
        vuln_classes=[primary_class],
    )
    one_best_next_step = build_best_next_step_from_matrix(
        next_try_matrix=next_try_matrix,
        fallback_title=next_action,
        fallback_why="This is the strongest bounded next manual step for the current Burp issue family.",
        fallback_expected_signal="A cleaner, reproducible delta tied to the current issue family.",
        fallback_stop_when="One reproducible artifact is captured.",
        source="burp-next-action",
        supporting_references=list(bcheck_selector.get("curated_reference_links") or [])[:6],
    )

    return {
        "target_url": getattr(payload, "target_url", "") or "",
        "primary_next_action": next_action,
        "request_plan": request_plan[:6],
        "burp_action_checklist": checklist[:8],
        "suggested_steps": steps,
        "labeled_steps": labeled_steps[:8],
        "dashboard_issue": dashboard_issue,
        "burp_context_summary": burp_context_summary,
        "safe_vapt_escalation_steps": impact_steps[:6],
        "labeled_safe_vapt_escalation_steps": impact.get("labeled_safe_vapt_escalation_steps", [])[:6],
        "escalation_profile": impact.get("escalation_profile", ""),
        "baseline_confirmation": impact.get("baseline_confirmation", ""),
        "business_impact_expansion_paths": list(impact.get("business_impact_expansion_paths") or [])[:6],
        "required_evidence_for_upgrade": list(impact.get("required_evidence_for_upgrade") or [])[:6],
        "stop_conditions": list(impact.get("stop_conditions") or [])[:6],
        "likely_severity_promotions": list(impact.get("likely_severity_promotions") or [])[:6],
        "scanner_focus": repeater_plan.get("scanner_focus") or {},
        "repeater_mutation_plan": repeater_mutation_plan,
        "repeater_variant_requests": repeater_variant_requests,
        "issue_chain_strategy": issue_chain_strategy,
        "related_scanner_issues": related_scanner_issues[:4],
        "kb_hints": list(repeater_plan.get("kb_hints") or [])[:4],
        "memory_hints": list(repeater_plan.get("memory_hints") or [])[:4],
        "preferred_request_ref": repeater_plan.get("preferred_request_ref", ""),
        "reasoning": advisory.get("analysis", "")[:800],
        "next_try_matrix": next_try_matrix,
        "one_best_next_step": one_best_next_step,
        "reporting_impact_notes": build_reporting_impact_notes(
            vuln_class=primary_class,
            required_evidence_for_upgrade=impact.get("required_evidence_for_upgrade", []),
            business_impact_expansion_paths=impact.get("business_impact_expansion_paths", []),
        ),
        "official_bcheck_selector": bcheck_selector,
        "issue_family_memory": issue_family_memory,
        "burp_capability_recommendations": capability_recommendations.get("recommendations", []),
        "burp_starter_assets": capability_recommendations.get("starter_assets", {}),
        "curated_bapp_categories": capability_recommendations.get("curated_bapp_categories", []),
        "external_tool_recommendations": capability_recommendations.get("external_tool_recommendations", []) if execution_safety.get("safe_to_expand") else [],
        "safe_to_expand": bool(execution_safety.get("safe_to_expand")),
        "analysis_backend": advisory.get("analysis_backend", ""),
        "escalation_ladder": list(advisory.get("escalation_ladder") or [])[:8],
        "reference_links": list(advisory.get("source_links") or [])[:10],
        "internet_reference_candidates": list(advisory.get("internet_reference_candidates") or [])[:6],
        "internet_reference_policy": advisory.get("internet_reference_policy", ""),
        "policy_gate": policy_gate,
        "execution_safety": execution_safety,
        "blocked_expansions": blocked_expansions,
    }


def burp_repeater_plan(payload_like, advisory: dict | None = None) -> dict:
    payload = coerce_payload(payload_like)
    if advisory is None:
        advisory = analyze_exchange(payload)["advisory"]

    impact = rank_impact_paths(payload, advisory=advisory)
    dashboard_issue = get_dashboard_issue_context(payload)
    related_scanner_issues = get_related_dashboard_issue_contexts(payload)
    burp_context_summary = summarize_burp_context(payload)
    policy_gate = impact.get("policy_gate") or advisory.get("policy_gate") or {}
    repeater_plan = build_repeater_escalation_plan(payload, advisory=advisory, impact=impact)
    execution_safety = evaluate_execution_safety(
        payload,
        policy_gate=policy_gate,
        fallback_used=bool(advisory.get("fallback_used")),
    )
    repeater_mutation_plan, repeater_variant_requests, issue_chain_strategy, blocked_expansions = _safe_expansion_payload(
        repeater_plan,
        execution_safety=execution_safety,
    )
    try:
        capability_recommendations = recommend_burp_capabilities(payload, impact=impact)
    except Exception as exc:
        capability_recommendations = {
            "recommendations": [],
            "starter_assets": {},
            "curated_bapp_categories": [],
            "external_tool_recommendations": [],
            "status": "degraded",
            "detail": f"Burp capability inspection failed: {exc}",
        }
    vuln_class = (dashboard_issue.get("vuln_hint") or "general")
    next_try_matrix = build_next_try_matrix(
        vuln_class=vuln_class,
        title=dashboard_issue.get("issue_name", ""),
        primary_next_action=advisory.get("primary_next_action", ""),
        request_plan=advisory.get("request_plan", []),
        payload_recommendations=advisory.get("payload_recommendations", []),
        impact_paths=impact.get("ranked_impact_paths", []),
        escalation_profile=impact.get("escalation_profile", ""),
        required_evidence_for_upgrade=impact.get("required_evidence_for_upgrade", []),
        business_impact_expansion_paths=impact.get("business_impact_expansion_paths", []),
    )
    bcheck_selector = recommend_bchecks_for_exchange(payload)
    issue_family_memory = summarize_issue_family_memory(
        payload,
        issue_id=dashboard_issue.get("issue_id", ""),
        vuln_classes=[vuln_class],
    )
    if bcheck_selector.get("selected_official_bcheck"):
        selected = dict(bcheck_selector["selected_official_bcheck"])
        one_best_next_step = build_one_best_next_step(
            title=f"Import and run {selected.get('name') or selected.get('relative_path')}.",
            source="official-bcheck-selector",
            why=selected.get("why", ""),
            manual_step=f"Import {selected.get('relative_path')} into Burp custom scan checks and run it only on the current issue family.",
            expected_signal=selected.get("usage_hint", ""),
            stop_when="One useful signal is captured, or the check stays noisy on this same issue family.",
            supporting_references=list(bcheck_selector.get("curated_reference_links") or [])[:6],
        )
    else:
        one_best_next_step = build_best_next_step_from_matrix(
            next_try_matrix=next_try_matrix,
            fallback_title=advisory.get("primary_next_action", ""),
            fallback_why="No single high-signal official BCheck is selected yet, so stay with the bounded manual plan.",
            fallback_expected_signal="One cleaner bounded diff on the current issue family.",
            fallback_stop_when="The issue family is narrow enough for one official check or one stronger diff.",
            source="repeater-plan",
            supporting_references=list(bcheck_selector.get("curated_reference_links") or [])[:6],
        )

    return {
        "target_url": getattr(payload, "target_url", "") or "",
        "dashboard_issue": dashboard_issue,
        "related_scanner_issues": related_scanner_issues[:4],
        "burp_context_summary": burp_context_summary,
        "scanner_focus": repeater_plan.get("scanner_focus") or {},
        "repeater_mutation_plan": repeater_mutation_plan,
        "repeater_variant_requests": repeater_variant_requests,
        "issue_chain_strategy": issue_chain_strategy,
        "kb_hints": list(repeater_plan.get("kb_hints") or [])[:4],
        "memory_hints": list(repeater_plan.get("memory_hints") or [])[:4],
        "preferred_request_ref": repeater_plan.get("preferred_request_ref", ""),
        "baseline_confirmation": impact.get("baseline_confirmation", ""),
        "escalation_profile": impact.get("escalation_profile", ""),
        "next_try_matrix": next_try_matrix,
        "one_best_next_step": one_best_next_step,
        "reporting_impact_notes": build_reporting_impact_notes(
            vuln_class=vuln_class,
            required_evidence_for_upgrade=impact.get("required_evidence_for_upgrade", []),
            business_impact_expansion_paths=impact.get("business_impact_expansion_paths", []),
        ),
        "official_bcheck_selector": bcheck_selector,
        "issue_family_memory": issue_family_memory,
        "analysis_backend": advisory.get("analysis_backend", ""),
        "burp_capability_recommendations": capability_recommendations.get("recommendations", []) if execution_safety.get("safe_to_expand") else [],
        "burp_starter_assets": capability_recommendations.get("starter_assets", {}),
        "curated_bapp_categories": capability_recommendations.get("curated_bapp_categories", []),
        "external_tool_recommendations": capability_recommendations.get("external_tool_recommendations", []) if execution_safety.get("safe_to_expand") else [],
        "safe_to_expand": bool(execution_safety.get("safe_to_expand")),
        "policy_gate": policy_gate,
        "execution_safety": execution_safety,
        "blocked_expansions": blocked_expansions,
    }
