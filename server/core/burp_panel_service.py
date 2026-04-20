from __future__ import annotations

from typing import Any

from server.capabilities.burp_companion import build_burp_companion_config
from server.core.analysis_service import coerce_payload
from server.core.best_next_step_service import build_best_next_step_from_matrix
from server.core.burp_action_service import burp_repeater_plan
from server.core.burp_capability_service import recommend_burp_capabilities
from server.core.confidence_service import build_confidence_to_claim_map
from server.core.impact_service import rank_impact_paths
from server.core.issue_workflow_service import best_next_tab, get_or_build_issue_workflow, lookup_issue_workflow
from server.core.recommendation_service import recommend_bchecks_for_exchange
from server.core.repeater_diff_service import score_repeater_diffs
from server.core.severity_service import assess_submission_severity
from server.issue_family_memory import summarize_issue_family_memory
from server.local_guidance_db import query_guidance_packs
from server.memory_partition import partition_from_payload
from server.negative_reasoning_memory import summarize_negative_reasoning
from server.review_dataset import query_review_examples


def build_burp_panel_state(
    payload_like=None,
    *,
    issue_id: str = "",
    snapshot_id: str = "",
    workflow_id: str = "",
    include_plan: bool = True,
    include_companion_actions: bool = True,
) -> dict[str, Any]:
    payload = coerce_payload(payload_like or {})
    has_payload_context = _payload_has_context(payload)
    plan = burp_repeater_plan(payload) if has_payload_context else {}
    resolved_issue_id = (issue_id or (plan.get("dashboard_issue") or {}).get("issue_id") or "").strip()
    resolved_snapshot_id = (snapshot_id or getattr(payload, "snapshot_id", "") or "").strip()
    resolved_workflow_id = (workflow_id or "").strip()

    workflow = lookup_issue_workflow(
        issue_id=resolved_issue_id,
        snapshot_id=resolved_snapshot_id,
        workflow_id=resolved_workflow_id,
    ) or {}
    if not workflow and (plan or has_payload_context):
        workflow = get_or_build_issue_workflow(payload, plan=plan or None)

    next_tab = best_next_tab(payload, plan=plan or None, workflow=workflow or None) if (workflow or plan or has_payload_context) else {}
    companion = build_burp_companion_config() if include_companion_actions else {"actions": [], "notes": []}
    strongest_delta = dict(workflow.get("strongest_delta") or {})
    ranked_items = list(workflow.get("ranked_items") or [])
    dashboard_issue = dict(plan.get("dashboard_issue") or {})
    guidance_hits = query_guidance_packs(
        [
            dashboard_issue.get("vuln_hint", ""),
            dashboard_issue.get("issue_name", ""),
            getattr(payload, "source_tool", "") or "general",
        ],
        partition_key=(workflow.get("memory_partition_key") or partition_from_payload(payload)),
        top_k=3,
    )
    review_dataset = query_review_examples(
        vuln_classes=[dashboard_issue.get("vuln_hint", "")],
        partition_key=(workflow.get("memory_partition_key") or partition_from_payload(payload)),
        limit=3,
    )
    impact = rank_impact_paths(payload) if has_payload_context else {}
    capability_recommendations = recommend_burp_capabilities(payload, impact=impact) if has_payload_context else {}
    official_bcheck_selector = recommend_bchecks_for_exchange(payload) if has_payload_context else {}
    severity = assess_submission_severity(payload, impact=impact) if has_payload_context else {}
    claim_map = build_confidence_to_claim_map(
        dashboard_issue.get("vuln_hint", "") or "general",
        confidence_level=((severity.get("confidence_calibration") or {}).get("level") or "low"),
        validation={},
        impact=impact,
    ) if has_payload_context else {}
    advanced_modules = _build_panel_advanced_modules(payload, plan=plan or {}) if has_payload_context else {
        "requested": False,
        "summary": "Advanced modules are off by default and were not requested.",
    }
    negative_reasoning = summarize_negative_reasoning(
        payload_like=payload,
        vuln_classes=[dashboard_issue.get("vuln_hint", "")],
    )
    issue_family_memory = summarize_issue_family_memory(
        payload,
        issue_id=resolved_issue_id,
        vuln_classes=[dashboard_issue.get("vuln_hint", "")],
    ) if has_payload_context else {}
    one_best_next_step = build_best_next_step_from_matrix(
        next_try_matrix=list((plan or {}).get("next_try_matrix") or []),
        fallback_title=(next_tab.get("request_text") or next_tab.get("tab_name") or "Capture one bounded next proof."),
        fallback_why=(next_tab.get("reason") or "This is the strongest bounded next step for the current workflow."),
        fallback_expected_signal=(next_tab.get("expected_signal") or "One stronger bounded signal on the current issue family."),
        fallback_stop_when="One reproducible artifact is captured or the workflow becomes noisy.",
        source="burp-panel-state",
        supporting_references=list(official_bcheck_selector.get("curated_reference_links") or [])[:6],
    ) if has_payload_context else {}
    notes = _build_notes(workflow, next_tab, companion, guidance_hits, negative_reasoning, issue_family_memory)
    advanced_summary = str(advanced_modules.get("summary") or "").strip()
    if advanced_summary and advanced_modules.get("requested"):
        notes.append("Advanced modules: " + advanced_summary)

    return {
        "target_url": getattr(payload, "target_url", "") or workflow.get("target_url", "") or "",
        "snapshot_id": resolved_snapshot_id or workflow.get("snapshot_id", "") or "",
        "issue_id": resolved_issue_id or workflow.get("issue_id", "") or "",
        "workflow_id": workflow.get("workflow_id", "") or next_tab.get("workflow_id", "") or "",
        "workflow_status": workflow.get("status", "") or "unknown",
        "dashboard_issue": dashboard_issue,
        "workflow": workflow,
        "best_next_tab": next_tab,
        "diff_summary": {
            "count": len(ranked_items),
            "best_item": strongest_delta,
            "summary": _build_diff_summary(ranked_items, strongest_delta),
        },
        "plan": plan if include_plan else {},
        "companion_actions": list(companion.get("actions") or []),
        "guidance_hits": guidance_hits.get("hits", [])[:3],
        "guidance_merge_policy": guidance_hits.get("merge_policy", []),
        "review_dataset_summary": review_dataset.get("summary", ""),
        "burp_capability_recommendations": capability_recommendations.get("recommendations", []),
        "official_bcheck_selector": official_bcheck_selector,
        "issue_family_memory": issue_family_memory,
        "one_best_next_step": one_best_next_step,
        "impact_upgrade_planner": impact.get("impact_upgrade_planner", {}),
        "reportability_gate": impact.get("reportability_gate", {}),
        "submission_value_score": severity.get("submission_value_score", {}),
        "confidence_to_claim_map": claim_map,
        "negative_reasoning_summary": negative_reasoning,
        "advanced_modules": advanced_modules,
        "notes": notes[:6],
    }


def _payload_has_context(payload) -> bool:
    return bool(
        getattr(payload, "raw_request", "")
        or getattr(payload, "target_url", "")
        or getattr(payload, "burp_dashboard_issue", {})
        or getattr(payload, "repeater_variant_observations", [])
    )


def _build_diff_summary(ranked_items: list[dict[str, Any]], strongest_delta: dict[str, Any]) -> str:
    if strongest_delta:
        return (
            f"Strongest scored delta: {strongest_delta.get('tab_name') or '<unknown>'} "
            f"(score {strongest_delta.get('score', 0.0)})."
        )
    if ranked_items:
        return f"{len(ranked_items)} Repeater observation(s) are stored, but none is currently dominant."
    return "No scored Repeater observations are stored for this workflow yet."


def _build_notes(
    workflow: dict[str, Any],
    next_tab: dict[str, Any],
    companion: dict[str, Any],
    guidance_hits: dict[str, Any],
    negative_reasoning: dict[str, Any],
    issue_family_memory: dict[str, Any],
) -> list[str]:
    notes = []
    readiness = dict(workflow.get("report_readiness") or {})
    if readiness:
        missing = list(readiness.get("missing_evidence") or [])
        if missing:
            notes.append("Missing evidence: " + "; ".join(missing[:3]))
    if next_tab.get("tab_name"):
        notes.append(f"Best next tab: {next_tab.get('tab_name')}.")
    hits = list(guidance_hits.get("hits") or [])
    if hits:
        top = hits[0]
        notes.append(
            "Matched pack: "
            + (top.get("name") or "<unknown>")
            + " | "
            + (top.get("influence_reason") or "guidance_db match")
        )
    learning = (workflow.get("mutation_learning_summary") or {}).get("summary", "")
    if learning:
        notes.append("Mutation learning: " + learning)
    negative_summary = (negative_reasoning or {}).get("summary", "")
    if negative_summary:
        notes.append("Negative reasoning: " + negative_summary)
    family_summary = (issue_family_memory or {}).get("summary", "")
    if family_summary:
        notes.append("Issue-family memory: " + family_summary)
    if companion.get("actions"):
        notes.append("Companion actions available: " + ", ".join(action.get("name", "") for action in companion["actions"][:5]))
    return notes[:6]


def _build_panel_advanced_modules(payload, *, plan: dict[str, Any]) -> dict[str, Any]:
    enabled = bool(getattr(payload, "enable_js_endpoint_extraction", False) or getattr(payload, "enable_race_signal_checks", False))
    if not enabled:
        return {
            "requested": False,
            "summary": "Advanced modules are off by default and were not requested.",
        }
    diff = score_repeater_diffs(payload, plan=plan)
    modules = dict(diff.get("advanced_modules") or {})
    if not modules:
        return {
            "requested": True,
            "summary": "Advanced modules were requested, but no bounded module output was produced.",
        }
    return modules
