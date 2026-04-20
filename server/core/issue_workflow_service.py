from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha1
from typing import Any

from server.core.analysis_service import coerce_payload
from server.core.burp_action_service import burp_repeater_plan
from server.issue_family_memory import summarize_issue_family_memory
from server.core.repeater_diff_service import score_repeater_diffs
from server.core.repeater_tab_service import build_repeater_tab_specs
from server.memory_partition import partition_from_payload
from server.negative_reasoning_memory import summarize_negative_reasoning
from server.repeater_learning import learn_from_repeater_diff, mutation_family, summarize_repeater_learning
from server.state.store import append_issue_workflow_state, get_issue_workflow_state


def get_or_build_issue_workflow(payload_like, *, plan: dict[str, Any] | None = None, diff_score: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = coerce_payload(payload_like)
    if plan is None:
        plan = burp_repeater_plan(payload)
    issue = plan.get("dashboard_issue") or {}
    workflow_id = _workflow_id(issue.get("issue_id", ""), getattr(payload, "snapshot_id", "") or "", getattr(payload, "target_url", "") or "")
    existing = get_issue_workflow_state(workflow_id=workflow_id) or {}
    tabs = build_repeater_tab_specs(payload, plan)
    ranked_items = list((diff_score or {}).get("ranked_items") or existing.get("ranked_items") or [])
    strongest_delta = (diff_score or {}).get("best_item") or existing.get("strongest_delta") or {}
    report_readiness = _report_readiness(plan, ranked_items, strongest_delta)
    mutation_learning = summarize_repeater_learning(payload_like=payload, vuln_classes=_workflow_classes(plan))
    negative_reasoning = summarize_negative_reasoning(payload_like=payload, vuln_classes=_workflow_classes(plan))
    issue_family_memory = summarize_issue_family_memory(
        payload,
        issue_id=issue.get("issue_id", ""),
        vuln_classes=_workflow_classes(plan),
    )
    workflow = {
        "workflow_id": workflow_id,
        "issue_id": issue.get("issue_id", ""),
        "issue_name": issue.get("issue_name", ""),
        "snapshot_id": getattr(payload, "snapshot_id", "") or "",
        "request_id": getattr(payload, "request_id", "") or "",
        "target_url": getattr(payload, "target_url", "") or "",
        "memory_partition_key": partition_from_payload(payload),
        "source_tool": getattr(payload, "source_tool", "") or "",
        "analysis_backend": plan.get("analysis_backend", ""),
        "status": _workflow_status(ranked_items, strongest_delta),
        "updated_at": _utc_now(),
        "created_at": existing.get("created_at") or _utc_now(),
        "issue_chain_strategy": list(plan.get("issue_chain_strategy") or existing.get("issue_chain_strategy") or [])[:6],
        "tab_plan": tabs,
        "ranked_items": ranked_items[:8],
        "strongest_delta": strongest_delta,
        "report_readiness": report_readiness,
        "notes": list(getattr(payload, "issue_workflow_notes", []) or existing.get("notes") or [])[:8],
        "missing_evidence": list(report_readiness.get("missing_evidence") or [])[:6],
        "mutation_learning_summary": mutation_learning,
        "negative_reasoning_summary": negative_reasoning,
        "issue_family_memory": issue_family_memory,
    }
    return workflow


def upsert_issue_workflow(payload_like, *, plan: dict[str, Any] | None = None, diff_score: dict[str, Any] | None = None) -> dict[str, Any]:
    workflow = get_or_build_issue_workflow(payload_like, plan=plan, diff_score=diff_score)
    append_issue_workflow_state(workflow)
    return workflow


def lookup_issue_workflow(issue_id: str = "", snapshot_id: str = "", workflow_id: str = "") -> dict[str, Any] | None:
    return get_issue_workflow_state(issue_id=issue_id, snapshot_id=snapshot_id, workflow_id=workflow_id)


def best_next_tab(payload_like, *, plan: dict[str, Any] | None = None, workflow: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = coerce_payload(payload_like)
    if plan is None:
        plan = burp_repeater_plan(payload)
    if workflow is None:
        workflow = lookup_issue_workflow(issue_id=(plan.get("dashboard_issue") or {}).get("issue_id", ""), snapshot_id=getattr(payload, "snapshot_id", "") or "") or {}
    if not workflow and list(getattr(payload, "repeater_variant_observations", []) or []):
        workflow = get_or_build_issue_workflow(payload, plan=plan, diff_score=score_repeater_diffs(payload, plan=plan))

    tabs = build_repeater_tab_specs(payload, plan)
    scored = {str(item.get("tab_name") or "").strip(): item for item in list(workflow.get("ranked_items") or []) if isinstance(item, dict)}
    strongest = dict(workflow.get("strongest_delta") or {})
    mutation_learning = dict(workflow.get("mutation_learning_summary") or summarize_repeater_learning(payload_like=payload, vuln_classes=_workflow_classes(plan)))
    negative_reasoning = dict(workflow.get("negative_reasoning_summary") or summarize_negative_reasoning(payload_like=payload, vuln_classes=_workflow_classes(plan)))
    candidate = {}
    candidate_score = -1
    candidate_details: dict[str, Any] = {}
    for item in tabs:
        tab_name = str(item.get("tab_name") or "").strip()
        if tab_name and tab_name not in scored and "baseline-control" not in tab_name.lower():
            score, details = _candidate_learning_score(item, learning=mutation_learning, negative_reasoning=negative_reasoning, plan=plan)
            if score > candidate_score:
                candidate = item
                candidate_score = score
                candidate_details = details
    if not candidate and strongest:
        candidate = next((item for item in tabs if item.get("tab_name") == strongest.get("tab_name")), {})
    if not candidate and tabs:
        candidate = tabs[min(len(tabs) - 1, 1)]

    compare_checks = [
        "Compare status code, redirect, and cache headers against the baseline tab.",
        "Check whether the highlighted sink or object boundary changed in the response body.",
        "Capture one screenshot or raw diff if this tab becomes the strongest signal.",
    ]
    rationale = _best_next_rationale(candidate, strongest, workflow, plan)
    return {
        "workflow_id": workflow.get("workflow_id") or _workflow_id((plan.get("dashboard_issue") or {}).get("issue_id", ""), getattr(payload, "snapshot_id", "") or "", getattr(payload, "target_url", "") or ""),
        "issue_id": (plan.get("dashboard_issue") or {}).get("issue_id", ""),
        "tab_name": candidate.get("tab_name", ""),
        "request_text": candidate.get("request_text", ""),
        "expected_signal": candidate.get("expected_signal", ""),
        "request_ref": candidate.get("request_ref", ""),
        "reason": rationale,
        "compare_checks": compare_checks,
        "score_context": strongest if strongest else {},
        "learning_hint": mutation_learning.get("summary", ""),
        "ranking_details": candidate_details,
    }


def build_workflow_from_observations(payload_like, *, plan: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = coerce_payload(payload_like)
    if plan is None:
        plan = burp_repeater_plan(payload)
    diff_score = score_repeater_diffs(payload, plan=plan)
    learn_from_repeater_diff(payload, plan=plan, diff_score=diff_score)
    return upsert_issue_workflow(payload_like, plan=plan, diff_score=diff_score)


def build_workflow_observation(
    payload_like,
    *,
    plan: dict[str, Any] | None = None,
    workflow: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = coerce_payload(payload_like)
    if plan is None:
        plan = burp_repeater_plan(payload)
    if workflow is None:
        workflow = build_workflow_from_observations(payload, plan=plan)
    next_tab = best_next_tab(payload, plan=plan, workflow=workflow)
    fingerprint = workflow_observation_fingerprint(workflow, next_tab)
    strongest = dict(workflow.get("strongest_delta") or {})
    report_readiness = dict(workflow.get("report_readiness") or {})
    return {
        "workflow_id": workflow.get("workflow_id", ""),
        "workflow_status": workflow.get("status", "planned"),
        "strongest_delta_score": float(strongest.get("score", 0.0) or 0.0),
        "strongest_delta_tab": strongest.get("tab_name", ""),
        "report_ready": bool(report_readiness.get("ready", False)),
        "next_tab_name": next_tab.get("tab_name", ""),
        "next_tab_signal": next_tab.get("expected_signal", ""),
        "next_tab_has_request": bool((next_tab.get("request_text") or "").strip()),
        "observation_fingerprint": fingerprint,
        "learning_hint": next_tab.get("learning_hint", ""),
    }


def workflow_observation_fingerprint(workflow: dict[str, Any], next_tab: dict[str, Any]) -> str:
    status = str(workflow.get("status") or "planned").strip().lower()
    strongest = dict(workflow.get("strongest_delta") or {})
    report_readiness = dict(workflow.get("report_readiness") or {})
    pieces = [
        status or "planned",
        str(strongest.get("tab_name") or "").strip(),
        str(strongest.get("score") or ""),
        str(next_tab.get("tab_name") or "").strip(),
        str(next_tab.get("expected_signal") or "").strip(),
        "ready" if report_readiness.get("ready") else "not-ready",
    ]
    digest = sha1("|".join(pieces).encode("utf-8")).hexdigest()[:16]
    return f"obs:{digest}"


def _report_readiness(plan: dict[str, Any], ranked_items: list[dict[str, Any]], strongest_delta: dict[str, Any]) -> dict[str, Any]:
    issue = plan.get("dashboard_issue") or {}
    missing = []
    if not issue.get("issue_id"):
        missing.append("Pinned Burp issue ID is missing.")
    if not ranked_items:
        missing.append("No scored Repeater observations are stored yet.")
    if strongest_delta and float(strongest_delta.get("score", 0.0) or 0.0) < 2.5:
        missing.append("No high-signal Repeater delta is stored yet.")
    if not (plan.get("required_evidence_for_upgrade") or []):
        missing.append("The escalation path does not yet list required upgrade evidence.")
    ready = not missing
    return {
        "ready": ready,
        "status": "ready" if ready else "needs-more-evidence",
        "missing_evidence": missing[:6],
    }


def _workflow_status(ranked_items: list[dict[str, Any]], strongest_delta: dict[str, Any]) -> str:
    if strongest_delta and float(strongest_delta.get("score", 0.0) or 0.0) >= 2.5:
        return "high-signal-delta"
    if ranked_items:
        return "diff-scored"
    return "planned"


def _best_next_rationale(candidate: dict[str, Any], strongest: dict[str, Any], workflow: dict[str, Any], plan: dict[str, Any]) -> str:
    if candidate and candidate.get("tab_name") and candidate.get("tab_name") != strongest.get("tab_name"):
        learning = ((workflow.get("mutation_learning_summary") or {}).get("summary") or "").strip()
        suffix = f" Prior learning: {learning}" if learning else ""
        return f"{candidate.get('tab_name')} has not been scored yet, so it is the highest-value remaining tab before broadening the workflow.{suffix}"
    if strongest:
        return f"{strongest.get('tab_name') or 'The strongest tab'} already produced the best delta so far; capture cleaner evidence and one confirming comparison before changing direction."
    chain = list(plan.get("issue_chain_strategy") or workflow.get("issue_chain_strategy") or [])
    if chain:
        return chain[0]
    return "Use the first unscored Repeater variant before adding more mutations."


def _candidate_learning_score(
    candidate: dict[str, Any],
    *,
    learning: dict[str, Any],
    negative_reasoning: dict[str, Any],
    plan: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    family = mutation_family(
        candidate.get("tab_name", ""),
        candidate.get("summary", ""),
        candidate.get("expected_signal", ""),
        candidate.get("request_ref", ""),
    )
    preferred = set(learning.get("preferred_families") or [])
    deprioritized = set(learning.get("deprioritized_families") or [])
    negative_families = set(negative_reasoning.get("deprioritized_families") or [])
    success_rates = dict(learning.get("success_rates") or {})
    score = 0
    details = {
        "family": family,
        "success_rate": float(success_rates.get(family, 0.0) or 0.0),
        "expected_signal_bonus": 0,
        "policy_safety_bonus": 0,
        "model_cost_bonus": 0,
        "negative_penalty": 0,
    }
    if family in preferred:
        score += 3
    elif family not in deprioritized:
        score += 1
    if family in negative_families or family in deprioritized:
        score -= 2
        details["negative_penalty"] = 2
    score += int(round(float(success_rates.get(family, 0.0) or 0.0) * 3))
    if any(token in str(candidate.get("expected_signal", "")).lower() for token in ("200/403", "callback", "viewer", "admin", "tenant")):
        score += 2
        details["expected_signal_bonus"] = 2
    if not ((plan.get("policy_gate") or {}).get("applies") and not (plan.get("policy_gate") or {}).get("allowed", True)):
        score += 1
        details["policy_safety_bonus"] = 1
    request_length = len(str(candidate.get("request_text", "") or ""))
    if request_length and request_length < 900:
        score += 1
        details["model_cost_bonus"] = 1
    details["total"] = score
    return score, details


def _workflow_classes(plan: dict[str, Any]) -> list[str]:
    classes = []
    for candidate in [
        (plan.get("dashboard_issue") or {}).get("vuln_hint", ""),
        *((item.get("vuln_hint", "") for item in plan.get("related_scanner_issues", []) or [])),
    ]:
        normalized = (candidate or "").strip().lower()
        if normalized and normalized not in classes:
            classes.append(normalized)
    return classes or ["general"]


def _workflow_id(issue_id: str, snapshot_id: str, target_url: str) -> str:
    normalized_issue = (issue_id or "").strip()
    normalized_snapshot = (snapshot_id or "").strip()
    normalized_target = (target_url or "").strip()
    if normalized_issue:
        return f"issue:{normalized_issue}"
    if normalized_snapshot:
        return f"snapshot:{normalized_snapshot}"
    digest = sha1(normalized_target.encode("utf-8")).hexdigest()[:12] if normalized_target else "unknown"
    return f"target:{digest}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
