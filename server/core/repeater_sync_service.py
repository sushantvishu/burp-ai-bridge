from typing import Any

from server.core.analysis_service import coerce_payload
from server.core.burp_action_service import burp_repeater_plan
from server.core.issue_workflow_service import best_next_tab, build_workflow_from_observations
from server.core.repeater_diff_service import score_repeater_diffs


def sync_repeater_observations(payload_like, *, include_plan: bool = True) -> dict[str, Any]:
    payload = coerce_payload(payload_like)
    plan = burp_repeater_plan(payload)
    diff = score_repeater_diffs(payload, plan=plan)
    workflow = build_workflow_from_observations(payload, plan=plan)
    next_tab = best_next_tab(payload, plan=plan, workflow=workflow)

    response = {
        "target_url": getattr(payload, "target_url", "") or "",
        "issue_id": (plan.get("dashboard_issue") or {}).get("issue_id", ""),
        "workflow_id": workflow.get("workflow_id", ""),
        "workflow_status": workflow.get("status", ""),
        "diff": diff,
        "workflow": workflow,
        "best_next_tab": next_tab,
        "summary": _build_summary(diff, workflow, next_tab),
    }
    if include_plan:
        response["plan"] = plan
    return response


def _build_summary(diff: dict[str, Any], workflow: dict[str, Any], next_tab: dict[str, Any]) -> str:
    best = diff.get("best_item") or {}
    if best:
        return (
            f"Top delta: {best.get('tab_name') or '<unknown>'} "
            f"(score {best.get('score', 0.0)}). "
            f"Workflow is {workflow.get('status') or 'planned'}. "
            f"Next tab: {next_tab.get('tab_name') or '<none>'}."
        )
    return (
        f"No strong Repeater delta scored yet. "
        f"Workflow is {workflow.get('status') or 'planned'}. "
        f"Next tab: {next_tab.get('tab_name') or '<none>'}."
    )
