from __future__ import annotations

from typing import Any

from server.core.submission_report_service import build_bug_bounty_submission


def build_operator_review(job_id: str, *, platform: str = "", snapshot_id: str = "") -> dict[str, Any]:
    submission = build_bug_bounty_submission(job_id, platform=platform, snapshot_id=snapshot_id)
    reportability_gate = submission.get("reportability_gate") or {}
    planner = submission.get("impact_upgrade_planner") or {}
    evidence = list(submission.get("evidence_highlights") or [])
    weakest = (
        (reportability_gate.get("still_inferred") or [None])[0]
        or (reportability_gate.get("unsafe_to_claim_yet") or [None])[0]
        or ""
    )
    return {
        "job_id": submission.get("job_id", ""),
        "request_id": submission.get("request_id", ""),
        "snapshot_id": submission.get("snapshot_id", ""),
        "platform": submission.get("platform", ""),
        "title": submission.get("title", ""),
        "strongest_evidence": evidence[:3],
        "weakest_assumption": weakest,
        "next_best_allowed_step": planner.get("next_strongest_allowed_step", ""),
        "reportability_gate": reportability_gate,
        "submission_value_score": submission.get("submission_value_score") or {},
        "confidence_to_claim_map": (submission.get("severity_assessment") or {}).get("confidence_to_claim_map") or {},
        "program_specific_impact_wording": submission.get("program_specific_impact_wording") or {},
        "summary": _summary(evidence, weakest, planner, submission),
    }


def _summary(evidence: list[str], weakest: str, planner: dict[str, Any], submission: dict[str, Any]) -> str:
    strongest = evidence[0] if evidence else "No strongest evidence artifact is stored yet."
    next_step = planner.get("next_strongest_allowed_step") or "No next allowed step is currently defined."
    return (
        f"Strongest evidence: {strongest} "
        f"Weakest assumption: {weakest or 'none recorded'}. "
        f"Next step: {next_step} "
        f"Submission value: {((submission.get('submission_value_score') or {}).get('summary') or 'not scored')}."
    )
