from server.core.action_labels import label_actions
from server.core.history_service import build_report_evidence
from server.core.impact_upgrade_service import (
    build_finding_to_impact_template,
    build_impact_upgrade_planner,
    build_program_specific_impact_wording,
    build_reportability_gate,
    build_submission_value_score,
)
from server.core.confidence_service import build_confidence_to_claim_map
from server.core.impact_service import rank_impact_paths
from server.core.reasoning_render_service import build_next_decision
from server.core.validation_service import validate_hypothesis
from server.history_store import get_job_record
from server.state.store import get_burp_session_snapshot


def build_structured_report(job_id: str, payload_like=None, advisory: dict | None = None, run: dict | None = None, snapshot_id: str = "") -> dict:
    evidence_bundle = build_report_evidence(job_id)
    if snapshot_id:
        snapshot = get_burp_session_snapshot(snapshot_id)
        if snapshot:
            evidence_bundle = {
                **evidence_bundle,
                "snapshot_id": snapshot_id,
                "burp_session_snapshot": snapshot,
            }
    report_payload = payload_like
    report_advisory = advisory
    report_run = run
    if report_payload is None or report_advisory is None or report_run is None:
        record = get_job_record(job_id)
        if record:
            if report_payload is None:
                report_payload = record
            if report_advisory is None:
                report_advisory = record.get("result") or {}
            if report_run is None:
                report_run = record.get("analysis_run") or {}

    validation = None
    impact = None
    if report_payload is not None:
        validation = validate_hypothesis(report_payload, advisory=report_advisory or {}, run=report_run or {})
        impact = rank_impact_paths(report_payload, advisory=report_advisory or {}, run=report_run or {})

    reproduction_steps = label_actions(
        list(evidence_bundle.get("reporting_checklist", []) or []),
        fallback_used=bool(evidence_bundle.get("fallback_used")),
    )
    top_hypothesis = (validation or {}).get("hypothesis") or ((evidence_bundle.get("hypothesis_summaries") or [{}])[0] if evidence_bundle.get("hypothesis_summaries") else {})
    vuln_class = (top_hypothesis.get("vuln_class") or ((impact or {}).get("dashboard_issue") or {}).get("vuln_hint") or "general").strip().lower()
    impact_upgrade_planner = build_impact_upgrade_planner(vuln_class, validation=validation or {}, impact=impact or {})
    reportability_gate = build_reportability_gate(vuln_class, validation=validation or {}, impact=impact or {})
    submission_value = build_submission_value_score(
        validation=validation or {},
        impact=impact or {},
        severity={"severity": ""},
        policy_gate=((impact or {}).get("policy_gate") or {}),
        platform=((report_payload or {}).get("program_policy_template") if isinstance(report_payload, dict) else getattr(report_payload, "program_policy_template", "")) or ((report_payload or {}).get("program_platform") if isinstance(report_payload, dict) else getattr(report_payload, "program_platform", "")) or "",
    )
    confidence_to_claim_map = build_confidence_to_claim_map(
        vuln_class,
        confidence_level=((validation or {}).get("validation_status") or "low"),
        validation=validation or {},
        impact=impact or {},
    )

    return {
        "job_id": job_id,
        "request_id": evidence_bundle.get("request_id", ""),
        "snapshot_id": snapshot_id or evidence_bundle.get("snapshot_id", ""),
        "title": f"AI Bridge Report for {evidence_bundle.get('target_url') or job_id}",
        "summary": evidence_bundle.get("report_summary", ""),
        "primary_next_action": evidence_bundle.get("primary_next_action", ""),
        "reporting_checklist": evidence_bundle.get("reporting_checklist", []),
        "labeled_reporting_steps": reproduction_steps[:8],
        "hypothesis_summaries": evidence_bundle.get("hypothesis_summaries", []),
        "evidence_artifacts": evidence_bundle.get("evidence_artifacts", []),
        "impact_assessment": impact,
        "validation_assessment": validation,
        "analysis_backend": evidence_bundle.get("analysis_backend", ""),
        "fallback_used": bool(evidence_bundle.get("fallback_used")),
        "source_links": evidence_bundle.get("source_links", []),
        "next_decision": build_next_decision(report_advisory or {}, validation or {}, impact or {}),
        "escalation_guidance": {
            "escalation_profile": (impact or {}).get("escalation_profile", ""),
            "baseline_confirmation": (impact or {}).get("baseline_confirmation", ""),
            "safe_vapt_escalation_steps": list((impact or {}).get("safe_vapt_escalation_steps") or [])[:6],
            "business_impact_expansion_paths": list((impact or {}).get("business_impact_expansion_paths") or [])[:6],
            "required_evidence_for_upgrade": list((impact or {}).get("required_evidence_for_upgrade") or [])[:6],
            "stop_conditions": list((impact or {}).get("stop_conditions") or [])[:6],
            "likely_severity_promotions": list((impact or {}).get("likely_severity_promotions") or [])[:6],
            "policy_gate": (impact or {}).get("policy_gate") or {},
        },
        "impact_upgrade_planner": impact_upgrade_planner,
        "finding_to_impact_template": build_finding_to_impact_template(vuln_class),
        "reportability_gate": reportability_gate,
        "submission_value_score": submission_value,
        "program_specific_impact_wording": build_program_specific_impact_wording("", vuln_class, impact or {}),
        "confidence_to_claim_map": confidence_to_claim_map,
        "burp_session_snapshot": evidence_bundle.get("burp_session_snapshot", {}),
    }
