from typing import Any

from server.core.browser_verification_service import build_browser_verification_plan
from server.core.impact_upgrade_service import (
    build_impact_upgrade_planner,
    build_program_specific_impact_wording,
)
from server.core.program_policy_service import build_program_policy_context
from server.core.report_service import build_structured_report
from server.core.severity_service import assess_submission_severity
from server.history_store import get_job_record


def build_bug_bounty_submission(job_id: str, platform: str = "", snapshot_id: str = "") -> dict[str, Any]:
    record = get_job_record(job_id)
    if not record:
        raise ValueError(f"History record '{job_id}' was not found.")

    structured_report = build_structured_report(
        job_id,
        payload_like=record,
        advisory=record.get("result") or {},
        run=record.get("analysis_run") or {},
        snapshot_id=snapshot_id or (record.get("snapshot_id") or ""),
    )
    policy = build_program_policy_context(record, template_name=platform)
    severity = assess_submission_severity(
        record,
        advisory=record.get("result") or {},
        run=record.get("analysis_run") or {},
        validation=structured_report.get("validation_assessment") or {},
        impact=structured_report.get("impact_assessment") or {},
    )
    browser_plan = build_browser_verification_plan(
        record,
        advisory=record.get("result") or {},
        run=record.get("analysis_run") or {},
        validation=structured_report.get("validation_assessment") or {},
        impact=structured_report.get("impact_assessment") or {},
    )

    report = {
        "job_id": job_id,
        "request_id": structured_report.get("request_id", ""),
        "snapshot_id": structured_report.get("snapshot_id", ""),
        "platform": policy.get("platform", "generic"),
        "template_name": policy.get("name", "generic"),
        "title": _build_title(structured_report, severity),
        "target_url": record.get("target_url", ""),
        "summary": _build_summary(structured_report, severity),
        "severity_assessment": severity,
        "validation_status": (structured_report.get("validation_assessment") or {}).get("validation_status", ""),
        "reportability": (structured_report.get("impact_assessment") or {}).get("reportability", ""),
        "reproduction_steps": _build_reproduction_steps(structured_report, browser_plan),
        "impact_statement": _build_impact_statement(structured_report, severity),
        "evidence_highlights": _build_evidence_highlights(structured_report),
        "submission_notes": _build_submission_notes(policy, severity),
        "policy_alignment": _build_policy_alignment(record, policy, browser_plan),
        "browser_verification_appendix": _browser_appendix(browser_plan),
        "escalation_guidance": structured_report.get("escalation_guidance") or {},
        "impact_upgrade_planner": build_impact_upgrade_planner(
            _top_vuln_class(structured_report),
            validation=structured_report.get("validation_assessment") or {},
            impact=structured_report.get("impact_assessment") or {},
            severity=severity,
        ),
        "finding_to_impact_template": structured_report.get("finding_to_impact_template") or {},
        "reportability_gate": (
            severity.get("reportability_gate")
            or structured_report.get("reportability_gate")
            or {}
        ),
        "submission_value_score": (
            severity.get("submission_value_score")
            or structured_report.get("submission_value_score")
            or {}
        ),
        "program_specific_impact_wording": build_program_specific_impact_wording(
            policy.get("name", "generic"),
            _top_vuln_class(structured_report),
            structured_report.get("impact_assessment") or {},
        ),
        "confidence_to_claim_map": severity.get("confidence_to_claim_map") or structured_report.get("confidence_to_claim_map") or {},
        "burp_session_snapshot": structured_report.get("burp_session_snapshot") or {},
    }
    report["markdown"] = render_bug_bounty_submission_markdown(report)
    return report


def render_bug_bounty_submission_markdown(report: dict[str, Any]) -> str:
    severity = report.get("severity_assessment") or {}
    lines = [
        f"# {report.get('title') or 'Bug Bounty Submission'}",
        "",
        f"- Platform template: {report.get('platform') or 'generic'}",
        f"- Job ID: {report.get('job_id') or '<unknown>'}",
        f"- Request ID: {report.get('request_id') or '<unknown>'}",
        f"- Snapshot ID: {report.get('snapshot_id') or '<none>'}",
        f"- Target URL: {report.get('target_url') or '<unknown>'}",
        f"- Severity: {severity.get('severity') or 'medium'}",
        f"- Candidate taxonomy: {severity.get('candidate_taxonomy') or 'General Web Application Security'}",
        f"- Confidence: {severity.get('confidence') or 0.0}",
        "",
        "## Summary",
        report.get("summary") or "No summary was generated.",
        "",
        "## Steps To Reproduce",
    ]
    steps = report.get("reproduction_steps") or []
    if steps:
        for index, item in enumerate(steps, start=1):
            lines.append(f"{index}. {item}")
    else:
        lines.append("1. No reproduction steps were generated.")

    lines.extend([
        "",
        "## Confidence Calibration",
    ])
    calibration = severity.get("confidence_calibration") or {}
    if calibration:
        lines.append(f"- Level: {calibration.get('level') or '<unknown>'}")
        lines.append(f"- Score: {calibration.get('score') or 0.0}")
        for item in calibration.get("reasons") or []:
            lines.append(f"- {item}")
        for item in calibration.get("missing_artifacts") or []:
            lines.append(f"- Missing artifact: {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Impact",
        report.get("impact_statement") or "No impact statement was generated.",
        "",
        "## Impact Upgrade Planner",
    ])
    planner = report.get("impact_upgrade_planner") or {}
    if planner:
        lines.append(f"- Current proof level: {planner.get('current_proof_level') or '<unknown>'}")
        lines.append(f"- Next strongest allowed step: {planner.get('next_strongest_allowed_step') or '<none>'}")
        lines.append(f"- Missing artifact for upgrade: {planner.get('missing_artifact_for_upgrade') or '<none>'}")
        lines.append(f"- Likely severity if confirmed: {planner.get('likely_severity_if_confirmed') or '<unknown>'}")
        lines.append(f"- Report-ready sentence: {planner.get('report_ready_impact_sentence') or '<none>'}")
        for item in planner.get("impact_ladder") or []:
            lines.append(f"- Impact ladder: {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Submission Value",
    ])
    submission_value = report.get("submission_value_score") or {}
    if submission_value:
        lines.append(f"- Score: {submission_value.get('score') or 0.0}")
        lines.append(f"- Summary: {submission_value.get('summary') or '<none>'}")
        for name, value in (submission_value.get("components") or {}).items():
            lines.append(f"- {name.replace('_', ' ').title()}: {value}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Platform Wording",
    ])
    wording = report.get("program_specific_impact_wording") or {}
    if wording:
        lines.append(f"- Focus: {wording.get('focus') or '<none>'}")
        lines.append(f"- Wording: {wording.get('wording') or '<none>'}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Confidence To Claim",
    ])
    claim_map = report.get("confidence_to_claim_map") or {}
    if claim_map:
        for item in claim_map.get("allowed_claims") or []:
            lines.append(f"- Allowed: {item}")
        for item in claim_map.get("guarded_claims") or []:
            lines.append(f"- Guarded: {item}")
        for item in claim_map.get("prohibited_claims") or []:
            lines.append(f"- Prohibited: {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Evidence Highlights",
    ])
    evidence = report.get("evidence_highlights") or []
    if evidence:
        for item in evidence:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Submission Notes",
    ])
    notes = report.get("submission_notes") or []
    if notes:
        for item in notes:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Policy Alignment",
    ])
    alignment = report.get("policy_alignment") or []
    if alignment:
        for item in alignment:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    browser_appendix = report.get("browser_verification_appendix") or {}
    escalation = report.get("escalation_guidance") or {}
    snapshot = report.get("burp_session_snapshot") or {}
    lines.extend([
        "",
        "## Browser Verification Appendix",
        f"- Allowed: {bool(browser_appendix.get('allowed'))}",
        f"- Goal: {browser_appendix.get('verification_goal') or '<none>'}",
    ])
    for item in browser_appendix.get("suggested_steps") or []:
        lines.append(f"- {item}")

    if escalation:
        lines.extend([
            "",
            "## Escalation Guidance",
            f"- Profile: {escalation.get('escalation_profile') or '<unknown>'}",
            f"- Baseline confirmation: {escalation.get('baseline_confirmation') or '<none>'}",
        ])
        for item in escalation.get("business_impact_expansion_paths") or []:
            lines.append(f"- Impact expansion: {item}")
        for item in escalation.get("required_evidence_for_upgrade") or []:
            lines.append(f"- Required evidence: {item}")
        for item in escalation.get("stop_conditions") or []:
            lines.append(f"- Stop condition: {item}")

    if snapshot:
        lines.extend([
            "",
            "## Burp Session Snapshot",
            f"- Snapshot ID: {snapshot.get('snapshot_id') or '<unknown>'}",
            f"- Created At: {snapshot.get('created_at') or '<unknown>'}",
            f"- Issue: {((snapshot.get('issue_context') or {}).get('issue_name') or '<none>')}",
            f"- Proxy History Entries: {((snapshot.get('proxy_history') or {}).get('count') or 0)}",
            f"- Repeater Entries: {((snapshot.get('repeater_context') or {}).get('count') or 0)}",
        ])

    return "\n".join(lines) + "\n"


def _build_title(structured_report: dict, severity: dict) -> str:
    hypotheses = structured_report.get("hypothesis_summaries") or []
    top = hypotheses[0] if hypotheses else {}
    vuln_class = (top.get("vuln_class") or "finding").upper()
    target = structured_report.get("title") or structured_report.get("job_id") or "submission"
    return f"[{severity.get('severity', 'medium').upper()}] {vuln_class} on {target}"


def _build_summary(structured_report: dict, severity: dict) -> str:
    impact = structured_report.get("impact_assessment") or {}
    validation = structured_report.get("validation_assessment") or {}
    hypotheses = structured_report.get("hypothesis_summaries") or []
    top = hypotheses[0] if hypotheses else {}
    summary = structured_report.get("summary") or ""
    if summary:
        return summary
    return (
        f"The finding is currently assessed as {severity.get('severity', 'medium')} severity. "
        f"The lead hypothesis is {top.get('summary') or 'a bounded security issue'} with validation "
        f"status {validation.get('validation_status') or 'needs-review'} and impact class "
        f"{impact.get('business_impact_class') or 'informational'}."
    )


def _build_reproduction_steps(structured_report: dict, browser_plan: dict) -> list[str]:
    steps = list(structured_report.get("reporting_checklist") or [])[:6]
    if browser_plan.get("allowed"):
        steps.extend((browser_plan.get("suggested_steps") or [])[:2])
    deduped: list[str] = []
    for item in steps:
        normalized = (item or "").strip()
        if normalized and normalized not in deduped:
            deduped.append(normalized)
    return deduped[:8]


def _build_impact_statement(structured_report: dict, severity: dict) -> str:
    impact = structured_report.get("impact_assessment") or {}
    validation = structured_report.get("validation_assessment") or {}
    safest_next_proof = (impact.get("safest_next_proof") or "").strip()
    base = (
        f"Current impact is {impact.get('business_impact_class') or 'informational'} with reportability "
        f"{impact.get('reportability') or 'low'}. The working severity is {severity.get('severity') or 'medium'}, "
        f"and validation is {validation.get('validation_status') or 'needs-review'}. "
        f"{safest_next_proof}".strip()
    )
    wording = build_program_specific_impact_wording(
        "",
        _top_vuln_class(structured_report),
        impact,
    ).get("wording", "")
    return f"{base} {wording}".strip()


def _build_evidence_highlights(structured_report: dict) -> list[str]:
    artifacts = structured_report.get("evidence_artifacts") or []
    items = []
    for artifact in artifacts[:6]:
        source = artifact.get("source") or "analysis"
        summary = artifact.get("summary") or ""
        if summary:
            items.append(f"[{source}] {summary}")
    return items


def _build_submission_notes(policy: dict, severity: dict) -> list[str]:
    notes = list(policy.get("report_expectations", []) or [])[:4]
    notes.append(severity.get("rationale") or "")
    submission_value = severity.get("submission_value_score") or {}
    if submission_value.get("summary"):
        notes.append(submission_value["summary"])
    return [item for item in notes if (item or "").strip()]


def _build_policy_alignment(record: dict, policy: dict, browser_plan: dict) -> list[str]:
    items = [
        f"Applied policy template: {policy.get('name') or 'generic'}.",
        "Testing remained bounded to non-destructive proof and evidence capture.",
    ]
    scope = (record.get("scope_includes_text") or "").strip()
    if scope:
        items.append(f"Scope note used during testing: {scope}")
    if browser_plan.get("allowed_workflows"):
        items.append("Browser verification stayed inside: " + ", ".join(browser_plan.get("allowed_workflows")[:3]))
    policy_gate = ((record.get("result") or {}).get("policy_gate") or {})
    if policy_gate.get("effective_applies", policy_gate.get("applies")) and not policy_gate.get("effective_allowed", policy_gate.get("allowed")):
        items.append(policy_gate.get("effective_reason") or policy_gate.get("reason") or "High-risk escalation remained gated by saved program policy.")
    items.extend(list(policy.get("safe_testing_notes", []) or [])[:2])
    return items[:6]


def _browser_appendix(browser_plan: dict) -> dict[str, Any]:
    return {
        "allowed": bool(browser_plan.get("allowed")),
        "verification_goal": browser_plan.get("verification_goal", ""),
        "allowed_workflows": list(browser_plan.get("allowed_workflows", []) or [])[:4],
        "suggested_steps": list(browser_plan.get("suggested_steps", []) or [])[:4],
        "stop_conditions": list(browser_plan.get("stop_conditions", []) or [])[:4],
    }


def _top_vuln_class(structured_report: dict[str, Any]) -> str:
    hypotheses = structured_report.get("hypothesis_summaries") or []
    if hypotheses:
        return (hypotheses[0].get("vuln_class") or "general").strip().lower()
    impact = structured_report.get("impact_assessment") or {}
    dashboard_issue = impact.get("dashboard_issue") or {}
    return (dashboard_issue.get("vuln_hint") or "general").strip().lower()
