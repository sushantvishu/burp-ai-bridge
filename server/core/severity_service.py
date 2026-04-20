from typing import Any

from server.core.analysis_service import analyze_exchange, build_analysis_run, coerce_payload
from server.core.confidence_service import (
    build_confidence_to_claim_map,
    calibrate_submission_confidence,
    severity_evidence_gate,
)
from server.core.impact_upgrade_service import build_reportability_gate, build_submission_value_score
from server.core.impact_service import rank_impact_paths
from server.core.validation_service import validate_hypothesis


_CRITICAL_CLASSES = {"authorization", "idor", "authentication", "session-management", "ssrf", "injection", "sqli", "ssti", "deserialization", "xxe", "rce"}
_HIGH_CLASSES = _CRITICAL_CLASSES | {"csrf", "xss", "file-upload", "path-traversal"}


def assess_submission_severity(
    payload_like=None,
    *,
    advisory: dict | None = None,
    run: dict | None = None,
    validation: dict | None = None,
    impact: dict | None = None,
) -> dict[str, Any]:
    payload = coerce_payload(payload_like or {})
    if (validation is None or impact is None) and advisory is None:
        analysis_bundle = analyze_exchange(payload)
        advisory = analysis_bundle["advisory"]
        run = analysis_bundle["run"]
    elif advisory is not None and (run is None or not isinstance(run, dict)):
        run = build_analysis_run(payload, advisory).to_dict()

    validation = validation or validate_hypothesis(payload, advisory=advisory or {}, run=run or {})
    impact = impact or rank_impact_paths(payload, advisory=advisory or {}, run=run or {})

    hypothesis = validation.get("hypothesis") or {}
    vuln_class = (hypothesis.get("vuln_class") or impact.get("dashboard_issue", {}).get("vuln_hint") or "general").strip().lower()
    validation_status = (validation.get("validation_status") or "").strip().lower()
    reportability = (impact.get("reportability") or "").strip().lower()
    business_impact_class = (impact.get("business_impact_class") or "").strip().lower()
    evidence_score = max(
        float(validation.get("evidence_score", 0.0) or 0.0),
        float(impact.get("evidence_score", 0.0) or 0.0),
    )
    dashboard_severity = (impact.get("dashboard_issue", {}).get("severity") or "").strip().lower()

    preliminary_severity = "low"
    if (
        validation_status == "confirmed"
        and bool(impact.get("reportable"))
        and business_impact_class == "high-impact"
        and vuln_class in _CRITICAL_CLASSES
        and evidence_score >= 3.2
    ):
        preliminary_severity = "critical"
    elif (
        bool(impact.get("reportable"))
        and validation_status in {"confirmed", "high-signal"}
        and (business_impact_class == "high-impact" or vuln_class in _HIGH_CLASSES or dashboard_severity in {"high", "critical"})
    ):
        preliminary_severity = "high"
    elif (
        reportability == "medium"
        or validation_status in {"needs-confirmation", "high-signal"}
        or business_impact_class in {"high-impact", "security-impact"}
    ):
        preliminary_severity = "medium"

    evidence_gate = severity_evidence_gate(vuln_class, validation=validation, impact=impact)
    severity = _bounded_severity(preliminary_severity, evidence_gate.get("max_allowed_severity", "critical"))

    downgrade_reasons = _build_downgrade_reasons(validation_status, impact, evidence_score)
    downgrade_reasons.extend(item for item in evidence_gate.get("reasons", []) if item not in downgrade_reasons)
    promotion_triggers = _build_promotion_triggers(vuln_class, validation_status, impact, evidence_score)
    confidence = 0.84 if severity in {"high", "critical"} else 0.72 if severity == "medium" else 0.6
    if downgrade_reasons:
        confidence = max(0.45, confidence - (0.06 * min(len(downgrade_reasons), 3)))
    confidence_calibration = calibrate_submission_confidence(
        vuln_class,
        validation=validation,
        impact=impact,
        severity=severity,
        base_confidence=confidence,
    )
    reportability_gate = build_reportability_gate(vuln_class, validation=validation, impact=impact)
    submission_value = build_submission_value_score(
        validation=validation,
        impact=impact,
        severity={"severity": severity},
        policy_gate=(impact.get("policy_gate") or {}),
        platform=(getattr(payload, "program_policy_template", "") or getattr(payload, "program_platform", "") or ""),
    )
    confidence_to_claim_map = build_confidence_to_claim_map(
        vuln_class,
        confidence_level=confidence_calibration["level"],
        validation=validation,
        impact=impact,
    )

    return {
        "severity": severity,
        "confidence": confidence_calibration["score"],
        "candidate_taxonomy": _candidate_taxonomy(vuln_class),
        "rationale": _build_rationale(severity, vuln_class, validation_status, impact, evidence_score),
        "promotion_triggers": promotion_triggers[:4],
        "downgrade_reasons": downgrade_reasons[:4],
        "evidence_gate": evidence_gate,
        "confidence_calibration": confidence_calibration,
        "reportability_gate": reportability_gate,
        "submission_value_score": submission_value,
        "confidence_to_claim_map": confidence_to_claim_map,
    }


def _bounded_severity(preliminary: str, maximum: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    reverse = {value: key for key, value in order.items()}
    bounded = min(order.get(preliminary, 0), order.get(maximum, 3))
    return reverse.get(bounded, "low")


def _candidate_taxonomy(vuln_class: str) -> str:
    mapping = {
        "authorization": "Access Control / Broken Authorization",
        "idor": "Access Control / IDOR",
        "authentication": "Authentication / Session Bypass",
        "session-management": "Authentication / Session Management",
        "ssrf": "Server-Side Request Forgery",
        "injection": "Injection",
        "sqli": "SQL Injection",
        "ssti": "Server-Side Template Injection",
        "xss": "Cross-Site Scripting",
        "csrf": "Cross-Site Request Forgery",
    }
    return mapping.get(vuln_class, "General Web Application Security")


def _build_rationale(severity: str, vuln_class: str, validation_status: str, impact: dict, evidence_score: float) -> str:
    business_impact_class = impact.get("business_impact_class") or "informational"
    reportability = impact.get("reportability") or "low"
    return (
        f"Severity stays at {severity} because the lead class is {vuln_class or 'general'}, "
        f"validation is {validation_status or 'needs-review'}, impact is {business_impact_class}, "
        f"reportability is {reportability}, and the current evidence score is {round(evidence_score, 2)}."
    )


def _build_promotion_triggers(vuln_class: str, validation_status: str, impact: dict, evidence_score: float) -> list[str]:
    items = []
    if validation_status != "confirmed":
        items.append("Promote only after one role-separated or workflow-separated confirmation is complete.")
    if evidence_score < 3.2:
        items.append("Add one stronger evidence artifact such as a role comparison, callback, or clean manual diff.")
    if not impact.get("reportable"):
        items.append("Promote only when the confirmed effect supports a reportable business-impact statement.")
    if vuln_class in {"xss", "csrf"}:
        items.append("Show privileged or shared-workflow reachability before claiming higher severity.")
    return items


def _build_downgrade_reasons(validation_status: str, impact: dict, evidence_score: float) -> list[str]:
    reasons = []
    if validation_status != "confirmed":
        reasons.append("The primary hypothesis is not yet fully confirmed.")
    if impact.get("confirmation_state") == "needs-confirmation":
        reasons.append("Impact remains bounded because the confirmation state is still incomplete.")
    if not impact.get("reportable"):
        reasons.append("The current evidence bundle does not yet support a strong reportable impact claim.")
    if evidence_score < 2.5:
        reasons.append("Evidence weight is still limited relative to a high-confidence bug-bounty submission.")
    return reasons
