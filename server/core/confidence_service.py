from __future__ import annotations

from typing import Any


def calibrate_submission_confidence(
    vuln_class: str,
    *,
    validation: dict[str, Any],
    impact: dict[str, Any],
    severity: str,
    base_confidence: float,
) -> dict[str, Any]:
    normalized_class = (vuln_class or "general").strip().lower()
    rules = _evidence_rules(normalized_class)
    evidence_score = max(
        float(validation.get("evidence_score", 0.0) or 0.0),
        float(impact.get("evidence_score", 0.0) or 0.0),
    )
    count_present = "evidence_count" in validation or "evidence_count" in impact
    evidence_count = max(
        int(validation.get("evidence_count", 0) or 0),
        int(impact.get("evidence_count", 0) or 0),
    )
    missing = list(validation.get("missing_evidence") or []) + list(impact.get("evidence_gaps") or [])
    missing = [str(item).strip() for item in missing if str(item).strip()]
    target_rule = rules.get(severity, {})
    score_gap = max(0.0, float(target_rule.get("min_score", 0.0) or 0.0) - evidence_score)
    count_gap = max(0, int(target_rule.get("min_count", 0) or 0) - evidence_count) if count_present else 0

    reasons = []
    if evidence_score >= float(target_rule.get("min_score", 0.0) or 0.0):
        reasons.append(f"Evidence score {round(evidence_score, 2)} meets the {severity} threshold.")
    else:
        reasons.append(f"Evidence score {round(evidence_score, 2)} is below the {severity} threshold.")
    if not count_present or evidence_count >= int(target_rule.get("min_count", 0) or 0):
        reasons.append(f"Evidence count {evidence_count} meets the {severity} threshold.")
    else:
        reasons.append(f"Evidence count {evidence_count} is below the {severity} threshold.")
    if missing:
        reasons.append("Open evidence gaps remain: " + "; ".join(missing[:3]))

    adjusted = base_confidence
    adjusted -= min(score_gap * 0.08, 0.22)
    adjusted -= min(count_gap * 0.06, 0.18)
    adjusted -= min(len(missing) * 0.04, 0.16)
    adjusted = max(0.32, min(0.96, adjusted))

    level = "high" if adjusted >= 0.8 else "medium" if adjusted >= 0.6 else "low"
    return {
        "level": level,
        "score": round(adjusted, 3),
        "target_rule": target_rule,
        "reasons": reasons[:5],
        "missing_artifacts": missing[:5],
    }


def severity_evidence_gate(vuln_class: str, *, validation: dict[str, Any], impact: dict[str, Any]) -> dict[str, Any]:
    normalized_class = (vuln_class or "general").strip().lower()
    rules = _evidence_rules(normalized_class)
    evidence_score = max(
        float(validation.get("evidence_score", 0.0) or 0.0),
        float(impact.get("evidence_score", 0.0) or 0.0),
    )
    count_present = "evidence_count" in validation or "evidence_count" in impact
    evidence_count = max(
        int(validation.get("evidence_count", 0) or 0),
        int(impact.get("evidence_count", 0) or 0),
    )
    missing = list(validation.get("missing_evidence") or []) + list(impact.get("evidence_gaps") or [])

    max_allowed = "low"
    reasons = []
    for candidate in ("medium", "high", "critical"):
        rule = rules[candidate]
        count_failed = count_present and evidence_count < rule["min_count"]
        missing_failed = candidate in {"critical", "high"} and bool(missing)
        if evidence_score >= rule["min_score"] and not count_failed and not missing_failed:
            max_allowed = candidate
        else:
            reasons.append(f"{candidate} blocked because score/count threshold or evidence completeness for {normalized_class} is not met.")
    return {
        "max_allowed_severity": max_allowed,
        "reasons": reasons[:4],
        "thresholds": rules,
    }


def build_confidence_to_claim_map(
    vuln_class: str,
    *,
    confidence_level: str,
    validation: dict[str, Any],
    impact: dict[str, Any],
) -> dict[str, Any]:
    normalized_class = (vuln_class or "general").strip().lower()
    level = (confidence_level or "low").strip().lower()
    validation_status = (validation.get("validation_status") or "").strip().lower()
    reportable = bool(impact.get("reportable"))
    allowed = [
        f"Describe the {normalized_class} condition as a bounded observed finding tied to the stored evidence bundle.",
    ]
    guarded = [
        "Use conditional wording for business impact when the required upgrade evidence is still missing.",
    ]
    prohibited = [
        "Do not claim broad tenant-wide or privileged compromise without the exact supporting artifact.",
    ]
    if level in {"high", "medium"} and validation_status in {"confirmed", "high-signal"}:
        allowed.append("State clearly what is already proven and keep the reproduction tied to one clean diff or viewer path.")
    if reportable and level == "high":
        allowed.append("Use direct business-impact wording, but only for the confirmed path.")
    else:
        guarded.append("Keep severity-upgrade wording framed as the next likely outcome if confirmed.")
    if normalized_class in {"xss", "stored-xss"}:
        prohibited.append("Do not imply session theft or account takeover unless the execution context proves it.")
    if normalized_class in {"idor", "bola", "api-bola"}:
        prohibited.append("Do not generalize one object leak into full cross-tenant compromise without an extra scope artifact.")
    if normalized_class in {"ssrf", "xxe"}:
        prohibited.append("Do not claim internal network compromise from parser behavior alone.")
    return {
        "confidence_level": level,
        "allowed_claims": allowed[:4],
        "guarded_claims": guarded[:4],
        "prohibited_claims": prohibited[:4],
    }


def _downgrade_target(severity: str) -> str:
    if severity == "critical":
        return "high"
    if severity == "high":
        return "medium"
    return "low"


def _evidence_rules(vuln_class: str) -> dict[str, dict[str, Any]]:
    base = {
        "critical": {"min_score": 3.6, "min_count": 3},
        "high": {"min_score": 2.8, "min_count": 2},
        "medium": {"min_score": 1.5, "min_count": 1},
    }
    overrides = {
        "idor": {"critical": {"min_score": 4.0, "min_count": 3}, "high": {"min_score": 2.9, "min_count": 2}},
        "authentication": {"critical": {"min_score": 3.6, "min_count": 2}, "high": {"min_score": 3.0, "min_count": 2}},
        "session-management": {"critical": {"min_score": 3.8, "min_count": 3}, "high": {"min_score": 2.9, "min_count": 2}},
        "ssrf": {"critical": {"min_score": 4.1, "min_count": 3}, "high": {"min_score": 3.1, "min_count": 2}},
        "xxe": {"critical": {"min_score": 4.1, "min_count": 3}, "high": {"min_score": 3.0, "min_count": 2}},
        "xss": {"critical": {"min_score": 4.0, "min_count": 3}, "high": {"min_score": 3.1, "min_count": 2}},
        "csrf": {"critical": {"min_score": 3.8, "min_count": 3}, "high": {"min_score": 2.8, "min_count": 2}},
        "mass-assignment": {"critical": {"min_score": 4.0, "min_count": 3}, "high": {"min_score": 3.0, "min_count": 2}},
        "http-request-smuggling": {"critical": {"min_score": 4.2, "min_count": 3}, "high": {"min_score": 3.2, "min_count": 2}},
        "api-bola": {"critical": {"min_score": 4.0, "min_count": 3}, "high": {"min_score": 3.0, "min_count": 2}},
        "api-bfl": {"critical": {"min_score": 4.0, "min_count": 3}, "high": {"min_score": 3.0, "min_count": 2}},
    }
    merged = {name: dict(rule) for name, rule in base.items()}
    for severity, rule in overrides.get(vuln_class, {}).items():
        merged[severity] = dict(rule)
    return merged
