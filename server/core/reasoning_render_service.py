def build_reasoning_summary(record: dict) -> dict:
    result = record.get("result") or {}
    analysis_run = record.get("analysis_run") or {}
    phase_results = analysis_run.get("phase_results") or analysis_run.get("phases") or {}
    hypotheses = analysis_run.get("hypotheses") or []
    evidence = analysis_run.get("evidence") or []
    top_hypothesis = hypotheses[0] if hypotheses else {}
    validation = phase_results.get("validate") or {}
    impact = phase_results.get("impact") or {}

    key_evidence = build_key_evidence(evidence)
    return {
        "job_id": record.get("job_id") or "",
        "request_id": record.get("request_id") or "",
        "target_url": record.get("target_url") or "",
        "top_hypothesis": top_hypothesis,
        "phase_highlights": build_phase_highlights(phase_results),
        "key_evidence": key_evidence,
        "confidence_drivers": build_confidence_drivers(top_hypothesis, key_evidence),
        "downgrade_reasons": build_downgrade_reasons(result, validation, impact),
        "next_decision": build_next_decision(result, validation, impact),
    }


def build_phase_highlights(phase_results: dict) -> list[dict]:
    highlights = []
    for phase_name in ("ingest", "enrich", "hypothesize", "validate", "impact", "report"):
        phase_result = phase_results.get(phase_name) or {}
        highlights.append({
            "phase": phase_name,
            "summary": phase_summary_line(phase_name, phase_result),
        })
    return highlights


def build_key_evidence(evidence: list[dict], limit: int = 5) -> list[dict]:
    items = []
    for item in evidence[:limit]:
        items.append({
            "source": item.get("source") or "",
            "evidence_type": item.get("evidence_type") or "",
            "summary": item.get("summary") or "",
            "confidence": item.get("confidence", 0.0),
        })
    return items


def build_confidence_drivers(top_hypothesis: dict, key_evidence: list[dict]) -> list[str]:
    drivers = list((top_hypothesis.get("evidence_for") or [])[:3])
    drivers.extend(
        f"{item.get('evidence_type')}: {item.get('summary')}"
        for item in key_evidence[:2]
        if item.get("evidence_type") and item.get("summary")
    )
    return drivers[:5]


def build_downgrade_reasons(result: dict, validation: dict, impact: dict) -> list[str]:
    reasons = []
    if result.get("fallback_used"):
        reasons.append("Provider fallback was used, so confidence was reduced automatically.")
    if validation.get("missing_evidence"):
        reasons.append("Validation still has unresolved evidence gaps.")
    if impact.get("confirmation_state") == "needs-confirmation":
        reasons.append("Impact stayed below strong reportability because the lead hypothesis is not confirmed.")
    if not impact.get("reportable"):
        reasons.append("The current evidence bundle is not yet strong enough for a reportable impact claim.")
    return reasons


def build_next_decision(result: dict, validation: dict, impact: dict) -> dict:
    return {
        "primary_next_action": result.get("primary_next_action") or "",
        "validation_status": validation.get("validation_status") or "",
        "reportability": impact.get("reportability") or "",
        "confirmation_state": impact.get("confirmation_state") or "",
    }


def phase_summary_line(phase_name: str, phase_result: dict) -> str:
    if phase_name == "ingest":
        return f"{phase_result.get('http_method', '')} {phase_result.get('target_url', '')}".strip()
    if phase_name == "enrich":
        return f"playbooks={len(phase_result.get('matched_playbooks', []) or [])}, kb_hits={len(phase_result.get('kb_hits', []) or [])}"
    if phase_name == "hypothesize":
        return f"count={phase_result.get('count', 0)}, classes={', '.join(phase_result.get('classes', [])[:3])}"
    if phase_name == "validate":
        return f"{phase_result.get('validation_status', 'needs-review')} with {phase_result.get('evidence_count', 0)} evidence items"
    if phase_name == "impact":
        return f"reportable={bool(phase_result.get('reportable'))}, class={phase_result.get('business_impact_class', '')}"
    if phase_name == "report":
        return f"backend={phase_result.get('backend', '')}, fallback={bool(phase_result.get('fallback_used'))}"
    return str(phase_result)
