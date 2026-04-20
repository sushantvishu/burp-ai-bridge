from server.core.action_labels import label_actions
from server.core.analysis_service import analyze_exchange, build_analysis_run, coerce_payload


def validate_hypothesis(payload_like, hypothesis_id: str | None = None, advisory: dict | None = None, run: dict | None = None) -> dict:
    payload = coerce_payload(payload_like)
    if advisory is None or run is None:
        analysis_bundle = analyze_exchange(payload)
        advisory = analysis_bundle["advisory"]
        run = analysis_bundle["run"]
    elif not isinstance(run, dict):
        run = build_analysis_run(payload, advisory).to_dict()

    hypotheses = [item for item in (run.get("hypotheses") or []) if isinstance(item, dict)]
    selected = None
    if hypothesis_id:
        selected = next((item for item in hypotheses if (item.get("id") or "").strip() == hypothesis_id.strip()), None)
    if selected is None and hypotheses:
        hypotheses.sort(key=lambda item: (item.get("status") == "confirmed", float(item.get("confidence", 0.0) or 0.0)), reverse=True)
        selected = hypotheses[0]

    evidence = [item for item in (run.get("evidence") or []) if isinstance(item, dict)]
    evidence_sources = {item.get("source") or "" for item in evidence}
    evidence_types = [((item.get("evidence_type") or "").strip().lower()) for item in evidence]
    confirming_sources = {
        source
        for source in evidence_sources
        if source in {"proxy", "logger", "repeater", "operator-delta", "timeline", "burp-dashboard", "collaborator"}
    }
    evidence_score = round(sum(_evidence_weight(item_type) for item_type in evidence_types), 2)
    missing_evidence = list(advisory.get("questions_for_user", []) or [])[:3]
    confirmation = list(advisory.get("confirmation_playbooks", []) or [])[:3]
    safest_next_proof = advisory.get("primary_next_action", "")

    validation_status = "needs-review"
    confidence = float((selected or {}).get("confidence", 0.0) or 0.0)
    if (selected or {}).get("status") == "confirmed":
        validation_status = "confirmed"
    elif confidence >= 0.85 and len(confirming_sources) >= 2 and evidence_score >= 3.0 and not missing_evidence:
        validation_status = "high-signal"
    elif confidence >= 0.45 or confirming_sources:
        validation_status = "needs-confirmation"

    if missing_evidence:
        confidence = max(0.0, confidence - 0.08)
        if validation_status == "high-signal":
            validation_status = "needs-confirmation"

    if advisory.get("fallback_used"):
        confidence = max(0.0, confidence - 0.15)
        if validation_status == "high-signal":
            validation_status = "needs-confirmation"

    recommended_actions = label_actions(
        [safest_next_proof, *confirmation, *missing_evidence],
        fallback_used=bool(advisory.get("fallback_used")),
    )

    return {
        "target_url": getattr(payload, "target_url", "") or "",
        "hypothesis": selected,
        "validation_status": validation_status,
        "confidence": round(confidence, 3),
        "evidence_sources": sorted(source for source in evidence_sources if source),
        "confirming_sources": sorted(confirming_sources),
        "evidence_score": evidence_score,
        "evidence_count": len(evidence),
        "missing_evidence": missing_evidence,
        "confirmation_requirements": confirmation,
        "safest_next_proof": safest_next_proof,
        "recommended_actions": recommended_actions[:6],
        "analysis_backend": advisory.get("analysis_backend", ""),
        "fallback_used": bool(advisory.get("fallback_used")),
    }


def _evidence_weight(evidence_type: str) -> float:
    weights = {
        "role-compare": 1.6,
        "manual-diff": 1.35,
        "callback": 1.35,
        "scanner": 0.9,
        "traffic-history": 0.8,
        "timeline": 0.7,
        "whitebox": 0.7,
        "knowledge-base": 0.45,
        "config": 0.35,
        "derived": 0.25,
        "operator-note": 0.5,
    }
    return weights.get((evidence_type or "").strip().lower(), 0.25)
