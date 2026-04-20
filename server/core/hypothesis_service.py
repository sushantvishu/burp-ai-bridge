from server.core.analysis_service import analyze_exchange, build_analysis_run, coerce_payload


def summarize_hypotheses(payload_like, advisory: dict | None = None, run: dict | None = None) -> dict:
    payload = coerce_payload(payload_like)
    if advisory is None or run is None:
        analysis_bundle = analyze_exchange(payload)
        advisory = analysis_bundle["advisory"]
        run = analysis_bundle["run"]
    elif not isinstance(run, dict):
        run = build_analysis_run(payload, advisory).to_dict()

    hypotheses = list(run.get("hypotheses") or [])
    evidence = list(run.get("evidence") or [])
    evidence_sources = [item.get("source", "") for item in evidence if isinstance(item, dict)]

    ranked = []
    for item in hypotheses:
        if not isinstance(item, dict):
            continue
        next_checks = list(item.get("next_checks") or [])
        ranked.append({
            "id": item.get("id") or "",
            "vuln_class": item.get("vuln_class") or "general",
            "summary": item.get("summary") or "",
            "confidence": float(item.get("confidence", 0.0) or 0.0),
            "status": item.get("status") or "suspected",
            "status_notes": item.get("status_notes", ""),
            "impact_paths": list(item.get("impact_paths") or [])[:3],
            "next_checks": next_checks[:3],
            "evidence_signal_count": len(item.get("evidence_for") or []),
            "contradiction_count": len(item.get("evidence_against") or []),
        })

    ranked.sort(key=lambda entry: (entry["status"] == "confirmed", entry["confidence"]), reverse=True)
    return {
        "target_url": getattr(payload, "target_url", "") or "",
        "primary_hypothesis": ranked[0] if ranked else None,
        "hypotheses": ranked[:8],
        "hypothesis_count": len(ranked),
        "evidence_count": len(evidence),
        "evidence_sources": sorted({source for source in evidence_sources if source}),
        "analysis_backend": advisory.get("analysis_backend", ""),
        "fallback_used": bool(advisory.get("fallback_used")),
    }
