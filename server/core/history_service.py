from server.core.analysis_service import coerce_payload
from server.history_store import get_job_record, paginate_history_records, read_history_records
from server.capabilities.memory import (
    build_history_fingerprint,
    describe_history_matches,
    find_history_matches,
)
from server.core.reasoning_render_service import build_reasoning_summary
from server.providers.deterministic_provider import build_deterministic_context
from server.state.store import append_hypothesis_transition, get_burp_session_snapshot, read_phase_snapshots


def list_history_records(cursor: int = 0, limit: int = 20) -> dict:
    page = paginate_history_records(limit=limit, cursor=cursor)
    window = page["items"]
    items = []
    for record in window:
        result = record.get("result") or {}
        analysis_run = record.get("analysis_run") or {}
        items.append({
            "job_id": record.get("job_id") or "",
            "request_id": record.get("request_id") or "",
            "created_at": record.get("created_at") or "",
            "target_url": record.get("target_url") or "",
            "http_method": record.get("http_method") or "",
            "status": record.get("status") or "",
            "analysis_backend": result.get("analysis_backend") or "",
            "fallback_used": bool(result.get("fallback_used")),
            "hypothesis_count": len(analysis_run.get("hypotheses") or []),
            "evidence_count": len(analysis_run.get("evidence") or []),
            "top_vulnerability": ((result.get("potential_vulnerabilities") or [""])[0] or ""),
        })

    return {
        "cursor": page["cursor"],
        "limit": page["limit"],
        "total": page["total"],
        "items": items,
        "next_cursor": page["next_cursor"],
    }


def query_similar_history(payload_like, limit: int = 5) -> dict:
    payload = coerce_payload(payload_like)
    rule_context = build_deterministic_context(payload)
    fingerprint = build_history_fingerprint(payload, rule_context)
    similar_hits = find_history_matches(fingerprint, limit=max(1, min(limit, 12)))
    correlation = describe_history_matches(fingerprint, similar_hits)
    records_by_job = {record.get("job_id"): record for record in read_history_records()}

    matches = []
    for hit in similar_hits:
        record = records_by_job.get(hit.get("job_id")) or {}
        analysis_run = record.get("analysis_run") or {}
        matches.append({
            "job_id": hit.get("job_id") or "",
            "target_url": hit.get("target_url") or record.get("target_url") or "",
            "created_at": hit.get("created_at") or record.get("created_at") or "",
            "similarity": hit.get("similarity", 0.0),
            "shared_classes": hit.get("shared_vuln_classes", []),
            "potential_vulnerabilities": (record.get("result") or {}).get("potential_vulnerabilities", [])[:4],
            "hypotheses": (analysis_run.get("hypotheses") or [])[:4],
            "evidence_count": len(analysis_run.get("evidence") or []),
            "feedback_labels": hit.get("feedback_labels", []),
            "analysis_backend": ((record.get("result") or {}).get("analysis_backend") or ""),
        })

    return {
        "fingerprint": fingerprint,
        "correlation": correlation[:6],
        "matches": matches,
    }


def build_report_evidence(job_id: str) -> dict:
    record = get_job_record(job_id)
    if not record:
        raise ValueError(f"History record '{job_id}' was not found.")

    result = record.get("result") or {}
    analysis_run = record.get("analysis_run") or {}
    hypotheses = analysis_run.get("hypotheses") or []
    evidence = analysis_run.get("evidence") or []
    snapshot_id = (record.get("snapshot_id") or "").strip()
    snapshot = get_burp_session_snapshot(snapshot_id) if snapshot_id else None
    snapshot_evidence = list((snapshot or {}).get("evidence_bundle") or [])[:4]

    return {
        "job_id": record.get("job_id") or "",
        "request_id": record.get("request_id") or "",
        "snapshot_id": snapshot_id,
        "target_url": record.get("target_url") or "",
        "http_method": record.get("http_method") or "",
        "primary_next_action": result.get("primary_next_action") or "",
        "report_summary": result.get("analysis") or "",
        "hypothesis_summaries": [
            {
                "vuln_class": item.get("vuln_class") or "general",
                "summary": item.get("summary") or "",
                "confidence": item.get("confidence", 0.0),
                "status": item.get("status") or "suspected",
                "next_checks": (item.get("next_checks") or [])[:3],
            }
            for item in hypotheses[:6]
        ],
        "evidence_artifacts": [
            {
                "source": item.get("source") or "analysis",
                "evidence_type": item.get("evidence_type") or "",
                "summary": item.get("summary") or "",
                "delta": item.get("delta") or "",
                "notes": item.get("notes") or "",
                "timestamp": item.get("timestamp") or "",
                "confidence": item.get("confidence", 0.0),
            }
            for item in evidence[:10]
        ] + [
            {
                "source": item.get("source") or "burp-snapshot",
                "evidence_type": "burp-session-snapshot",
                "summary": item.get("summary") or "",
                "delta": "",
                "notes": item.get("detail") or "",
                "timestamp": (snapshot or {}).get("created_at") or "",
                "confidence": 0.66,
            }
            for item in snapshot_evidence
        ],
        "reporting_checklist": (result.get("burp_action_checklist") or [])[:8],
        "confirmation_playbooks": (result.get("confirmation_playbooks") or [])[:6],
        "source_links": (result.get("source_links") or [])[:8],
        "analysis_backend": result.get("analysis_backend") or "",
        "fallback_used": bool(result.get("fallback_used")),
        "burp_session_snapshot": snapshot or {},
    }


def update_hypothesis_status(job_id: str, hypothesis_id: str, status: str, notes: str = "") -> dict:
    record = get_job_record(job_id)
    if not record:
        raise ValueError(f"History record '{job_id}' was not found.")

    analysis_run = record.get("analysis_run") or {}
    hypotheses = analysis_run.get("hypotheses") or []
    match = next((item for item in hypotheses if (item.get("id") or "").strip() == (hypothesis_id or "").strip()), None)
    if not match:
        raise ValueError(f"Hypothesis '{hypothesis_id}' was not found for job '{job_id}'.")

    append_hypothesis_transition(job_id, hypothesis_id, status, notes)
    updated_record = get_job_record(job_id)
    updated_run = (updated_record or {}).get("analysis_run") or {}
    updated_hypothesis = next(
        (item for item in (updated_run.get("hypotheses") or []) if (item.get("id") or "").strip() == (hypothesis_id or "").strip()),
        None,
    )
    return {
        "job_id": job_id,
        "hypothesis_id": hypothesis_id,
        "status": (updated_hypothesis or {}).get("status") or status,
        "notes": (updated_hypothesis or {}).get("status_notes") or (notes or "").strip(),
        "updated_at": (updated_hypothesis or {}).get("status_updated_at") or "",
        "summary": (updated_hypothesis or {}).get("summary") or match.get("summary") or "",
    }


def query_phase_history(job_id: str = "", phase: str = "", limit: int = 20) -> dict:
    safe_limit = max(1, min(int(limit or 20), 100))
    normalized_job_id = (job_id or "").strip()
    normalized_phase = (phase or "").strip().lower()

    snapshots = list(reversed(read_phase_snapshots()))
    items = []
    for snapshot in snapshots:
        if normalized_job_id and (snapshot.get("job_id") or "").strip() != normalized_job_id:
            continue
        if normalized_phase and (snapshot.get("phase") or "").strip().lower() != normalized_phase:
            continue
        items.append(snapshot)
        if len(items) >= safe_limit:
            break

    if not items and normalized_job_id:
        record = get_job_record(normalized_job_id)
        if record:
            analysis_run = record.get("analysis_run") or {}
            for phase_name, result in (analysis_run.get("phase_results") or analysis_run.get("phases") or {}).items():
                if normalized_phase and phase_name.strip().lower() != normalized_phase:
                    continue
                items.append({
                    "job_id": normalized_job_id,
                    "request_id": record.get("request_id") or "",
                    "created_at": record.get("completed_at") or record.get("created_at") or "",
                    "target_url": record.get("target_url") or "",
                    "phase": phase_name,
                    "result": result,
                    "input_context": analysis_run.get("input_context") or {},
                })

    return {
        "job_id": normalized_job_id,
        "request_id": (items[0].get("request_id") if items else ""),
        "phase": normalized_phase,
        "count": len(items),
        "items": items[:safe_limit],
    }


def explain_analysis_run(job_id: str) -> dict:
    record = get_job_record(job_id)
    if not record:
        raise ValueError(f"History record '{job_id}' was not found.")
    return build_reasoning_summary(record)
