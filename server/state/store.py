import json
from datetime import datetime, timezone
from pathlib import Path

from server.knowledge_base import MEMORY_DIR, ensure_storage
from server.memory_partition import partition_from_payload
from server.persistence_redaction import redact_persisted_data
from server.settings import (
    ANALYSIS_RUN_STATE_JSONL_MAX_RECORDS,
    BURP_SESSION_SNAPSHOT_JSONL_MAX_RECORDS,
    HYPOTHESIS_STATE_JSONL_MAX_RECORDS,
    ISSUE_WORKFLOW_STATE_JSONL_MAX_RECORDS,
    PHASE_SNAPSHOT_JSONL_MAX_RECORDS,
    PROVIDER_DIAGNOSTICS_JSONL_MAX_RECORDS,
    REVIEW_DATASET_JSONL_MAX_RECORDS,
    REPEATER_LEARNING_JSONL_MAX_RECORDS,
    STATE_JSONL_MAX_RECORDS,
)
from server.storage_protection import deserialize_jsonl_record, serialize_jsonl_record

HYPOTHESIS_STATE_PATH = MEMORY_DIR / "hypothesis_state.jsonl"
ANALYSIS_RUN_STATE_PATH = MEMORY_DIR / "analysis_run_state.jsonl"
PROVIDER_DIAGNOSTICS_PATH = MEMORY_DIR / "provider_diagnostics.jsonl"
PHASE_SNAPSHOT_PATH = MEMORY_DIR / "phase_snapshots.jsonl"
BURP_SESSION_SNAPSHOT_PATH = MEMORY_DIR / "burp_session_snapshots.jsonl"
ISSUE_WORKFLOW_STATE_PATH = MEMORY_DIR / "issue_workflow_state.jsonl"
ALLOWED_HYPOTHESIS_STATUSES = {"suspected", "confirmed", "discarded", "needs-review"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_hypothesis_transition(job_id: str, hypothesis_id: str, status: str, notes: str = "") -> Path:
    normalized_status = (status or "").strip().lower()
    if normalized_status not in ALLOWED_HYPOTHESIS_STATUSES:
        allowed = ", ".join(sorted(ALLOWED_HYPOTHESIS_STATUSES))
        raise ValueError(f"Unsupported hypothesis status. Use one of: {allowed}")

    ensure_storage()
    entry = {
        "job_id": (job_id or "").strip(),
        "hypothesis_id": (hypothesis_id or "").strip(),
        "status": normalized_status,
        "notes": (notes or "").strip(),
        "created_at": _utc_now(),
    }
    _append_jsonl_entries(HYPOTHESIS_STATE_PATH, [entry])
    return HYPOTHESIS_STATE_PATH


def read_hypothesis_transitions(limit: int | None = None) -> list[dict]:
    ensure_storage()
    if not HYPOTHESIS_STATE_PATH.exists():
        return []

    lines = HYPOTHESIS_STATE_PATH.read_text(encoding="utf-8").splitlines()
    if limit is not None:
        lines = lines[-limit:]

    records = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def append_analysis_snapshot(record: dict) -> Path | None:
    if not isinstance(record, dict):
        return None
    analysis_run = record.get("analysis_run")
    if not isinstance(analysis_run, dict):
        return None

    ensure_storage()
    promoted_hypotheses = _promoted_hypotheses(analysis_run.get("hypotheses") or [])
    promoted_evidence = _promoted_evidence(analysis_run.get("evidence") or [])
    entry = {
        "job_id": (record.get("job_id") or "").strip(),
        "request_id": (record.get("request_id") or "").strip(),
        "created_at": (record.get("completed_at") or record.get("created_at") or _utc_now()),
        "target_url": record.get("target_url") or "",
        "http_method": record.get("http_method") or "",
        "memory_partition_key": record.get("memory_partition_key") or partition_from_payload(record),
        "input_context": analysis_run.get("input_context") or {
            "target_url": record.get("target_url") or "",
            "http_method": record.get("http_method") or "",
            "source_tool": record.get("source_tool") or "",
            "selected_profile": record.get("selected_profile") or "",
        },
        "phase_results": analysis_run.get("phase_results") or analysis_run.get("phases") or {},
        "hypotheses": promoted_hypotheses,
        "evidence": promoted_evidence,
        "memory_promotion": record.get("memory_promotion") or {},
    }
    _append_jsonl_entries(ANALYSIS_RUN_STATE_PATH, [entry])
    return ANALYSIS_RUN_STATE_PATH


def read_analysis_snapshots(limit: int | None = None) -> list[dict]:
    return _read_jsonl(ANALYSIS_RUN_STATE_PATH, limit=limit)


def append_provider_diagnostics(record: dict) -> Path | None:
    if not isinstance(record, dict):
        return None
    analysis_run = record.get("analysis_run")
    if not isinstance(analysis_run, dict):
        return None

    ensure_storage()
    entry = {
        "job_id": (record.get("job_id") or "").strip(),
        "request_id": (record.get("request_id") or "").strip(),
        "created_at": (record.get("completed_at") or record.get("created_at") or _utc_now()),
        "target_url": record.get("target_url") or "",
        "memory_partition_key": record.get("memory_partition_key") or partition_from_payload(record),
        "status": record.get("status") or "",
        "analysis_backend": ((record.get("result") or {}).get("analysis_backend") or ""),
        "fallback_used": bool((record.get("result") or {}).get("fallback_used")),
        "fallback_reason": analysis_run.get("fallback_reason") or "",
        "provider_trace": analysis_run.get("provider_trace") or [],
        "provider_failover": ((record.get("result") or {}).get("provider_failover") or {}),
    }
    _append_jsonl_entries(PROVIDER_DIAGNOSTICS_PATH, [entry])
    return PROVIDER_DIAGNOSTICS_PATH


def read_provider_diagnostics(limit: int | None = None) -> list[dict]:
    return _read_jsonl(PROVIDER_DIAGNOSTICS_PATH, limit=limit)


def append_phase_snapshots(record: dict) -> Path | None:
    if not isinstance(record, dict):
        return None
    analysis_run = record.get("analysis_run")
    if not isinstance(analysis_run, dict):
        return None

    phase_results = analysis_run.get("phase_results") or analysis_run.get("phases") or {}
    if not isinstance(phase_results, dict) or not phase_results:
        return None

    ensure_storage()
    created_at = record.get("completed_at") or record.get("created_at") or _utc_now()
    job_id = (record.get("job_id") or "").strip()
    target_url = record.get("target_url") or ""
    input_context = analysis_run.get("input_context") or {}
    entries = []
    for phase_name, phase_result in phase_results.items():
        entries.append({
            "job_id": job_id,
            "request_id": (record.get("request_id") or "").strip(),
            "created_at": created_at,
            "target_url": target_url,
            "memory_partition_key": record.get("memory_partition_key") or partition_from_payload(record),
            "phase": (phase_name or "").strip(),
            "result": phase_result if isinstance(phase_result, dict) else {"value": phase_result},
            "input_context": input_context,
            "memory_promotion": record.get("memory_promotion") or {},
        })
    _append_jsonl_entries(PHASE_SNAPSHOT_PATH, entries)
    return PHASE_SNAPSHOT_PATH


def read_phase_snapshots(limit: int | None = None) -> list[dict]:
    return _read_jsonl(PHASE_SNAPSHOT_PATH, limit=limit)


def append_burp_session_snapshot(snapshot: dict) -> Path | None:
    if not isinstance(snapshot, dict):
        return None
    ensure_storage()
    entry = dict(snapshot)
    entry.setdefault("memory_partition_key", partition_from_payload(entry))
    _append_jsonl_entries(BURP_SESSION_SNAPSHOT_PATH, [entry])
    return BURP_SESSION_SNAPSHOT_PATH


def read_burp_session_snapshots(limit: int | None = None) -> list[dict]:
    return _read_jsonl(BURP_SESSION_SNAPSHOT_PATH, limit=limit)


def get_burp_session_snapshot(snapshot_id: str) -> dict | None:
    normalized = (snapshot_id or "").strip()
    if not normalized:
        return None
    for record in read_burp_session_snapshots():
        if (record.get("snapshot_id") or "").strip() == normalized:
            return record
    return None


def append_issue_workflow_state(record: dict) -> Path | None:
    if not isinstance(record, dict):
        return None
    ensure_storage()
    entry = dict(record)
    entry.setdefault("updated_at", _utc_now())
    entry.setdefault("memory_partition_key", partition_from_payload(entry))
    _append_jsonl_entries(ISSUE_WORKFLOW_STATE_PATH, [entry])
    return ISSUE_WORKFLOW_STATE_PATH


def read_issue_workflow_states(limit: int | None = None) -> list[dict]:
    return _read_jsonl(ISSUE_WORKFLOW_STATE_PATH, limit=limit)


def get_issue_workflow_state(*, workflow_id: str = "", issue_id: str = "", snapshot_id: str = "") -> dict | None:
    normalized_workflow_id = (workflow_id or "").strip()
    normalized_issue_id = (issue_id or "").strip()
    normalized_snapshot_id = (snapshot_id or "").strip()
    for record in reversed(read_issue_workflow_states()):
        if normalized_workflow_id and (record.get("workflow_id") or "").strip() == normalized_workflow_id:
            return record
        if normalized_issue_id and (record.get("issue_id") or "").strip() == normalized_issue_id:
            return record
        if normalized_snapshot_id and (record.get("snapshot_id") or "").strip() == normalized_snapshot_id:
            return record
    return None


def latest_hypothesis_state_map() -> dict[tuple[str, str], dict]:
    latest: dict[tuple[str, str], dict] = {}
    for entry in read_hypothesis_transitions():
        job_id = (entry.get("job_id") or "").strip()
        hypothesis_id = (entry.get("hypothesis_id") or "").strip()
        if not job_id or not hypothesis_id:
            continue
        latest[(job_id, hypothesis_id)] = entry
    return latest


def apply_hypothesis_state(record: dict, latest: dict[tuple[str, str], dict] | None = None) -> dict:
    if not isinstance(record, dict):
        return record

    analysis_run = record.get("analysis_run")
    if not isinstance(analysis_run, dict):
        return dict(record)

    hypotheses = analysis_run.get("hypotheses")
    if not isinstance(hypotheses, list) or not hypotheses:
        return dict(record)

    latest = latest if latest is not None else latest_hypothesis_state_map()
    job_id = (record.get("job_id") or "").strip()
    if not job_id:
        return dict(record)

    enriched_record = dict(record)
    enriched_run = dict(analysis_run)
    enriched_hypotheses = []
    updated_any = False

    for hypothesis in hypotheses:
        if not isinstance(hypothesis, dict):
            enriched_hypotheses.append(hypothesis)
            continue
        enriched_hypothesis = dict(hypothesis)
        transition = latest.get((job_id, (hypothesis.get("id") or "").strip()))
        if transition:
            updated_any = True
            enriched_hypothesis["status"] = transition.get("status") or enriched_hypothesis.get("status") or "suspected"
            enriched_hypothesis["status_notes"] = transition.get("notes", "")
            enriched_hypothesis["status_updated_at"] = transition.get("created_at", "")
        enriched_hypotheses.append(enriched_hypothesis)

    if updated_any:
        enriched_run["hypotheses"] = enriched_hypotheses
        enriched_record["analysis_run"] = enriched_run
    return enriched_record


def _promoted_hypotheses(hypotheses: list[dict]) -> list[dict]:
    promoted: list[dict] = []
    for item in hypotheses:
        if not isinstance(item, dict):
            continue
        status = (item.get("status") or "suspected").strip().lower()
        try:
            confidence = float(item.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        if status == "confirmed" or confidence >= 0.78:
            promoted.append(item)
    if not promoted and hypotheses:
        first = hypotheses[0]
        if isinstance(first, dict):
            promoted.append(first)
    return promoted[:6]


def _promoted_evidence(evidence: list[dict]) -> list[dict]:
    promoted: list[dict] = []
    for item in evidence:
        if not isinstance(item, dict):
            continue
        summary = str(item.get("summary") or "").strip()
        if not summary:
            continue
        if _looks_like_noisy_scanner_blob(summary):
            continue
        confidence = float(item.get("confidence") or 0.0)
        evidence_type = (item.get("evidence_type") or "").strip().lower()
        source = (item.get("source") or "").strip().lower()
        if confidence >= 0.7 or evidence_type in {"role-compare", "manual-diff", "timeline", "callback"}:
            compact = dict(item)
            compact["summary"] = summary[:280]
            compact["source"] = source
            promoted.append(compact)
    if not promoted and evidence:
        first = evidence[0]
        if isinstance(first, dict):
            compact = dict(first)
            compact["summary"] = str(compact.get("summary") or "")[:280]
            promoted.append(compact)
    return promoted[:8]


def _looks_like_noisy_scanner_blob(text: str) -> bool:
    normalized = (text or "").strip().lower()
    if not normalized:
        return False
    markers = (
        "auto-collected burp audit issues",
        "requestresponses",
        "scanner request",
        "oastify.com",
    )
    if any(marker in normalized for marker in markers):
        return True
    return len(normalized) > 1200


def _read_jsonl(path: Path, limit: int | None = None) -> list[dict]:
    ensure_storage()
    if not path.exists():
        return []

    lines = path.read_text(encoding="utf-8").splitlines()
    if limit is not None:
        lines = lines[-limit:]

    records = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            payload = deserialize_jsonl_record(line)
        except Exception:
            payload = None
        if not payload:
            continue
        records.append(payload)
    return records


def _append_jsonl_entries(path: Path, entries: list[dict]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(serialize_jsonl_record(redact_persisted_data(entry)) + "\n")
    _prune_jsonl(path, _max_records_for_path(path))


def _prune_jsonl(path: Path, max_records: int) -> None:
    if max_records <= 0 or not path.exists():
        return

    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) <= max_records:
        return

    retained = lines[-max_records:]
    path.write_text(("\n".join(retained) + "\n") if retained else "", encoding="utf-8")


def _max_records_for_path(path: Path) -> int:
    normalized = path.resolve()
    mapping = {
        HYPOTHESIS_STATE_PATH.resolve(): HYPOTHESIS_STATE_JSONL_MAX_RECORDS,
        ANALYSIS_RUN_STATE_PATH.resolve(): ANALYSIS_RUN_STATE_JSONL_MAX_RECORDS,
        PROVIDER_DIAGNOSTICS_PATH.resolve(): PROVIDER_DIAGNOSTICS_JSONL_MAX_RECORDS,
        PHASE_SNAPSHOT_PATH.resolve(): PHASE_SNAPSHOT_JSONL_MAX_RECORDS,
        BURP_SESSION_SNAPSHOT_PATH.resolve(): BURP_SESSION_SNAPSHOT_JSONL_MAX_RECORDS,
        ISSUE_WORKFLOW_STATE_PATH.resolve(): ISSUE_WORKFLOW_STATE_JSONL_MAX_RECORDS,
    }
    return mapping.get(normalized, STATE_JSONL_MAX_RECORDS)
