from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from server.core.reference_enrichment_service import normalize_vuln_class
from server.knowledge_base import MEMORY_DIR, ensure_storage
from server.memory_partition import build_partition_key, partition_from_payload
from server.persistence_redaction import redact_persisted_data
from server.settings import REVIEW_DATASET_JSONL_MAX_RECORDS
from server.storage_protection import deserialize_jsonl_record, serialize_jsonl_record

REVIEW_DATASET_PATH = MEMORY_DIR / "review_dataset.jsonl"


def append_review_example(record: dict[str, Any]) -> Path | None:
    example = build_review_example(record)
    if not example:
        return None
    return append_review_dataset_entry(example)


def append_review_dataset_entry(example: dict[str, Any]) -> Path | None:
    normalized = normalize_review_example(example)
    if not normalized:
        return None
    ensure_storage()
    with REVIEW_DATASET_PATH.open("a", encoding="utf-8") as handle:
        handle.write(serialize_jsonl_record(redact_persisted_data(normalized)) + "\n")
    _prune(REVIEW_DATASET_PATH, REVIEW_DATASET_JSONL_MAX_RECORDS)
    return REVIEW_DATASET_PATH


def read_review_examples(limit: int | None = None) -> list[dict[str, Any]]:
    ensure_storage()
    if not REVIEW_DATASET_PATH.exists():
        return []
    lines = REVIEW_DATASET_PATH.read_text(encoding="utf-8").splitlines()
    if limit is not None:
        lines = lines[-limit:]
    results: list[dict[str, Any]] = []
    seen_job_ids: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        payload = deserialize_jsonl_record(line)
        if not payload:
            continue
        job_id = str(payload.get("job_id") or "").strip()
        if job_id and job_id in seen_job_ids:
            continue
        if job_id:
            seen_job_ids.add(job_id)
        results.append(payload)
    return results


def query_review_examples(
    *,
    vuln_classes: list[str] | None = None,
    partition_key: str = "",
    limit: int = 5,
) -> dict[str, Any]:
    normalized_classes = {str(item or "").strip().lower() for item in (vuln_classes or []) if str(item or "").strip()}
    normalized_partition = (partition_key or "").strip()
    matches: list[dict[str, Any]] = []
    for item in reversed(read_review_examples()):
        if normalized_partition and (item.get("memory_partition_key") or "").strip() != normalized_partition:
            continue
        item_classes = {str(entry or "").strip().lower() for entry in item.get("vuln_classes", []) or [] if str(entry or "").strip()}
        if normalized_classes and not (normalized_classes & item_classes):
            continue
        matches.append(item)
        if len(matches) >= max(1, limit):
            break
    return {
        "count": len(matches),
        "items": matches,
        "summary": _summary(matches),
    }


def build_review_example(record: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(record, dict) or record.get("status") != "completed":
        return None
    analysis_run = record.get("analysis_run") or {}
    result = record.get("result") or {}
    dashboard_issue = ((analysis_run.get("phases") or {}).get("ingest") or {}).get("dashboard_issue") or {}
    if not (dashboard_issue.get("found") or record.get("bapp_findings_text") or (analysis_run.get("hypotheses") or [])):
        return None
    vuln_classes = []
    for item in analysis_run.get("hypotheses") or []:
        vuln_class = str(item.get("vuln_class") or "").strip().lower()
        if vuln_class and vuln_class not in vuln_classes:
            vuln_classes.append(vuln_class)
    label = _label_for_record(record)
    return {
        "job_id": record.get("job_id", ""),
        "request_id": record.get("request_id", ""),
        "created_at": record.get("completed_at") or record.get("created_at") or _utc_now(),
        "target_url": record.get("target_url", ""),
        "http_method": record.get("http_method", ""),
        "memory_partition_key": partition_from_payload(record),
        "scanner_issue_name": dashboard_issue.get("issue_name", ""),
        "scanner_severity": dashboard_issue.get("severity", ""),
        "scanner_confidence": dashboard_issue.get("confidence", ""),
        "vuln_classes": vuln_classes,
        "validation_status": ((analysis_run.get("phases") or {}).get("validate") or {}).get("validation_status", ""),
        "reportable": bool(((analysis_run.get("phases") or {}).get("impact") or {}).get("reportable")),
        "business_impact_class": ((analysis_run.get("phases") or {}).get("impact") or {}).get("business_impact_class", ""),
        "evidence_count": len(analysis_run.get("evidence") or []),
        "hypothesis_count": len(analysis_run.get("hypotheses") or []),
        "outcome_label": label,
        "analysis_backend": result.get("analysis_backend", ""),
        "summary": (result.get("primary_next_action") or result.get("analysis") or "")[:220],
    }


def normalize_review_example(example: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(example, dict):
        return None
    vuln_classes = []
    for item in example.get("vuln_classes", []) or []:
        normalized = normalize_vuln_class(item)
        if normalized and normalized not in vuln_classes:
            vuln_classes.append(normalized)

    target_url = str(example.get("target_url", "") or "").strip()
    program_platform = str(example.get("program_platform", "") or example.get("platform", "") or "").strip()
    selected_profile = str(example.get("selected_profile", "") or "review-dataset").strip()
    memory_partition_key = str(example.get("memory_partition_key", "") or "").strip() or build_partition_key(
        target_url=target_url,
        program_platform=program_platform,
        selected_profile=selected_profile,
    )

    return {
        "job_id": str(example.get("job_id", "") or "").strip(),
        "request_id": str(example.get("request_id", "") or "").strip(),
        "created_at": str(example.get("created_at", "") or _utc_now()),
        "target_url": target_url,
        "http_method": str(example.get("http_method", "") or "").strip(),
        "memory_partition_key": memory_partition_key,
        "scanner_issue_name": str(example.get("scanner_issue_name", "") or "").strip(),
        "scanner_severity": str(example.get("scanner_severity", "") or "").strip(),
        "scanner_confidence": str(example.get("scanner_confidence", "") or "").strip(),
        "vuln_classes": vuln_classes,
        "validation_status": str(example.get("validation_status", "") or "").strip(),
        "reportable": bool(example.get("reportable")),
        "business_impact_class": str(example.get("business_impact_class", "") or "").strip(),
        "evidence_count": int(example.get("evidence_count") or 0),
        "hypothesis_count": int(example.get("hypothesis_count") or len(vuln_classes)),
        "outcome_label": str(example.get("outcome_label", "") or "scanner-review").strip(),
        "analysis_backend": str(example.get("analysis_backend", "") or "").strip(),
        "summary": str(example.get("summary", "") or "").strip()[:220],
        "program_platform": program_platform,
        "selected_profile": selected_profile,
        "source_file": str(example.get("source_file", "") or "").strip(),
    }


def _label_for_record(record: dict[str, Any]) -> str:
    result = record.get("result") or {}
    phases = (record.get("analysis_run") or {}).get("phases") or {}
    validate = phases.get("validate") or {}
    impact = phases.get("impact") or {}
    if (validate.get("validation_status") or "").strip().lower() == "confirmed" and bool(impact.get("reportable")):
        return "confirmed-reportable"
    if (validate.get("validation_status") or "").strip().lower() == "confirmed":
        return "confirmed-bounded"
    if bool(result.get("fallback_used")):
        return "fallback-review"
    return "scanner-review"


def _summary(items: list[dict[str, Any]]) -> str:
    if not items:
        return "No local review examples matched this target partition and vulnerability class."
    top = items[0]
    return (
        f"Matched {len(items)} local review example(s). "
        f"Most recent outcome: {top.get('outcome_label') or 'review'} for "
        f"{top.get('scanner_issue_name') or top.get('target_url') or 'stored finding'}."
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _prune(path: Path, max_records: int) -> None:
    if max_records <= 0 or not path.exists():
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) <= max_records:
        return
    retained = lines[-max_records:]
    path.write_text(("\n".join(retained) + "\n") if retained else "", encoding="utf-8")
