from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from server.core.reference_enrichment_service import normalize_vuln_class
from server.knowledge_base import MEMORY_DIR, ensure_storage
from server.memory_partition import partition_from_payload
from server.negative_reasoning_memory import append_negative_reasoning
from server.persistence_redaction import redact_persisted_data
from server.settings import REVIEW_DATASET_JSONL_MAX_RECORDS
from server.storage_protection import deserialize_jsonl_record, serialize_jsonl_record

BCHECK_RESULT_PATH = MEMORY_DIR / "bcheck_results.jsonl"
BCHECK_RESULT_WEIGHTS = {
    "true_positive": 3,
    "useful": 2,
    "neutral": 0,
    "not_useful": -2,
    "false_positive": -3,
}
BCHECK_RESULT_LABEL_ALIASES = {
    "high-signal": "true_positive",
    "high_signal": "true_positive",
    "false-positive": "false_positive",
    "not-useful": "not_useful",
}


def normalize_bcheck_result_label(label: str) -> str:
    normalized = (label or "").strip().lower().replace(" ", "_")
    normalized = BCHECK_RESULT_LABEL_ALIASES.get(normalized, normalized)
    return normalized if normalized in BCHECK_RESULT_WEIGHTS else ""


def append_bcheck_result(
    payload_like,
    *,
    selected_bcheck: dict[str, Any],
    outcome_label: str,
    notes: str = "",
    evidence_signal: str = "",
    issue_id: str = "",
) -> Path | None:
    payload = _to_payload_dict(payload_like)
    normalized_label = normalize_bcheck_result_label(outcome_label)
    if not normalized_label:
        allowed = ", ".join(sorted(BCHECK_RESULT_WEIGHTS))
        raise ValueError(f"Unsupported BCheck result label. Use one of: {allowed}")

    bcheck_id = str(selected_bcheck.get("relative_path") or selected_bcheck.get("id") or "").strip()
    if not bcheck_id:
        raise ValueError("selected_bcheck must include a relative_path or id.")

    ensure_storage()
    partition_key = partition_from_payload(payload)
    vuln_class = normalize_vuln_class(
        selected_bcheck.get("selected_for_vuln_class")
        or selected_bcheck.get("vuln_class")
        or _payload_vuln_class(payload)
        or "general"
    )
    normalized_path = _normalize_path(urlparse(str(payload.get("target_url") or "")).path or "/")
    resolved_issue_id = (issue_id or payload.get("burp_dashboard_issue", {}).get("issue_id") or "").strip()
    entry = {
        "created_at": _utc_now(),
        "request_id": payload.get("request_id", ""),
        "snapshot_id": payload.get("snapshot_id", ""),
        "target_url": payload.get("target_url", ""),
        "normalized_path": normalized_path,
        "memory_partition_key": partition_key,
        "issue_id": resolved_issue_id,
        "issue_family_key": issue_family_key(
            partition_key=partition_key,
            issue_id=resolved_issue_id,
            normalized_path=normalized_path,
            vuln_class=vuln_class,
        ),
        "vuln_classes": [vuln_class],
        "bcheck_id": bcheck_id,
        "bcheck_name": str(selected_bcheck.get("name") or "").strip(),
        "relative_path": str(selected_bcheck.get("relative_path") or "").strip(),
        "source_url": str(selected_bcheck.get("source_url") or "").strip(),
        "scan_mode": str(selected_bcheck.get("scan_mode") or "").strip(),
        "requires_collaborator": bool(selected_bcheck.get("requires_collaborator")),
        "usage_hint": str(selected_bcheck.get("usage_hint") or "").strip(),
        "why": str(selected_bcheck.get("why") or "").strip(),
        "score": float(selected_bcheck.get("score", 0.0) or 0.0),
        "outcome_label": normalized_label,
        "notes": (notes or "").strip(),
        "evidence_signal": (evidence_signal or "").strip(),
    }
    with BCHECK_RESULT_PATH.open("a", encoding="utf-8") as handle:
        handle.write(serialize_jsonl_record(redact_persisted_data(entry)) + "\n")
    _prune(BCHECK_RESULT_PATH, max(200, int(REVIEW_DATASET_JSONL_MAX_RECORDS or 1000)))

    if BCHECK_RESULT_WEIGHTS[normalized_label] < 0:
        append_negative_reasoning(
            payload,
            vuln_classes=[vuln_class],
            mutation_family=f"bcheck:{bcheck_id}",
            weak_assumption=f"{entry['bcheck_name'] or bcheck_id} produced low-value or false-positive signal for this issue family.",
            reason=entry["notes"] or entry["evidence_signal"] or "The imported BCheck did not improve the bounded proof path.",
            score=float(entry.get("score", 0.0) or 0.0),
            issue_id=resolved_issue_id,
        )
    return BCHECK_RESULT_PATH


def read_bcheck_results(limit: int | None = None) -> list[dict[str, Any]]:
    ensure_storage()
    if not BCHECK_RESULT_PATH.exists():
        return []
    lines = BCHECK_RESULT_PATH.read_text(encoding="utf-8").splitlines()
    if limit is not None:
        lines = lines[-limit:]
    results: list[dict[str, Any]] = []
    for line in lines:
        payload = deserialize_jsonl_record(line.strip())
        if payload:
            results.append(payload)
    return results


def summarize_bcheck_learning(
    *,
    payload_like=None,
    issue_id: str = "",
    vuln_classes: list[str] | None = None,
    limit: int = 5,
) -> dict[str, Any]:
    payload = _to_payload_dict(payload_like or {})
    partition_key = partition_from_payload(payload) if payload else ""
    normalized_path = _normalize_path(urlparse(str(payload.get("target_url") or "")).path or "/") if payload else ""
    target_classes = {normalize_vuln_class(item) for item in (vuln_classes or []) if item}
    family_key = issue_family_key(
        partition_key=partition_key,
        issue_id=(issue_id or payload.get("burp_dashboard_issue", {}).get("issue_id") or "").strip(),
        normalized_path=normalized_path,
        vuln_class=next(iter(target_classes), "general"),
    )

    preferred = Counter()
    suppressed = Counter()
    examples: list[dict[str, Any]] = []
    score_by_bcheck: dict[str, int] = {}
    for entry in reversed(read_bcheck_results(limit=1200)):
        if partition_key and (entry.get("memory_partition_key") or "").strip() != partition_key:
            continue
        if issue_id and (entry.get("issue_id") or "").strip() != issue_id.strip():
            continue
        if not issue_id and family_key and (entry.get("issue_family_key") or "").strip() != family_key:
            continue
        entry_classes = {normalize_vuln_class(item) for item in entry.get("vuln_classes", []) or [] if item}
        if target_classes and not (target_classes & entry_classes):
            continue
        bcheck_id = str(entry.get("bcheck_id") or "").strip()
        label = normalize_bcheck_result_label(entry.get("outcome_label") or "")
        if not bcheck_id or not label:
            continue
        weight = BCHECK_RESULT_WEIGHTS[label]
        score_by_bcheck[bcheck_id] = score_by_bcheck.get(bcheck_id, 0) + weight
        if weight > 0:
            preferred[bcheck_id] += 1
        if weight < 0:
            suppressed[bcheck_id] += 1
        if len(examples) < max(1, limit):
            examples.append(entry)

    return {
        "issue_family_key": family_key,
        "preferred_bcheck_ids": [name for name, _ in preferred.most_common(4)],
        "suppressed_bcheck_ids": [name for name, _ in suppressed.most_common(4)],
        "score_by_bcheck": score_by_bcheck,
        "examples": examples,
        "summary": _summary(preferred, suppressed),
    }


def issue_family_key(*, partition_key: str, issue_id: str, normalized_path: str, vuln_class: str) -> str:
    if (issue_id or "").strip():
        return f"{partition_key}|issue:{issue_id.strip()}"
    return f"{partition_key}|path:{normalized_path}|class:{normalize_vuln_class(vuln_class or 'general')}"


def _summary(preferred: Counter, suppressed: Counter) -> str:
    if not preferred and not suppressed:
        return "No prior official BCheck history matched this issue family."
    parts = []
    if preferred:
        parts.append("preferred official checks: " + ", ".join(name for name, _ in preferred.most_common(3)))
    if suppressed:
        parts.append("suppressed checks: " + ", ".join(name for name, _ in suppressed.most_common(3)))
    return "; ".join(parts) + "."


def _payload_vuln_class(payload: dict[str, Any]) -> str:
    issue = payload.get("burp_dashboard_issue") or {}
    return str(issue.get("vuln_hint") or issue.get("name") or "").strip().lower()


def _to_payload_dict(payload_like) -> dict[str, Any]:
    if isinstance(payload_like, dict):
        return dict(payload_like)
    if hasattr(payload_like, "model_dump"):
        return payload_like.model_dump()
    if hasattr(payload_like, "dict"):
        return payload_like.dict()
    return dict(vars(payload_like)) if payload_like is not None else {}


def _normalize_path(path: str) -> str:
    parts = []
    for item in str(path or "/").split("/"):
        lowered = item.strip().lower()
        if not lowered:
            continue
        parts.append("{id}" if lowered.isdigit() else lowered)
    return "/" + "/".join(parts)


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
