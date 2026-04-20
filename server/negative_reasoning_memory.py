from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from server.knowledge_base import MEMORY_DIR, ensure_storage
from server.memory_partition import partition_from_payload
from server.persistence_redaction import redact_persisted_data
from server.storage_protection import deserialize_jsonl_record, serialize_jsonl_record

NEGATIVE_REASONING_PATH = MEMORY_DIR / "negative_reasoning_memory.jsonl"
NEGATIVE_REASONING_JSONL_MAX_RECORDS = 1200


def append_negative_reasoning(
    payload_like,
    *,
    vuln_classes: list[str] | None = None,
    mutation_family: str = "",
    weak_assumption: str = "",
    reason: str = "",
    score: float = 0.0,
    request_ref: str = "",
    issue_id: str = "",
) -> Path | None:
    payload = _to_payload_dict(payload_like)
    if not payload:
        return None
    ensure_storage()
    path = urlparse(str(payload.get("target_url") or "")).path or "/"
    entry = {
        "created_at": _utc_now(),
        "request_id": payload.get("request_id", ""),
        "snapshot_id": payload.get("snapshot_id", ""),
        "target_url": payload.get("target_url", ""),
        "normalized_path": _normalize_path(path),
        "memory_partition_key": partition_from_payload(payload),
        "vuln_classes": [str(item or "").strip().lower() for item in (vuln_classes or []) if str(item or "").strip()],
        "mutation_family": (mutation_family or "").strip(),
        "weak_assumption": (weak_assumption or "").strip(),
        "reason": (reason or "").strip(),
        "score": float(score or 0.0),
        "request_ref": (request_ref or "").strip(),
        "issue_id": (issue_id or "").strip(),
    }
    with NEGATIVE_REASONING_PATH.open("a", encoding="utf-8") as handle:
        handle.write(serialize_jsonl_record(redact_persisted_data(entry)) + "\n")
    _prune(NEGATIVE_REASONING_PATH, NEGATIVE_REASONING_JSONL_MAX_RECORDS)
    return NEGATIVE_REASONING_PATH


def read_negative_reasoning(limit: int | None = None) -> list[dict[str, Any]]:
    ensure_storage()
    if not NEGATIVE_REASONING_PATH.exists():
        return []
    lines = NEGATIVE_REASONING_PATH.read_text(encoding="utf-8").splitlines()
    if limit is not None:
        lines = lines[-limit:]
    results: list[dict[str, Any]] = []
    for line in lines:
        payload = deserialize_jsonl_record(line.strip())
        if payload:
            results.append(payload)
    return results


def summarize_negative_reasoning(
    *,
    payload_like=None,
    vuln_classes: list[str] | None = None,
    limit: int = 5,
) -> dict[str, Any]:
    payload = _to_payload_dict(payload_like or {})
    partition_key = partition_from_payload(payload) if payload else ""
    normalized_path = _normalize_path(urlparse(str(payload.get("target_url") or "")).path or "/") if payload else ""
    target_classes = {str(item or "").strip().lower() for item in (vuln_classes or []) if str(item or "").strip()}
    weak_assumptions: list[str] = []
    deprioritized_families: list[str] = []
    matched: list[dict[str, Any]] = []
    for item in reversed(read_negative_reasoning()):
        if partition_key and (item.get("memory_partition_key") or "").strip() != partition_key:
            continue
        if normalized_path and (item.get("normalized_path") or "") != normalized_path:
            continue
        item_classes = {str(entry or "").strip().lower() for entry in item.get("vuln_classes", []) or [] if str(entry or "").strip()}
        if target_classes and not (target_classes & item_classes):
            continue
        matched.append(item)
        family = (item.get("mutation_family") or "").strip()
        assumption = (item.get("weak_assumption") or item.get("reason") or "").strip()
        if family and family not in deprioritized_families:
            deprioritized_families.append(family)
        if assumption and assumption not in weak_assumptions:
            weak_assumptions.append(assumption)
        if len(matched) >= max(1, limit):
            break
    return {
        "count": len(matched),
        "deprioritized_families": deprioritized_families[:4],
        "weak_assumptions": weak_assumptions[:4],
        "examples": matched[:limit],
        "summary": _summary(matched, weak_assumptions, deprioritized_families),
    }


def _summary(items: list[dict[str, Any]], weak_assumptions: list[str], families: list[str]) -> str:
    if not items:
        return "No prior negative reasoning memory matched this target partition."
    parts = [f"Matched {len(items)} prior low-value or failed escalation attempt(s)."]
    if weak_assumptions:
        parts.append("Weak assumptions: " + "; ".join(weak_assumptions[:2]))
    if families:
        parts.append("Deprioritized families: " + ", ".join(families[:3]))
    return " ".join(parts)


def _normalize_path(path: str) -> str:
    parts = []
    for item in str(path or "/").split("/"):
        lowered = item.strip().lower()
        if not lowered:
            continue
        if lowered.isdigit():
            parts.append("{id}")
        else:
            parts.append(lowered)
    return "/" + "/".join(parts)


def _to_payload_dict(payload_like) -> dict[str, Any]:
    if isinstance(payload_like, dict):
        return dict(payload_like)
    if hasattr(payload_like, "model_dump"):
        return payload_like.model_dump()
    if hasattr(payload_like, "dict"):
        return payload_like.dict()
    return dict(vars(payload_like)) if payload_like is not None else {}


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
