from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from server.core.reference_enrichment_service import normalize_vuln_class
from server.knowledge_base import MEMORY_DIR, ensure_storage
from server.memory_partition import partition_from_payload
from server.persistence_redaction import redact_persisted_data
from server.settings import REVIEW_DATASET_JSONL_MAX_RECORDS
from server.storage_protection import deserialize_jsonl_record, serialize_jsonl_record

BURP_ASSET_FEEDBACK_PATH = MEMORY_DIR / "burp_asset_feedback.jsonl"

ASSET_FEEDBACK_WEIGHTS = {
    "true_positive": 3,
    "useful": 2,
    "neutral": 0,
    "not_useful": -2,
    "noisy": -2,
    "false_positive": -3,
}

ASSET_FEEDBACK_LABEL_ALIASES = {
    "high-signal": "true_positive",
    "high_signal": "true_positive",
    "false-positive": "false_positive",
    "not-useful": "not_useful",
}


def normalize_asset_feedback_label(label: str) -> str:
    normalized = (label or "").strip().lower().replace(" ", "_")
    normalized = ASSET_FEEDBACK_LABEL_ALIASES.get(normalized, normalized)
    return normalized if normalized in ASSET_FEEDBACK_WEIGHTS else ""


def append_asset_feedback(
    *,
    asset_type: str,
    asset_id: str,
    label: str,
    target_url: str = "",
    vuln_class: str = "",
    selected_profile: str = "",
    program_platform: str = "",
    program_policy_template: str = "",
    notes: str = "",
    job_id: str = "",
    request_id: str = "",
) -> dict[str, Any]:
    normalized_label = normalize_asset_feedback_label(label)
    if not normalized_label:
        allowed = ", ".join(sorted(ASSET_FEEDBACK_WEIGHTS))
        raise ValueError(f"Unsupported asset feedback label. Use one of: {allowed}")

    normalized_asset_type = (asset_type or "").strip().lower()
    normalized_asset_id = (asset_id or "").strip()
    if normalized_asset_type not in {"custom_scan_check", "bambda"}:
        raise ValueError("asset_type must be 'custom_scan_check' or 'bambda'.")
    if not normalized_asset_id:
        raise ValueError("asset_id is required.")

    payload = {
        "asset_type": normalized_asset_type,
        "asset_id": normalized_asset_id,
        "label": normalized_label,
        "target_url": (target_url or "").strip(),
        "vuln_class": normalize_vuln_class(vuln_class or "general"),
        "selected_profile": (selected_profile or "").strip(),
        "program_platform": (program_platform or "").strip(),
        "program_policy_template": (program_policy_template or "").strip(),
        "memory_partition_key": partition_from_payload(
            {
                "target_url": target_url,
                "selected_profile": selected_profile,
                "program_platform": program_platform,
                "program_policy_template": program_policy_template,
            }
        ),
        "job_id": (job_id or "").strip(),
        "request_id": (request_id or "").strip(),
        "notes": (notes or "").strip(),
        "created_at": _utc_now(),
    }
    ensure_storage()
    with BURP_ASSET_FEEDBACK_PATH.open("a", encoding="utf-8") as handle:
        handle.write(serialize_jsonl_record(redact_persisted_data(payload)) + "\n")
    _prune(BURP_ASSET_FEEDBACK_PATH, max(200, int(REVIEW_DATASET_JSONL_MAX_RECORDS or 1000)))
    return payload


def read_asset_feedback(limit: int | None = None) -> list[dict[str, Any]]:
    ensure_storage()
    if not BURP_ASSET_FEEDBACK_PATH.exists():
        return []
    lines = BURP_ASSET_FEEDBACK_PATH.read_text(encoding="utf-8").splitlines()
    if limit is not None:
        lines = lines[-limit:]
    results: list[dict[str, Any]] = []
    for line in lines:
        value = deserialize_jsonl_record(line.strip())
        if isinstance(value, dict):
            results.append(value)
    return results


def asset_feedback_scores(
    *,
    partition_key: str = "",
    vuln_class: str = "",
    asset_type: str = "",
) -> dict[str, dict[str, Any]]:
    normalized_partition = (partition_key or "").strip()
    normalized_class = normalize_vuln_class(vuln_class or "")
    normalized_type = (asset_type or "").strip().lower()
    scores: dict[str, dict[str, Any]] = {}
    for entry in read_asset_feedback(limit=1000):
        entry_type = (entry.get("asset_type") or "").strip().lower()
        entry_id = (entry.get("asset_id") or "").strip()
        if normalized_type and entry_type != normalized_type:
            continue
        if not entry_id:
            continue

        entry_class = normalize_vuln_class(entry.get("vuln_class") or "general")
        if normalized_class and entry_class not in {"general", normalized_class}:
            continue

        label = normalize_asset_feedback_label(entry.get("label") or "")
        if not label:
            continue
        weight = ASSET_FEEDBACK_WEIGHTS[label]
        current = scores.setdefault(
            entry_id,
            {
                "asset_id": entry_id,
                "asset_type": entry_type,
                "score": 0,
                "global_score": 0,
                "partition_score": 0,
                "class_score": 0,
                "positive_count": 0,
                "negative_count": 0,
                "labels": {},
            },
        )
        current["global_score"] += weight
        if normalized_partition and (entry.get("memory_partition_key") or "").strip() == normalized_partition:
            current["partition_score"] += weight
        if normalized_class and entry_class == normalized_class:
            current["class_score"] += weight
        current["labels"][label] = current["labels"].get(label, 0) + 1
        if weight > 0:
            current["positive_count"] += 1
        if weight < 0:
            current["negative_count"] += 1
        current["score"] = current["global_score"] + current["partition_score"] + current["class_score"]
    return scores


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
