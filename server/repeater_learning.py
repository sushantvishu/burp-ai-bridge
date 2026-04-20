from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from server.knowledge_base import MEMORY_DIR, ensure_storage
from server.memory_partition import partition_from_payload
from server.negative_reasoning_memory import append_negative_reasoning
from server.persistence_redaction import redact_persisted_data
from server.settings import REPEATER_LEARNING_JSONL_MAX_RECORDS
from server.storage_protection import deserialize_jsonl_record, serialize_jsonl_record

REPEATER_LEARNING_PATH = MEMORY_DIR / "repeater_variant_learning.jsonl"


def learn_from_repeater_diff(payload_like, *, plan: dict[str, Any], diff_score: dict[str, Any]) -> Path | None:
    items = list(diff_score.get("ranked_items") or [])
    if not items:
        return None
    ensure_storage()
    payload_dict = _to_payload_dict(payload_like)
    path = urlparse(str(payload_dict.get("target_url") or "")).path or "/"
    vuln_classes = _plan_vuln_classes(plan)
    partition_key = partition_from_payload(payload_dict)
    entries = []
    for item in items[:8]:
        family = mutation_family(
            item.get("tab_name", ""),
            item.get("summary", ""),
            item.get("expected_signal", ""),
            item.get("request_ref", ""),
        )
        status_transition = str(item.get("status_transition") or "").strip()
        response_signature = "|".join(
            part for part in [
                status_transition,
                str(item.get("expected_signal") or "").strip(),
                ",".join(str(marker or "").strip() for marker in item.get("matched_markers", [])[:3]),
            ] if part
        )
        success = bool(item.get("high_signal")) or float(item.get("score", 0.0) or 0.0) >= 2.5
        entries.append({
            "created_at": _utc_now(),
            "request_id": payload_dict.get("request_id", ""),
            "snapshot_id": payload_dict.get("snapshot_id", ""),
            "target_url": payload_dict.get("target_url", ""),
            "normalized_path": _normalize_path(path),
            "memory_partition_key": partition_key,
            "vuln_classes": vuln_classes,
            "issue_id": item.get("issue_id", "") or (plan.get("dashboard_issue") or {}).get("issue_id", ""),
            "tab_name": item.get("tab_name", ""),
            "mutation_family": family,
            "expected_signal": item.get("expected_signal", ""),
            "status_transition": status_transition,
            "response_signature": response_signature,
            "auth_context": _auth_context(payload_dict),
            "score": float(item.get("score", 0.0) or 0.0),
            "high_signal": bool(item.get("high_signal")),
            "suggested_step_success": success,
            "label": "useful" if success else "low-value",
        })
        if not success:
            append_negative_reasoning(
                payload_dict,
                vuln_classes=vuln_classes,
                mutation_family=family,
                weak_assumption=f"{family} did not produce a strong enough delta for this target.",
                reason=str(item.get("summary") or item.get("expected_signal") or "Low-value mutation path."),
                score=float(item.get("score", 0.0) or 0.0),
                request_ref=str(item.get("request_ref") or ""),
                issue_id=str(item.get("issue_id") or (plan.get("dashboard_issue") or {}).get("issue_id", "")),
            )
    with REPEATER_LEARNING_PATH.open("a", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(serialize_jsonl_record(redact_persisted_data(entry)) + "\n")
    _prune(REPEATER_LEARNING_PATH, REPEATER_LEARNING_JSONL_MAX_RECORDS)
    return REPEATER_LEARNING_PATH


def summarize_repeater_learning(
    *,
    payload_like=None,
    vuln_classes: list[str] | None = None,
    limit: int = 5,
) -> dict[str, Any]:
    payload_dict = _to_payload_dict(payload_like or {})
    partition_key = partition_from_payload(payload_dict) if payload_dict else ""
    normalized_path = _normalize_path(urlparse(str(payload_dict.get("target_url") or "")).path or "/") if payload_dict else ""
    target_classes = {str(item or "").strip().lower() for item in (vuln_classes or []) if str(item or "").strip()}
    preferred = Counter()
    deprioritized = Counter()
    examples = []
    success_rates: dict[str, float] = {}
    family_totals: dict[str, int] = defaultdict(int)
    family_successes: dict[str, int] = defaultdict(int)
    for item in reversed(read_repeater_learning()):
        if partition_key and (item.get("memory_partition_key") or "").strip() != partition_key:
            continue
        if normalized_path and (item.get("normalized_path") or "") != normalized_path:
            continue
        item_classes = {str(entry or "").strip().lower() for entry in item.get("vuln_classes", []) or [] if str(entry or "").strip()}
        if target_classes and not (target_classes & item_classes):
            continue
        family = str(item.get("mutation_family") or "").strip()
        if not family:
            continue
        if item.get("label") == "useful":
            preferred[family] += 1
            family_successes[family] += 1
        else:
            deprioritized[family] += 1
        family_totals[family] += 1
        if len(examples) < max(1, limit):
            examples.append(item)
    for family, total in family_totals.items():
        success_rates[family] = round(family_successes.get(family, 0) / max(1, total), 3)
    return {
        "preferred_families": [name for name, _ in preferred.most_common(4)],
        "deprioritized_families": [name for name, _ in deprioritized.most_common(4)],
        "success_rates": success_rates,
        "examples": examples,
        "summary": _learning_summary(preferred, deprioritized),
    }


def read_repeater_learning(limit: int | None = None) -> list[dict[str, Any]]:
    ensure_storage()
    if not REPEATER_LEARNING_PATH.exists():
        return []
    lines = REPEATER_LEARNING_PATH.read_text(encoding="utf-8").splitlines()
    if limit is not None:
        lines = lines[-limit:]
    results = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        payload = deserialize_jsonl_record(line)
        if payload:
            results.append(payload)
    return results


def mutation_family(tab_name: str, summary: str, expected_signal: str, request_ref: str = "") -> str:
    haystack = " ".join([tab_name or "", summary or "", expected_signal or "", request_ref or ""]).lower()
    checks = [
        ("authorization-boundary", ("403", "401", "tenant", "role", "idor", "object")),
        ("render-context", ("render", "viewer", "sink", "xss", "marker")),
        ("parser-structure", ("xml", "doctype", "entity", "parser", "xxe", "json")),
        ("session-state", ("cookie", "session", "logout", "login", "auth")),
        ("header-routing", ("header", "host", "cache", "smuggling", "forwarded")),
    ]
    for family, tokens in checks:
        if any(token in haystack for token in tokens):
            return family
    normalized = re.sub(r"[^a-z0-9]+", "-", haystack).strip("-")
    return normalized[:32] or "general-variation"


def _plan_vuln_classes(plan: dict[str, Any]) -> list[str]:
    classes = []
    dashboard_issue = plan.get("dashboard_issue") or {}
    for candidate in [
        dashboard_issue.get("vuln_hint", ""),
        *((item.get("vuln_hint", "") for item in plan.get("related_scanner_issues", []) or [])),
    ]:
        normalized = str(candidate or "").strip().lower()
        if normalized and normalized not in classes:
            classes.append(normalized)
    return classes or ["general"]


def _learning_summary(preferred: Counter, deprioritized: Counter) -> str:
    if not preferred and not deprioritized:
        return "No prior Repeater-variant learning matched this target partition yet."
    parts = []
    if preferred:
        parts.append("preferred families: " + ", ".join(name for name, _ in preferred.most_common(3)))
    if deprioritized:
        parts.append("deprioritized families: " + ", ".join(name for name, _ in deprioritized.most_common(3)))
    return "; ".join(parts) + "."


def _auth_context(payload_dict: dict[str, Any]) -> str:
    if payload_dict.get("custom_headers_text") or payload_dict.get("raw_request", "").lower().count("cookie:"):
        return "cookie-or-header-auth"
    if payload_dict.get("http_method", "").upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        return "state-changing"
    return "anonymous-or-unknown"


def _to_payload_dict(payload_like) -> dict[str, Any]:
    if isinstance(payload_like, dict):
        return dict(payload_like)
    if hasattr(payload_like, "model_dump"):
        return payload_like.model_dump()
    if hasattr(payload_like, "dict"):
        return payload_like.dict()
    return dict(vars(payload_like))


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
