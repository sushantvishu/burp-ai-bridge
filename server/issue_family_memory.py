from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from server.bcheck_learning import issue_family_key, summarize_bcheck_learning
from server.memory_partition import partition_from_payload
from server.negative_reasoning_memory import summarize_negative_reasoning
from server.repeater_learning import summarize_repeater_learning
from server.review_dataset import query_review_examples


def summarize_issue_family_memory(
    payload_like,
    *,
    issue_id: str = "",
    vuln_classes: list[str] | None = None,
) -> dict[str, Any]:
    partition_key = partition_from_payload(payload_like)
    normalized_classes = [str(item or "").strip().lower() for item in (vuln_classes or []) if str(item or "").strip()] or ["general"]
    bcheck_learning = summarize_bcheck_learning(
        payload_like=payload_like,
        issue_id=issue_id,
        vuln_classes=normalized_classes,
    )
    repeater_learning = summarize_repeater_learning(
        payload_like=payload_like,
        vuln_classes=normalized_classes,
    )
    negative_reasoning = summarize_negative_reasoning(
        payload_like=payload_like,
        vuln_classes=normalized_classes,
    )
    review_examples = query_review_examples(
        vuln_classes=normalized_classes,
        partition_key=partition_key,
        limit=3,
    )
    return {
        "issue_family_key": bcheck_learning.get("issue_family_key")
        or issue_family_key(
            partition_key=partition_key,
            issue_id=issue_id,
            normalized_path=_normalized_path(payload_like),
            vuln_class=normalized_classes[0],
        ),
        "memory_partition_key": partition_key,
        "preferred_bcheck_ids": bcheck_learning.get("preferred_bcheck_ids", []),
        "suppressed_bcheck_ids": bcheck_learning.get("suppressed_bcheck_ids", []),
        "preferred_mutation_families": repeater_learning.get("preferred_families", []),
        "deprioritized_mutation_families": repeater_learning.get("deprioritized_families", []),
        "negative_reasoning_count": int(negative_reasoning.get("count", 0) or 0),
        "review_example_count": int(review_examples.get("count", 0) or 0),
        "bcheck_learning_summary": bcheck_learning,
        "repeater_learning_summary": repeater_learning,
        "negative_reasoning_summary": negative_reasoning,
        "review_dataset_summary": review_examples.get("summary", ""),
        "summary": _summary(bcheck_learning, repeater_learning, negative_reasoning, review_examples),
    }


def _summary(
    bcheck_learning: dict[str, Any],
    repeater_learning: dict[str, Any],
    negative_reasoning: dict[str, Any],
    review_examples: dict[str, Any],
) -> str:
    parts = []
    if bcheck_learning.get("preferred_bcheck_ids"):
        parts.append("Preferred official BChecks: " + ", ".join(bcheck_learning["preferred_bcheck_ids"][:2]))
    if repeater_learning.get("preferred_families"):
        parts.append("Preferred mutation families: " + ", ".join(repeater_learning["preferred_families"][:2]))
    if negative_reasoning.get("count"):
        parts.append(f"Prior low-value branches: {negative_reasoning['count']}")
    if review_examples.get("count"):
        parts.append(f"Local review examples: {review_examples['count']}")
    return " | ".join(parts) if parts else "No issue-family memory matched this issue yet."


def _normalized_path(payload_like) -> str:
    target_url = ""
    if isinstance(payload_like, dict):
        target_url = str(payload_like.get("target_url") or "")
    elif hasattr(payload_like, "target_url"):
        target_url = str(getattr(payload_like, "target_url") or "")
    raw_path = urlparse(target_url).path or "/"
    parts = []
    for item in raw_path.split("/"):
        lowered = item.strip().lower()
        if not lowered:
            continue
        parts.append("{id}" if lowered.isdigit() else lowered)
    return "/" + "/".join(parts)
