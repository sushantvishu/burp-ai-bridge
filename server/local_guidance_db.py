import json
from pathlib import Path
from typing import Any

from server.core.reference_enrichment_service import normalize_vuln_class
from server.memory_retrieval import FEEDBACK_WEIGHTS, read_feedback_records
from server.negative_reasoning_memory import read_negative_reasoning
from server.review_dataset import read_review_examples


BASE_DIR = Path(__file__).resolve().parent
GUIDANCE_DB_DIR = BASE_DIR / "guidance_db"
GUIDANCE_MERGE_POLICY = [
    "program_policy_gates",
    "burp_scanner_evidence",
    "issue_workflow_state",
    "guidance_db",
    "local_kb",
    "internet_reference_candidates",
]


def list_guidance_pack_files() -> list[Path]:
    GUIDANCE_DB_DIR.mkdir(parents=True, exist_ok=True)
    return sorted(GUIDANCE_DB_DIR.glob("*.json"))


def load_guidance_packs() -> list[dict[str, Any]]:
    packs: list[dict[str, Any]] = []
    for path in list_guidance_pack_files():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for entry in payload.get("packs", []):
            if isinstance(entry, dict):
                normalized = dict(entry)
                normalized["_source_file"] = path.name
                packs.append(normalized)
    return packs


def query_guidance_packs(
    vuln_classes: list[str] | None = None,
    *,
    styles: list[str] | None = None,
    partition_key: str = "",
    top_k: int = 6,
) -> dict[str, Any]:
    normalized_classes = _normalize_classes(vuln_classes)
    normalized_styles = {item.strip().lower() for item in (styles or []) if item.strip()}
    feedback_scores = guidance_feedback_scores()
    decay_scores = guidance_decay_scores(partition_key=partition_key, vuln_classes=normalized_classes)
    hits: list[dict[str, Any]] = []

    for pack in load_guidance_packs():
        pack_style = (pack.get("style") or "").strip().lower()
        if normalized_styles and pack_style not in normalized_styles:
            continue
        applies_to = {normalize_vuln_class(item) for item in pack.get("applies_to", []) if item}
        matched_classes = [
            vuln_class
            for vuln_class in normalized_classes
            if vuln_class in applies_to or "general" in applies_to
        ]
        if not matched_classes:
            continue
        guidance = _extract_guidance(pack, matched_classes)
        reference_links = _extract_reference_links(pack, matched_classes)
        feedback_score = feedback_scores.get(pack.get("id", ""), 0)
        decay_score = decay_scores.get(pack_style, 0)
        influence_reason = _influence_reason(pack_style, matched_classes, feedback_score, decay_score)
        hits.append({
            "id": pack.get("id", ""),
            "name": pack.get("name", ""),
            "style": pack_style,
            "origin": pack.get("origin", ""),
            "summary": pack.get("summary", ""),
            "matched_classes": matched_classes,
            "guidance": guidance,
            "reference_links": reference_links[:8],
            "source_file": pack.get("_source_file", ""),
            "feedback_score": feedback_score,
            "decay_score": decay_score,
            "influence_reason": influence_reason,
        })

    hits.sort(
        key=lambda item: (
            _style_priority(item.get("style", "")),
            -len(item.get("matched_classes") or []),
            -((item.get("feedback_score") or 0) - (item.get("decay_score") or 0)),
            item.get("name", ""),
        )
    )
    hits = hits[:top_k]
    return {
        "hits": hits,
        "context": format_guidance_hits(hits),
        "reference_links": _collect_reference_links(hits),
        "merge_policy": list(GUIDANCE_MERGE_POLICY),
    }


def format_guidance_hits(hits: list[dict[str, Any]]) -> str:
    if not hits:
        return "No structured methodology guidance found."
    sections = []
    for hit in hits:
        guidance = hit.get("guidance") or {}
        lines = [
            f"[Pack: {hit.get('name', '')} | Style: {hit.get('style', '')} | Matched: {', '.join(hit.get('matched_classes') or [])}]",
            hit.get("summary", ""),
        ]
        for key in (
            "baseline_confirmation",
            "validation_focus",
            "impact_focus",
            "workflow_focus",
            "payload_strategy",
            "evidence_priorities",
            "reporting_focus",
            "stop_conditions",
        ):
            values = list(guidance.get(key) or [])
            if values:
                lines.append(f"{key}: " + " | ".join(values[:3]))
        refs = list(hit.get("reference_links") or [])
        if refs:
            lines.append("references: " + " | ".join(refs[:3]))
        if hit.get("influence_reason"):
            lines.append("influence: " + str(hit.get("influence_reason")))
        sections.append("\n".join(item for item in lines if item))
    return "\n\n".join(sections)


def guidance_feedback_scores() -> dict[str, int]:
    scores: dict[str, int] = {}
    for entry in read_feedback_records():
        pack_ids = [item.strip() for item in str(entry.get("guidance_pack_ids") or "").split(",") if item.strip()]
        label = (entry.get("label") or "").strip()
        if not pack_ids or label not in FEEDBACK_WEIGHTS:
            continue
        for pack_id in pack_ids:
            scores[pack_id] = scores.get(pack_id, 0) + FEEDBACK_WEIGHTS[label]
    return scores


def guidance_decay_scores(*, partition_key: str = "", vuln_classes: list[str] | None = None) -> dict[str, int]:
    if not partition_key:
        return {}
    normalized_classes = {normalize_vuln_class(item) for item in (vuln_classes or []) if item}
    decay = {
        "methodology": 0,
        "validation-impact": 0,
        "workflow-payload": 0,
        "references": 0,
    }
    for item in read_negative_reasoning(limit=300):
        if (item.get("memory_partition_key") or "").strip() != partition_key:
            continue
        item_classes = {normalize_vuln_class(entry) for entry in item.get("vuln_classes", []) or [] if entry}
        if normalized_classes and not (normalized_classes & item_classes):
            continue
        decay["workflow-payload"] += 1
        decay["validation-impact"] += 1
    for item in read_review_examples(limit=300):
        if (item.get("memory_partition_key") or "").strip() != partition_key:
            continue
        item_classes = {normalize_vuln_class(entry) for entry in item.get("vuln_classes", []) or [] if entry}
        if normalized_classes and not (normalized_classes & item_classes):
            continue
        if (item.get("outcome_label") or "") in {"scanner-review", "fallback-review"}:
            decay["references"] += 1
            decay["workflow-payload"] += 1
    return {key: min(value, 3) for key, value in decay.items() if value}


def append_guidance_feedback(job_id: str, label: str, pack_ids: list[str], notes: str = "") -> dict[str, Any]:
    from server.memory_retrieval import append_feedback_record

    payload = {
        "guidance_pack_ids": ",".join(pack_ids[:8]),
        "notes": notes.strip(),
    }
    append_feedback_record(job_id, label, json.dumps(payload, ensure_ascii=True))
    return {
        "job_id": job_id,
        "label": label,
        "guidance_pack_ids": pack_ids[:8],
    }


def _extract_guidance(pack: dict[str, Any], matched_classes: list[str]) -> dict[str, list[str]]:
    guidance: dict[str, list[str]] = {}
    for key, values in (pack.get("global_guidance") or {}).items():
        if isinstance(values, list):
            guidance[key] = list(values)

    overrides = pack.get("class_overrides") or {}
    for vuln_class in matched_classes:
        class_override = overrides.get(vuln_class) or {}
        for key, values in class_override.items():
            if not isinstance(values, list):
                continue
            guidance.setdefault(key, [])
            for item in values:
                if item not in guidance[key]:
                    guidance[key].append(item)
    for key in list(guidance):
        guidance[key] = guidance[key][:6]
    return guidance


def _extract_reference_links(pack: dict[str, Any], matched_classes: list[str]) -> list[str]:
    links: list[str] = []
    overrides = pack.get("class_overrides") or {}
    for vuln_class in matched_classes:
        class_override = overrides.get(vuln_class) or {}
        for link in class_override.get("reference_links", []) or []:
            normalized = (link or "").strip()
            if normalized and normalized not in links:
                links.append(normalized)
    for link in pack.get("reference_links") or []:
        normalized = (link or "").strip()
        if normalized and normalized not in links:
            links.append(normalized)
    return links[:8]


def _collect_reference_links(hits: list[dict[str, Any]]) -> list[str]:
    links: list[str] = []
    for hit in hits:
        for link in hit.get("reference_links") or []:
            normalized = (link or "").strip()
            if normalized and normalized not in links:
                links.append(normalized)
    return links[:10]


def _normalize_classes(vuln_classes: list[str] | None) -> list[str]:
    normalized = []
    for item in vuln_classes or ["general"]:
        candidate = normalize_vuln_class(item or "general")
        if candidate and candidate not in normalized:
            normalized.append(candidate)
    return normalized or ["general"]


def _style_priority(style: str) -> int:
    order = {
        "methodology": 0,
        "validation-impact": 1,
        "workflow-payload": 2,
        "references": 3,
    }
    return order.get((style or "").strip().lower(), 99)


def _influence_reason(style: str, matched_classes: list[str], feedback_score: int, decay_score: int) -> str:
    parts = [
        f"style={style or 'unknown'}",
        "matched=" + ",".join(matched_classes[:3] or ["general"]),
    ]
    if feedback_score:
        parts.append(f"feedback={feedback_score:+d}")
    if decay_score:
        parts.append(f"decay=-{decay_score}")
    return "; ".join(parts)
