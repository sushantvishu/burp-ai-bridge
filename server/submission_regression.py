from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from server.core.reference_enrichment_service import normalize_vuln_class
from server.memory_partition import build_partition_key
from server.review_dataset import append_review_dataset_entry, read_review_examples

BASE_DIR = Path(__file__).resolve().parent
SUBMISSION_REGRESSION_DIR = BASE_DIR / "submission_regressions"
REGRESSION_OUTCOME_TO_REVIEW_LABEL = {
    "accepted": "confirmed-reportable",
    "downgraded": "confirmed-bounded",
    "duplicate-na": "scanner-review",
}


def load_submission_regressions() -> list[dict[str, Any]]:
    SUBMISSION_REGRESSION_DIR.mkdir(parents=True, exist_ok=True)
    items: list[dict[str, Any]] = []
    for path in sorted(SUBMISSION_REGRESSION_DIR.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            normalized = dict(payload)
            normalized["_source_file"] = path.name
            items.append(normalized)
    return items


def query_submission_regressions(
    *,
    vuln_class: str = "",
    outcome: str = "",
    platform: str = "",
    limit: int = 10,
) -> dict[str, Any]:
    normalized_class = (vuln_class or "").strip().lower()
    normalized_outcome = (outcome or "").strip().lower()
    normalized_platform = (platform or "").strip().lower()
    items: list[dict[str, Any]] = []
    for entry in load_submission_regressions():
        if normalized_class and normalized_class != (entry.get("vuln_class") or "").strip().lower():
            continue
        if normalized_outcome and normalized_outcome != (entry.get("outcome") or "").strip().lower():
            continue
        if normalized_platform and normalized_platform != (entry.get("platform") or "").strip().lower():
            continue
        items.append(entry)
        if len(items) >= max(1, limit):
            break
    review_examples = _review_examples_for_outcome(normalized_outcome, normalized_class, limit=max(1, min(limit, 5)))
    return {
        "count": len(items),
        "items": items,
        "review_examples": review_examples,
        "summary": _summary(items, review_examples),
    }


def build_wording_comparison(vuln_class: str, platform: str = "") -> dict[str, Any]:
    normalized_class = (vuln_class or "general").strip().lower()
    normalized_platform = (platform or "generic").strip().lower()
    matches = query_submission_regressions(vuln_class=normalized_class, platform=normalized_platform, limit=12).get("items", [])
    wording = {
        "too_vague": [],
        "too_strong": [],
        "just_right": [],
    }
    for item in matches:
        bucket = (item.get("wording_bucket") or "").strip().lower()
        if bucket in wording:
            phrase = (item.get("phrase") or "").strip()
            if phrase:
                wording[bucket].append(phrase)
    return {
        "vuln_class": normalized_class,
        "platform": normalized_platform,
        "too_vague": wording["too_vague"][:4],
        "too_strong": wording["too_strong"][:4],
        "just_right": wording["just_right"][:4],
        "summary": _wording_summary(wording),
    }


def import_submission_regressions_into_review_dataset(
    *,
    vuln_class: str = "",
    outcome: str = "",
    platform: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    imported: list[dict[str, Any]] = []
    skipped: list[str] = []
    existing_job_ids = {
        str(item.get("job_id") or "").strip()
        for item in read_review_examples(limit=5000)
        if str(item.get("job_id") or "").strip()
    }

    for entry in query_submission_regressions(
        vuln_class=vuln_class,
        outcome=outcome,
        platform=platform,
        limit=max(1, limit),
    ).get("items", []):
        example = build_review_example_from_submission_regression(entry)
        job_id = str(example.get("job_id") or "").strip()
        if job_id and job_id in existing_job_ids:
            skipped.append(job_id)
            continue
        if append_review_dataset_entry(example):
            imported.append(example)
            if job_id:
                existing_job_ids.add(job_id)

    return {
        "imported_count": len(imported),
        "skipped_count": len(skipped),
        "items": imported,
        "skipped_job_ids": skipped[:20],
        "summary": _import_summary(imported, skipped),
    }


def _review_examples_for_outcome(outcome: str, vuln_class: str, limit: int) -> list[dict[str, Any]]:
    mapped = {
        "accepted": {"confirmed-reportable"},
        "downgraded": {"confirmed-bounded", "fallback-review"},
        "duplicate-na": {"scanner-review"},
    }
    allowed = mapped.get((outcome or "").strip().lower(), set())
    items: list[dict[str, Any]] = []
    for example in reversed(read_review_examples()):
        if vuln_class and vuln_class not in [str(item or "").strip().lower() for item in example.get("vuln_classes", []) or []]:
            continue
        if allowed and (example.get("outcome_label") or "") not in allowed:
            continue
        items.append(example)
        if len(items) >= limit:
            break
    return items


def build_review_example_from_submission_regression(entry: dict[str, Any]) -> dict[str, Any]:
    normalized_class = normalize_vuln_class(entry.get("vuln_class") or "general")
    normalized_outcome = (entry.get("outcome") or "duplicate-na").strip().lower()
    label = REGRESSION_OUTCOME_TO_REVIEW_LABEL.get(normalized_outcome, "scanner-review")
    platform = (entry.get("platform") or "generic").strip().lower()
    target_url = (entry.get("target_url") or "").strip()
    selected_profile = "submission-regression"
    source_id = (entry.get("id") or f"{platform}-{normalized_class}-{normalized_outcome}").strip()
    phrase = (entry.get("phrase") or "").strip()
    notes = entry.get("notes") or []
    note_text = notes[0] if isinstance(notes, list) and notes else ""
    return {
        "job_id": f"submission-regression:{source_id}",
        "request_id": "",
        "created_at": str(entry.get("created_at") or _utc_now()),
        "target_url": target_url,
        "http_method": str(entry.get("http_method") or "").strip(),
        "memory_partition_key": build_partition_key(
            target_url=target_url,
            program_platform=platform,
            selected_profile=selected_profile,
        ),
        "scanner_issue_name": str(entry.get("title") or entry.get("vuln_class") or normalized_class).strip(),
        "scanner_severity": str(entry.get("scanner_severity") or "").strip(),
        "scanner_confidence": str(entry.get("scanner_confidence") or "").strip(),
        "vuln_classes": [normalized_class],
        "validation_status": "confirmed" if normalized_outcome in {"accepted", "downgraded"} else "needs-review",
        "reportable": normalized_outcome == "accepted",
        "business_impact_class": str(entry.get("business_impact_class") or "").strip(),
        "evidence_count": int(entry.get("evidence_count") or (1 if phrase else 0)),
        "hypothesis_count": 1,
        "outcome_label": label,
        "analysis_backend": "submission-regression",
        "summary": (phrase or note_text or f"{normalized_class} regression example").strip()[:220],
        "program_platform": platform,
        "selected_profile": selected_profile,
        "source_file": str(entry.get("_source_file") or "").strip(),
    }


def _summary(items: list[dict[str, Any]], review_examples: list[dict[str, Any]]) -> str:
    if not items and not review_examples:
        return "No submission regression examples matched this query."
    parts = []
    if items:
        parts.append(f"Loaded {len(items)} curated regression example(s).")
    if review_examples:
        parts.append(f"Matched {len(review_examples)} local review example(s).")
    return " ".join(parts)


def _import_summary(imported: list[dict[str, Any]], skipped: list[str]) -> str:
    if not imported and not skipped:
        return "No regression examples matched the import filters."
    parts = []
    if imported:
        parts.append(f"Imported {len(imported)} regression example(s) into the review dataset.")
    if skipped:
        parts.append(f"Skipped {len(skipped)} existing example(s).")
    return " ".join(parts)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _wording_summary(wording: dict[str, list[str]]) -> str:
    if wording["just_right"]:
        return "Use the just-right wording patterns as the default report tone."
    if wording["too_strong"]:
        return "The current dataset has stronger-than-supported phrasing examples; keep claims narrower."
    return "No strong wording comparison matches were found for this query."
