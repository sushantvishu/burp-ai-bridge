import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from server.history_store import ANALYSIS_HISTORY_PATH, read_history_records
from server.knowledge_base import MEMORY_DIR, ensure_storage
from server.memory_partition import partition_from_payload
from server.persistence_redaction import redact_persisted_data
from server.settings import TARGET_MEMORY_PARTITIONING_ENABLED
from server.storage_protection import deserialize_jsonl_record, serialize_jsonl_record

FEEDBACK_PATH = MEMORY_DIR / "feedback.jsonl"
ENDPOINT_CACHE_PATH = MEMORY_DIR / "endpoint_cache.json"

FEEDBACK_WEIGHTS = {
    "true_positive": 3,
    "useful": 2,
    "not_useful": -2,
    "false_positive": -3,
}
CONFIRMED_HYPOTHESIS_WEIGHT = 2
DISCARDED_HYPOTHESIS_WEIGHT = -2
NEEDS_REVIEW_HYPOTHESIS_WEIGHT = -1


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _content_family(content_type: str) -> str:
    value = (content_type or "").lower()
    if "json" in value:
        return "json"
    if "html" in value:
        return "html"
    if "xml" in value:
        return "xml"
    if "form-urlencoded" in value:
        return "form"
    if "multipart/form-data" in value:
        return "multipart"
    return value.split(";", 1)[0].strip() or "unknown"


def _normalize_path(path: str) -> str:
    if not path:
        return "/"

    normalized_parts = []
    for part in path.split("/"):
        if not part:
            continue

        lower = part.lower()
        if re.fullmatch(r"\d+", lower):
            normalized_parts.append("{id}")
        elif re.fullmatch(r"[0-9a-f]{8,}", lower.replace("-", "")):
            normalized_parts.append("{token}")
        else:
            normalized_parts.append(lower)

    return "/" + "/".join(normalized_parts)


def _path_tokens(normalized_path: str) -> list[str]:
    return [token for token in normalized_path.split("/") if token]


def _extract_vuln_classes(vulnerabilities: list[str]) -> list[str]:
    classes = []
    for vulnerability in vulnerabilities or []:
        if isinstance(vulnerability, str) and vulnerability.startswith("[") and "]" in vulnerability:
            vuln_class = vulnerability[1:vulnerability.index("]")]
            if vuln_class not in classes:
                classes.append(vuln_class)
    return classes


def _extract_hypothesis_classes(analysis_run: dict | None) -> list[str]:
    classes = []
    hypotheses = (analysis_run or {}).get("hypotheses") or []
    for hypothesis in hypotheses:
        if not isinstance(hypothesis, dict):
            continue
        vuln_class = (hypothesis.get("vuln_class") or "").strip()
        if vuln_class and vuln_class not in classes:
            classes.append(vuln_class)
    return classes


def _hypothesis_status_breakdown(analysis_run: dict | None) -> dict[str, list[str]]:
    status_map = {
        "confirmed": [],
        "discarded": [],
        "needs-review": [],
        "suspected": [],
    }
    hypotheses = (analysis_run or {}).get("hypotheses") or []
    for hypothesis in hypotheses:
        if not isinstance(hypothesis, dict):
            continue
        vuln_class = (hypothesis.get("vuln_class") or "").strip() or "general"
        status = (hypothesis.get("status") or "suspected").strip().lower()
        if status not in status_map:
            status = "suspected"
        if vuln_class not in status_map[status]:
            status_map[status].append(vuln_class)
    return status_map


def _kb_signal_summary(analysis_run: dict | None) -> dict[str, list[str]]:
    enrich = ((analysis_run or {}).get("phases") or {}).get("enrich") or {}
    kb_hits = enrich.get("kb_hits") or []
    tags: list[str] = []
    titles: list[str] = []
    for hit in kb_hits:
        if not isinstance(hit, dict):
            continue
        title = (hit.get("title") or "").strip()
        if title and title not in titles:
            titles.append(title)
        for tag in hit.get("tags", []) or []:
            normalized = (tag or "").strip()
            if normalized and normalized not in tags:
                tags.append(normalized)
    return {
        "tags": tags,
        "titles": titles,
    }


def build_endpoint_fingerprint(payload, rule_context: dict) -> dict:
    features = rule_context["features"]
    matched_recipes = rule_context["matched_recipes"]
    vuln_classes = []
    for recipe in matched_recipes:
        vuln_class = recipe.get("vuln_class", "general")
        if vuln_class not in vuln_classes:
            vuln_classes.append(vuln_class)

    signal_subset = sorted(
        signal for signal in features["signals"]
        if signal.startswith("request_has_")
        or signal.startswith("path_looks_")
        or signal.startswith("response_has_")
        or signal.startswith("response_missing_")
    )

    normalized_path = _normalize_path(features["path"])
    signature = "|".join([
        (payload.http_method or "").upper() or "UNKNOWN",
        normalized_path,
        ",".join(features["param_names"]) or "-",
        _content_family(features["request_content_type"]),
        _content_family(features["response_content_type"]),
        ",".join(vuln_classes) or "-",
    ])

    return {
        "signature": signature,
        "method": (payload.http_method or "").upper() or "UNKNOWN",
        "path": features["path"] or "/",
        "normalized_path": normalized_path,
        "path_tokens": _path_tokens(normalized_path),
        "param_names": list(features["param_names"]),
        "request_content_family": _content_family(features["request_content_type"]),
        "response_content_family": _content_family(features["response_content_type"]),
        "vuln_classes": vuln_classes,
        "signals": signal_subset,
        "has_auth": "request_has_authorization" in features["signals"],
        "has_cookies": "request_has_cookies" in features["signals"],
        "memory_partition_key": partition_from_payload(payload),
    }


def _fingerprint_from_history_record(record: dict) -> dict:
    fingerprint = record.get("fingerprint")
    if isinstance(fingerprint, dict) and fingerprint.get("signature"):
        normalized = dict(fingerprint)
        normalized["path_tokens"] = normalized.get("path_tokens") or _path_tokens(normalized.get("normalized_path", "/"))
        normalized["vuln_classes"] = normalized.get("vuln_classes") or _extract_hypothesis_classes(record.get("analysis_run")) or _extract_vuln_classes(
            (record.get("result") or {}).get("potential_vulnerabilities", [])
        )
        return normalized

    parsed = urlparse(record.get("target_url") or "")
    param_names = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())
    vuln_classes = _extract_hypothesis_classes(record.get("analysis_run")) or _extract_vuln_classes((record.get("result") or {}).get("potential_vulnerabilities", []))
    normalized_path = _normalize_path(parsed.path or "/")
    return {
        "signature": "|".join([
            (record.get("http_method") or "UNKNOWN").upper(),
            normalized_path,
            ",".join(param_names) or "-",
            "unknown",
            "unknown",
            ",".join(vuln_classes) or "-",
        ]),
        "method": (record.get("http_method") or "UNKNOWN").upper(),
        "path": parsed.path or "/",
        "normalized_path": normalized_path,
        "path_tokens": _path_tokens(normalized_path),
        "param_names": param_names,
        "request_content_family": "unknown",
        "response_content_family": "unknown",
        "vuln_classes": vuln_classes,
        "signals": [],
        "has_auth": False,
        "has_cookies": False,
        "memory_partition_key": record.get("memory_partition_key") or partition_from_payload(record),
    }


def append_feedback_record(job_id: str, label: str, notes: str = "") -> Path:
    ensure_storage()
    entry = redact_persisted_data({
        "job_id": job_id,
        "label": label,
        "notes": notes.strip(),
        "created_at": _utc_now(),
    })
    with FEEDBACK_PATH.open("a", encoding="utf-8") as handle:
        handle.write(serialize_jsonl_record(entry) + "\n")
    return FEEDBACK_PATH


def read_feedback_records(limit: int | None = None) -> list[dict]:
    ensure_storage()
    if not FEEDBACK_PATH.exists():
        return []

    lines = FEEDBACK_PATH.read_text(encoding="utf-8").splitlines()
    if limit is not None:
        lines = lines[-limit:]

    records = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        payload = deserialize_jsonl_record(line)
        if not payload:
            continue
        records.append(payload)
    return records


def _feedback_summary() -> dict[str, dict]:
    summary = {}
    for entry in read_feedback_records():
        job_id = entry.get("job_id")
        label = entry.get("label", "").strip()
        if not job_id or label not in FEEDBACK_WEIGHTS:
            continue
        current = summary.setdefault(job_id, {"score": 0, "labels": []})
        current["score"] += FEEDBACK_WEIGHTS[label]
        if label not in current["labels"]:
            current["labels"].append(label)
    return summary


def _cache_is_fresh() -> bool:
    if not ENDPOINT_CACHE_PATH.exists():
        return False

    cache_mtime = ENDPOINT_CACHE_PATH.stat().st_mtime
    history_mtime = ANALYSIS_HISTORY_PATH.stat().st_mtime if ANALYSIS_HISTORY_PATH.exists() else 0
    feedback_mtime = FEEDBACK_PATH.stat().st_mtime if FEEDBACK_PATH.exists() else 0
    return cache_mtime >= max(history_mtime, feedback_mtime)


def _build_cache() -> dict:
    feedback = _feedback_summary()
    entries_by_signature: dict[tuple[str, str], dict] = {}
    signature_counts = Counter()

    for record in read_history_records():
        if record.get("status") != "completed" or not record.get("result"):
            continue

        fingerprint = _fingerprint_from_history_record(record)
        result = record.get("result") or {}
        analysis_run = record.get("analysis_run") or {}
        job_feedback = feedback.get(record.get("job_id"), {"score": 0, "labels": []})
        status_breakdown = _hypothesis_status_breakdown(analysis_run)
        kb_signals = _kb_signal_summary(analysis_run)
        status_score = (
            len(status_breakdown["confirmed"]) * CONFIRMED_HYPOTHESIS_WEIGHT
            + len(status_breakdown["discarded"]) * DISCARDED_HYPOTHESIS_WEIGHT
            + len(status_breakdown["needs-review"]) * NEEDS_REVIEW_HYPOTHESIS_WEIGHT
        )
        memory_promotion = _memory_promotion(record, status_breakdown=status_breakdown, feedback_score=job_feedback["score"])
        if not memory_promotion.get("promoted") and job_feedback["score"] <= 0:
            continue
        if not (status_breakdown["confirmed"] or status_breakdown["suspected"] or status_breakdown["needs-review"]):
            continue

        entry = {
            "job_id": record.get("job_id"),
            "target_url": record.get("target_url") or "",
            "created_at": record.get("created_at") or "",
            "fingerprint": fingerprint,
            "analysis": _analysis_excerpt(result.get("analysis", "")),
            "potential_vulnerabilities": result.get("potential_vulnerabilities", []),
            "hypotheses": [
                hypothesis
                for hypothesis in (analysis_run.get("hypotheses") or [])
                if isinstance(hypothesis, dict)
                and (
                    (hypothesis.get("status") or "").strip().lower() == "confirmed"
                    or _as_float(hypothesis.get("confidence")) >= 0.78
                )
            ][:6],
            "evidence_count": len(analysis_run.get("evidence") or []),
            "source_links": result.get("source_links", []),
            "tool_results_excerpt": _tool_results_excerpt(record.get("tool_results_text") or ""),
            "feedback_score": job_feedback["score"] + status_score,
            "explicit_feedback_score": job_feedback["score"],
            "feedback_labels": job_feedback["labels"],
            "confirmed_classes": status_breakdown["confirmed"],
            "discarded_classes": status_breakdown["discarded"],
            "needs_review_classes": status_breakdown["needs-review"],
            "kb_signal_tags": kb_signals["tags"],
            "kb_signal_titles": kb_signals["titles"],
            "batch_id": record.get("batch_id") or "",
            "memory_promotion": memory_promotion,
        }
        dedupe_key = (
            fingerprint.get("signature") or "",
            fingerprint.get("memory_partition_key") or "",
        )
        previous = entries_by_signature.get(dedupe_key)
        if previous is None:
            entries_by_signature[dedupe_key] = entry
        else:
            current_score = (entry.get("memory_promotion") or {}).get("score", 0)
            previous_score = (previous.get("memory_promotion") or {}).get("score", 0)
            if current_score > previous_score or (
                current_score == previous_score and (entry.get("created_at") or "") > (previous.get("created_at") or "")
            ):
                entries_by_signature[dedupe_key] = entry
        signature_counts[fingerprint["signature"]] += 1

    cache = {
        "generated_at": _utc_now(),
        "entries": list(entries_by_signature.values()),
        "signature_counts": dict(signature_counts),
    }
    ENDPOINT_CACHE_PATH.write_text(json.dumps(cache, ensure_ascii=True, indent=2), encoding="utf-8")
    return cache


def load_endpoint_cache() -> dict:
    ensure_storage()
    if _cache_is_fresh():
        try:
            return json.loads(ENDPOINT_CACHE_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return _build_cache()


def _jaccard(left: list[str], right: list[str]) -> float:
    left_set = set(left)
    right_set = set(right)
    if not left_set and not right_set:
        return 1.0
    union = left_set | right_set
    if not union:
        return 0.0
    return len(left_set & right_set) / len(union)


def _tool_results_excerpt(text: str) -> str:
    value = (text or "").strip()
    if not value:
        return ""
    if _looks_like_noisy_scanner_blob(value):
        return ""
    normalized = " ".join(line.strip() for line in value.splitlines() if line.strip())
    if len(normalized) <= 180:
        return normalized
    return normalized[:177].rstrip() + "..."


def _analysis_excerpt(text: str) -> str:
    value = (text or "").strip()
    if not value:
        return ""
    if _looks_like_noisy_scanner_blob(value):
        return ""
    normalized = " ".join(line.strip() for line in value.splitlines() if line.strip())
    if len(normalized) <= 240:
        return normalized
    return normalized[:237].rstrip() + "..."


def _looks_like_noisy_scanner_blob(text: str) -> bool:
    normalized = (text or "").strip().lower()
    if not normalized:
        return False
    markers = (
        "auto-collected burp audit issues",
        "requestresponses",
        "scanner request",
        "oastify.com",
        "requesttext",
        "responsetext",
    )
    if any(marker in normalized for marker in markers):
        return True
    return len(normalized) > 1600


def _memory_promotion(record: dict, *, status_breakdown: dict, feedback_score: int) -> dict:
    profile = record.get("memory_promotion")
    if isinstance(profile, dict) and "promoted" in profile:
        return dict(profile)

    result = record.get("result") or {}
    phases = ((record.get("analysis_run") or {}).get("phases") or {})
    validation_status = ((phases.get("validate") or {}).get("validation_status") or "").strip().lower()
    impact_reportable = bool((phases.get("impact") or {}).get("reportable"))
    confirmed_count = len(status_breakdown.get("confirmed") or [])
    evidence_count = len((record.get("analysis_run") or {}).get("evidence") or [])
    score = feedback_score + confirmed_count * 3 + (2 if validation_status == "confirmed" else 0) + (2 if impact_reportable else 0)
    if bool(result.get("fallback_used")):
        score -= 2
    if evidence_count >= 3:
        score += 1
    promoted = bool(confirmed_count or impact_reportable or score >= 4)
    return {
        "promoted": promoted,
        "score": score,
        "validation_status": validation_status,
        "impact_reportable": impact_reportable,
        "confirmed_classes": list(status_breakdown.get("confirmed") or [])[:6],
    }


def _similarity_score(current: dict, previous: dict) -> tuple[float, bool]:
    score = 0.0
    exact_signature = current["signature"] == previous["signature"]

    if current["method"] == previous["method"]:
        score += 0.15
    if current["normalized_path"] == previous["normalized_path"]:
        score += 0.35
    else:
        score += 0.20 * _jaccard(current["path_tokens"], previous["path_tokens"])

    score += 0.20 * _jaccard(current["param_names"], previous["param_names"])
    score += 0.15 * _jaccard(current["vuln_classes"], previous["vuln_classes"])

    if current["request_content_family"] == previous["request_content_family"]:
        score += 0.05
    if current["response_content_family"] == previous["response_content_family"]:
        score += 0.05
    if current["has_auth"] == previous["has_auth"]:
        score += 0.025
    if current["has_cookies"] == previous["has_cookies"]:
        score += 0.025
    if TARGET_MEMORY_PARTITIONING_ENABLED and current.get("memory_partition_key") == previous.get("memory_partition_key"):
        score += 0.08

    return score, exact_signature


def find_similar_history(current_fingerprint: dict, limit: int = 3) -> list[dict]:
    cache = load_endpoint_cache()
    results = []

    for entry in cache.get("entries", []):
        previous_fingerprint = entry["fingerprint"]
        path_overlap = _jaccard(current_fingerprint["path_tokens"], previous_fingerprint["path_tokens"])
        similarity, exact_signature = _similarity_score(current_fingerprint, previous_fingerprint)
        same_partition = current_fingerprint.get("memory_partition_key") == previous_fingerprint.get("memory_partition_key")
        shared_confirmed = len(set(current_fingerprint.get("vuln_classes", [])) & set(entry.get("confirmed_classes", [])))
        shared_discarded = len(set(current_fingerprint.get("vuln_classes", [])) & set(entry.get("discarded_classes", [])))
        status_alignment = min(shared_confirmed, 3) * 0.04 - min(shared_discarded, 3) * 0.05
        final_score = similarity + max(min(entry.get("feedback_score", 0), 4), -4) * 0.03 + status_alignment
        if exact_signature:
            final_score += 0.08
        if TARGET_MEMORY_PARTITIONING_ENABLED:
            final_score += 0.08 if same_partition else -0.04
        if not exact_signature and current_fingerprint["normalized_path"] != previous_fingerprint["normalized_path"] and path_overlap < 0.34:
            continue
        if similarity < 0.35:
            continue

        results.append({
            **entry,
            "similarity": round(similarity, 3),
            "score": round(final_score, 3),
            "exact_signature": exact_signature,
            "path_overlap": round(path_overlap, 3),
            "same_partition": same_partition,
        })

    results.sort(key=lambda item: (item["score"], item["created_at"]), reverse=True)
    return results[:limit]


def summarize_similar_findings(similar_hits: list[dict]) -> dict:
    if not similar_hits:
        return {
            "total_hits": 0,
            "exact_matches": 0,
            "preferred_vuln_classes": [],
            "deprioritized_vuln_classes": [],
            "preferred_kb_tags": [],
            "deprioritized_kb_tags": [],
            "preferred_kb_titles": [],
            "deprioritized_kb_titles": [],
            "top_targets": [],
            "top_partitions": [],
            "feedback_labels": [],
            "note": "",
        }

    positive = Counter()
    negative = Counter()
    positive_kb_tags = Counter()
    negative_kb_tags = Counter()
    positive_kb_titles = Counter()
    negative_kb_titles = Counter()
    feedback_labels = []
    top_targets = []
    top_partitions = []

    for hit in similar_hits:
        vuln_classes = hit["fingerprint"].get("vuln_classes", [])
        for label in hit.get("feedback_labels", []):
            if label not in feedback_labels:
                feedback_labels.append(label)

        if hit["target_url"] and hit["target_url"] not in top_targets:
            top_targets.append(hit["target_url"])
        partition_key = (hit.get("fingerprint") or {}).get("memory_partition_key", "")
        if partition_key and partition_key not in top_partitions:
            top_partitions.append(partition_key)

        if hit.get("feedback_score", 0) > 0:
            for vuln_class in vuln_classes:
                positive[vuln_class] += 1
            for vuln_class in hit.get("confirmed_classes", []):
                positive[vuln_class] += 2
            for tag in hit.get("kb_signal_tags", []):
                positive_kb_tags[tag] += 1
            for title in hit.get("kb_signal_titles", []):
                positive_kb_titles[title] += 1
        elif hit.get("feedback_score", 0) < 0:
            for vuln_class in vuln_classes:
                negative[vuln_class] += 1
            for vuln_class in hit.get("discarded_classes", []):
                negative[vuln_class] += 2
            for tag in hit.get("kb_signal_tags", []):
                negative_kb_tags[tag] += 1
            for title in hit.get("kb_signal_titles", []):
                negative_kb_titles[title] += 1

    preferred = [name for name, _ in positive.most_common(3)]
    deprioritized = [name for name, _ in negative.most_common(3)]
    preferred_kb_tags = [name for name, _ in positive_kb_tags.most_common(4)]
    deprioritized_kb_tags = [name for name, _ in negative_kb_tags.most_common(4)]
    preferred_kb_titles = [name for name, _ in positive_kb_titles.most_common(3)]
    deprioritized_kb_titles = [name for name, _ in negative_kb_titles.most_common(3)]
    exact_matches = sum(1 for hit in similar_hits if hit.get("exact_signature"))

    note_parts = [f"Seen {len(similar_hits)} similar prior exchange(s) in local memory"]
    if exact_matches:
        note_parts.append(f"{exact_matches} exact normalized endpoint match(es)")
    if preferred:
        note_parts.append("prior useful patterns favored " + ", ".join(preferred))
    if deprioritized:
        note_parts.append("prior negative feedback de-prioritized " + ", ".join(deprioritized))
    if preferred_kb_titles:
        note_parts.append("confirmed local KB notes favored " + ", ".join(preferred_kb_titles))
    if deprioritized_kb_titles:
        note_parts.append("discarded local KB notes were suppressed " + ", ".join(deprioritized_kb_titles))

    return {
        "total_hits": len(similar_hits),
        "exact_matches": exact_matches,
        "preferred_vuln_classes": preferred,
        "deprioritized_vuln_classes": deprioritized,
        "preferred_kb_tags": preferred_kb_tags,
        "deprioritized_kb_tags": deprioritized_kb_tags,
        "preferred_kb_titles": preferred_kb_titles,
        "deprioritized_kb_titles": deprioritized_kb_titles,
        "top_targets": top_targets[:3],
        "top_partitions": top_partitions[:3],
        "feedback_labels": feedback_labels,
        "note": ". ".join(note_parts) + ".",
    }


def describe_history_correlation(current_fingerprint: dict, similar_hits: list[dict]) -> list[str]:
    if not similar_hits:
        return [
            "No similar prior exchanges were found in local memory for this normalized endpoint.",
            "Capture one baseline request, then compare the next approved manual variation against this baseline in Burp HTTP history.",
        ]

    lines = []
    exact_matches = [hit for hit in similar_hits if hit.get("exact_signature")]
    if exact_matches:
        lines.append(f"Found {len(exact_matches)} exact normalized endpoint match(es) in local memory.")
    lines.append(f"Compared against {len(similar_hits)} similar prior exchange(s) from local memory.")

    current_params = current_fingerprint.get("param_names", [])
    current_classes = current_fingerprint.get("vuln_classes", [])
    for hit in similar_hits[:3]:
        fingerprint = hit.get("fingerprint", {})
        shared_params = sorted(set(current_params) & set(fingerprint.get("param_names", [])))
        shared_classes = sorted(set(current_classes) & set(fingerprint.get("vuln_classes", [])))
        parts = [
            f"Similarity {hit.get('similarity', 0):.2f}",
            hit.get("target_url") or "<unknown target>",
        ]
        if shared_params:
            parts.append("shared params: " + ", ".join(shared_params))
        if shared_classes:
            parts.append("shared classes: " + ", ".join(shared_classes))
        if hit.get("same_partition"):
            parts.append("same target partition")
        feedback_labels = hit.get("feedback_labels", [])
        if feedback_labels:
            parts.append("feedback: " + ", ".join(feedback_labels))
        confirmed_classes = hit.get("confirmed_classes", [])
        if confirmed_classes:
            parts.append("confirmed: " + ", ".join(confirmed_classes))
        discarded_classes = hit.get("discarded_classes", [])
        if discarded_classes:
            parts.append("discarded: " + ", ".join(discarded_classes))
        kb_signal_titles = hit.get("kb_signal_titles", [])
        if kb_signal_titles:
            parts.append("kb notes: " + ", ".join(kb_signal_titles[:2]))
        tool_results_excerpt = hit.get("tool_results_excerpt", "")
        if tool_results_excerpt:
            parts.append("prior tool note: " + tool_results_excerpt)
        lines.append(" | ".join(parts))

    lines.append("Use Burp HTTP history to compare status, content type, headers, and body deltas for the next approved manual variation.")
    return lines[:6]
