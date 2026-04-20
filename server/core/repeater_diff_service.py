from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import parse_qsl, urlparse

from server.repeater_learning import mutation_family

ADVANCED_JS_MAX_ENDPOINTS = 10
ADVANCED_JS_MAX_PARAMS = 12
ADVANCED_JS_MAX_BODIES = 5
ADVANCED_JS_BODY_CHAR_LIMIT = 6000
ADVANCED_RACE_MIN_OBSERVATIONS = 3
ADVANCED_RACE_MAX_OBSERVATIONS = 8
ADVANCED_RACE_ALLOWED_CLASSES = {
    "access-control",
    "authentication",
    "business-logic",
    "idor",
    "race-condition",
    "session-management",
}
ADVANCED_ANNOTATION_JS = {"advanced-js", "advanced-js-endpoints", "js-endpoint-extraction"}
ADVANCED_ANNOTATION_RACE = {"advanced-race", "advanced-race-signals", "race-signal-check"}

JS_ENDPOINT_PATTERNS = (
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|\$.ajax)\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE),
    re.compile(r"""['"]((?:https?://[^'"]+|/(?:api|graphql|v[0-9]+)[^'"]*))['"]""", re.IGNORECASE),
)


def score_repeater_diffs(payload_like, plan: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = _to_payload_dict(payload_like)
    baseline_request = str(payload.get("raw_request") or "").strip()
    baseline_response = str(payload.get("baseline_response_text") or payload.get("raw_response") or "").strip()
    observations = [item for item in list(payload.get("repeater_variant_observations") or []) if isinstance(item, dict)]
    if not plan:
        plan = {}

    baseline = _parse_http_response(baseline_response)
    scanner_focus = plan.get("scanner_focus") or {}
    expected_signals = {
        str(item.get("name") or item.get("tab_name") or "").strip(): str(item.get("expected_signal") or "").strip()
        for item in list(plan.get("repeater_variant_requests") or [])[:8]
        if isinstance(item, dict)
    }
    ranked_items = []
    for observation in observations[:8]:
        ranked_items.append(_score_observation(observation, baseline, scanner_focus, expected_signals))

    ranked_items.sort(key=lambda item: (float(item.get("score", 0.0) or 0.0), bool(item.get("high_signal"))), reverse=True)
    best = ranked_items[0] if ranked_items else {}
    advanced_modules = _build_advanced_modules(payload, plan, baseline, observations, ranked_items)
    return {
        "baseline": {
            "status_code": baseline.get("status_code", 0),
            "header_count": len(baseline.get("headers") or {}),
            "body_length": len(baseline.get("body") or ""),
            "has_body": bool(baseline.get("body")),
        },
        "count": len(ranked_items),
        "ranked_items": ranked_items,
        "best_item": best,
        "summary": _build_summary(best, ranked_items, baseline_request),
        "advanced_modules": advanced_modules,
    }


def _score_observation(observation: dict[str, Any], baseline: dict[str, Any], scanner_focus: dict[str, Any], expected_signals: dict[str, str]) -> dict[str, Any]:
    response_text = str(observation.get("response_text") or observation.get("raw_response") or "").strip()
    request_text = str(observation.get("request_text") or observation.get("raw_request") or "").strip()
    parsed = _parse_http_response(response_text)
    tab_name = str(observation.get("tab_name") or observation.get("name") or "").strip()
    baseline_status = int(baseline.get("status_code") or 0)
    variant_status = int(parsed.get("status_code") or 0)
    status_changed = bool(baseline_status and variant_status and baseline_status != variant_status)
    status_transition = f"{baseline_status}->{variant_status}" if baseline_status or variant_status else ""

    header_delta_count = _header_delta_count(baseline.get("headers") or {}, parsed.get("headers") or {})
    baseline_body = str(baseline.get("body") or "")
    variant_body = str(parsed.get("body") or "")
    body_delta_ratio = round(1.0 - SequenceMatcher(None, baseline_body, variant_body).ratio(), 3) if (baseline_body or variant_body) else 0.0
    body_length_delta = abs(len(variant_body) - len(baseline_body))

    matched_markers = _matched_markers(scanner_focus, request_text, variant_body)
    expected_signal = str(observation.get("expected_signal") or expected_signals.get(tab_name) or "").strip()
    expected_signal_matched = _expected_signal_matched(expected_signal, status_changed, header_delta_count, body_length_delta, matched_markers)

    score = 0.0
    if status_changed:
        score += 1.4
    if _auth_boundary_signal(baseline_status, variant_status):
        score += 1.2
    if header_delta_count >= 2:
        score += min(1.0, header_delta_count * 0.18)
    if body_delta_ratio >= 0.15:
        score += min(1.4, body_delta_ratio * 2.5)
    if body_length_delta >= 80:
        score += min(0.8, body_length_delta / 500.0)
    if matched_markers:
        score += 0.9
    if expected_signal_matched:
        score += 0.6

    score = round(score, 2)
    high_signal = score >= 2.5
    family = mutation_family(tab_name, str(observation.get("summary") or "").strip(), expected_signal, str(observation.get("request_ref") or "").strip())
    reasons = []
    if status_changed:
        reasons.append(f"HTTP status changed: {status_transition}.")
    if _auth_boundary_signal(baseline_status, variant_status):
        reasons.append("The status transition looks like an auth or authorization boundary change.")
    if header_delta_count:
        reasons.append(f"{header_delta_count} header change(s) detected.")
    if body_delta_ratio:
        reasons.append(f"Body diff ratio {body_delta_ratio:.3f}.")
    if matched_markers:
        reasons.append("Response contains scanner-anchored or mutation markers: " + ", ".join(matched_markers[:3]) + ".")
    if expected_signal_matched and expected_signal:
        reasons.append("Observed changes match the expected signal for this variant.")

    return {
        "tab_name": tab_name,
        "summary": str(observation.get("summary") or "").strip(),
        "request_ref": str(observation.get("request_ref") or "").strip(),
        "issue_id": str(observation.get("issue_id") or "").strip(),
        "status_code": variant_status,
        "status_transition": status_transition,
        "header_delta_count": header_delta_count,
        "body_length_delta": body_length_delta,
        "body_delta_ratio": body_delta_ratio,
        "matched_markers": matched_markers[:4],
        "expected_signal": expected_signal,
        "expected_signal_matched": expected_signal_matched,
        "mutation_family": family,
        "score": score,
        "high_signal": high_signal,
        "reasons": reasons[:6],
    }


def _parse_http_response(raw_response: str) -> dict[str, Any]:
    content = (raw_response or "").replace("\r\n", "\n")
    head, _, body = content.partition("\n\n")
    lines = [line for line in head.split("\n") if line]
    status_code = 0
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2:
            try:
                status_code = int(parts[1])
            except ValueError:
                status_code = 0
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return {"status_code": status_code, "headers": headers, "body": body}


def _header_delta_count(baseline: dict[str, str], variant: dict[str, str]) -> int:
    keys = set(baseline) | set(variant)
    changed = 0
    for key in keys:
        if baseline.get(key, "") != variant.get(key, ""):
            changed += 1
    return changed


def _matched_markers(scanner_focus: dict[str, Any], request_text: str, response_body: str) -> list[str]:
    markers = []
    for item in list(scanner_focus.get("highlights") or [])[:8]:
        if not isinstance(item, dict):
            continue
        text = str(item.get("text") or "").strip()
        if text and text in response_body and text not in markers:
            markers.append(text)
    for token in ("<other-tenant", "<benign", "<same-", "bridge-proof"):
        if token in request_text and token not in markers:
            markers.append(token)
    return markers


def _expected_signal_matched(expected_signal: str, status_changed: bool, header_delta_count: int, body_length_delta: int, matched_markers: list[str]) -> bool:
    lowered = (expected_signal or "").lower()
    if not lowered:
        return False
    if "200/403" in lowered or "403" in lowered or "401" in lowered:
        return status_changed
    if "header" in lowered and header_delta_count:
        return True
    if "length" in lowered or "diff" in lowered:
        return body_length_delta > 0 or status_changed
    if "marker" in lowered or "sink" in lowered:
        return bool(matched_markers)
    return status_changed or header_delta_count > 0 or body_length_delta > 0


def _auth_boundary_signal(baseline_status: int, variant_status: int) -> bool:
    if baseline_status in {401, 403} and 200 <= variant_status < 300:
        return True
    if 200 <= baseline_status < 300 and variant_status in {401, 403}:
        return True
    return False


def _build_summary(best: dict[str, Any], ranked_items: list[dict[str, Any]], baseline_request: str) -> str:
    if not ranked_items:
        return "No Repeater observations were supplied yet, so the bridge cannot score response deltas."
    if not best:
        return "Repeater observations were parsed, but no strong signal was identified."
    parts = [f"Top tab: {best.get('tab_name') or '<unknown>'}"]
    if best.get("status_transition"):
        parts.append(f"status {best['status_transition']}")
    parts.append(f"score {best.get('score', 0.0)}")
    if baseline_request:
        parts.append("baseline request present")
    return ", ".join(parts) + "."


def _build_advanced_modules(
    payload: dict[str, Any],
    plan: dict[str, Any],
    baseline: dict[str, Any],
    observations: list[dict[str, Any]],
    ranked_items: list[dict[str, Any]],
) -> dict[str, Any]:
    js_enabled, race_enabled = _advanced_toggle_state(payload)
    requested = bool(js_enabled or race_enabled)
    modules = {
        "requested": requested,
        "js_endpoint_extraction": {
            "enabled": js_enabled,
            "summary": "JS endpoint extraction is disabled for this request.",
            "count": 0,
            "endpoints": [],
            "parameters": [],
            "bounded": True,
        },
        "race_signal_check": {
            "enabled": race_enabled,
            "summary": "Race-condition signal checks are disabled for this request.",
            "eligible": False,
            "bounded": True,
            "inconsistent": False,
            "candidate_group": "",
            "signals": [],
        },
    }
    if not requested:
        modules["summary"] = "Advanced modules are off by default and were not requested."
        return modules

    if js_enabled:
        js_result = _extract_js_endpoints(baseline, observations)
        modules["js_endpoint_extraction"] = js_result

    if race_enabled:
        race_result = _race_signal_check(plan, observations, ranked_items)
        modules["race_signal_check"] = race_result

    summaries = [
        modules["js_endpoint_extraction"].get("summary", ""),
        modules["race_signal_check"].get("summary", ""),
    ]
    modules["summary"] = " | ".join(item for item in summaries if item)
    return modules


def _advanced_toggle_state(payload: dict[str, Any]) -> tuple[bool, bool]:
    annotations = {
        str(item).strip().lower()
        for item in list(payload.get("annotations") or [])
        if str(item).strip()
    }
    js_enabled = bool(payload.get("enable_js_endpoint_extraction")) or bool(annotations & ADVANCED_ANNOTATION_JS)
    race_enabled = bool(payload.get("enable_race_signal_checks")) or bool(annotations & ADVANCED_ANNOTATION_RACE)
    return js_enabled, race_enabled


def _extract_js_endpoints(baseline: dict[str, Any], observations: list[dict[str, Any]]) -> dict[str, Any]:
    bodies = [str(baseline.get("body") or "")]
    for item in observations[:ADVANCED_JS_MAX_BODIES - 1]:
        response_text = str(item.get("response_text") or item.get("raw_response") or "")
        bodies.append(str(_parse_http_response(response_text).get("body") or ""))

    endpoints: list[str] = []
    params: list[str] = []
    for body in bodies[:ADVANCED_JS_MAX_BODIES]:
        if not body:
            continue
        clipped = body[:ADVANCED_JS_BODY_CHAR_LIMIT]
        for pattern in JS_ENDPOINT_PATTERNS:
            for match in pattern.findall(clipped):
                normalized = _normalize_endpoint_candidate(str(match or "").strip())
                if not normalized:
                    continue
                if normalized not in endpoints:
                    endpoints.append(normalized)
                for key, _ in parse_qsl(urlparse(normalized).query, keep_blank_values=True):
                    key_name = key.strip().lower()
                    if key_name and key_name not in params:
                        params.append(key_name)
                if len(endpoints) >= ADVANCED_JS_MAX_ENDPOINTS:
                    break
            if len(endpoints) >= ADVANCED_JS_MAX_ENDPOINTS:
                break
        if len(endpoints) >= ADVANCED_JS_MAX_ENDPOINTS:
            break

    summary = (
        f"Extracted {len(endpoints)} JS/API endpoint candidate(s) from bounded response bodies."
        if endpoints
        else "No JS/API endpoint candidates were extracted from the bounded response bodies."
    )
    return {
        "enabled": True,
        "summary": summary,
        "count": len(endpoints),
        "endpoints": endpoints[:ADVANCED_JS_MAX_ENDPOINTS],
        "parameters": params[:ADVANCED_JS_MAX_PARAMS],
        "bounded": True,
    }


def _normalize_endpoint_candidate(raw_value: str) -> str:
    value = (raw_value or "").strip()
    if not value:
        return ""
    if "${" in value:
        return ""
    lowered = value.lower()
    if lowered.startswith("javascript:") or lowered.startswith("data:"):
        return ""
    parsed = urlparse(value)
    path = parsed.path or ""
    if not path and value.startswith("/"):
        path = value
    if not path:
        return ""
    path_lower = path.lower()
    if not any(token in path_lower for token in ("/api", "/graphql", "/v1/", "/v2/", "/v3/")):
        return ""
    query = parsed.query or ""
    normalized = path if not query else f"{path}?{query}"
    return normalized[:180]


def _race_signal_check(plan: dict[str, Any], observations: list[dict[str, Any]], ranked_items: list[dict[str, Any]]) -> dict[str, Any]:
    classes = _race_classes_from_plan(plan)
    if not (set(classes) & ADVANCED_RACE_ALLOWED_CLASSES):
        return {
            "enabled": True,
            "summary": "Race signal checks were requested but skipped because the issue class is outside the allowed bounded set.",
            "eligible": False,
            "bounded": True,
            "inconsistent": False,
            "candidate_group": "",
            "signals": [],
        }

    sample_items = list(ranked_items[:ADVANCED_RACE_MAX_OBSERVATIONS])
    if len(sample_items) < ADVANCED_RACE_MIN_OBSERVATIONS:
        return {
            "enabled": True,
            "summary": "Race signal checks need at least three observations for bounded inconsistency detection.",
            "eligible": True,
            "bounded": True,
            "inconsistent": False,
            "candidate_group": "",
            "signals": [],
        }

    groups: dict[str, list[dict[str, Any]]] = {}
    for item in sample_items:
        key = str(item.get("request_ref") or item.get("mutation_family") or item.get("tab_name") or "").strip().lower()
        if not key:
            key = "default"
        groups.setdefault(key, []).append(item)

    best_group_key = ""
    best_signals: list[str] = []
    for key, items in groups.items():
        if len(items) < ADVANCED_RACE_MIN_OBSERVATIONS:
            continue
        statuses = {int(item.get("status_code") or 0) for item in items}
        lengths = [int(item.get("body_length_delta") or 0) for item in items]
        scores = [float(item.get("score") or 0.0) for item in items]
        signals: list[str] = []
        if len(statuses) > 1:
            signals.append("Status codes changed across near-identical race candidates.")
        if lengths and (max(lengths) - min(lengths)) >= 180:
            signals.append("Body length deltas were inconsistent across race candidates.")
        if scores and (max(scores) - min(scores)) >= 1.0:
            signals.append("Delta scores varied materially across race candidates.")
        if signals and len(signals) > len(best_signals):
            best_group_key = key
            best_signals = signals

    inconsistent = bool(best_signals)
    summary = (
        f"Race signal check flagged inconsistent responses in group `{best_group_key}`."
        if inconsistent
        else "Race signal check found no inconsistent response pattern in bounded observations."
    )
    return {
        "enabled": True,
        "summary": summary,
        "eligible": True,
        "bounded": True,
        "inconsistent": inconsistent,
        "candidate_group": best_group_key,
        "signals": best_signals[:4],
        "sample_count": len(sample_items),
        "class_scope": classes[:4],
    }


def _race_classes_from_plan(plan: dict[str, Any]) -> list[str]:
    classes: list[str] = []
    for candidate in [
        ((plan.get("dashboard_issue") or {}).get("vuln_hint") or ""),
        *[item.get("vuln_hint") or "" for item in list(plan.get("related_scanner_issues") or [])[:4] if isinstance(item, dict)],
    ]:
        normalized = str(candidate or "").strip().lower()
        if normalized and normalized not in classes:
            classes.append(normalized)
    return classes or ["general"]


def _to_payload_dict(payload_like) -> dict[str, Any]:
    if isinstance(payload_like, dict):
        return dict(payload_like)
    if hasattr(payload_like, "model_dump"):
        return payload_like.model_dump()
    if hasattr(payload_like, "dict"):
        return payload_like.dict()
    return dict(vars(payload_like))
