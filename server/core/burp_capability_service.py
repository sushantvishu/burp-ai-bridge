from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from server.burp_asset_feedback import asset_feedback_scores
from server.burp_mcp_adapter import inspect_burp_mcp_capabilities
from server.core.analysis_service import coerce_payload
from server.core.burp_context_service import get_dashboard_issue_context
from server.memory_partition import partition_from_payload
from server.kali_tools import CLASS_TOOL_MAP, TOOL_DEFINITIONS

ASSETS_DIR = Path(__file__).resolve().parents[1] / "burp_assets"
CUSTOM_SCAN_CHECKS_DIR = ASSETS_DIR / "custom_scan_checks"
BAMBDA_DIR = ASSETS_DIR / "bambda"


def recommend_burp_capabilities(payload_like, *, impact: dict | None = None) -> dict[str, Any]:
    payload = coerce_payload(payload_like)
    impact = dict(impact or {})
    issue = get_dashboard_issue_context(payload)
    capability_inspection = inspect_burp_mcp_capabilities()
    capability_map = capability_inspection.get("capability_map") or {}
    vuln_class = _normalize_vuln_class(
        ((impact.get("dashboard_issue") or {}).get("vuln_hint"))
        or issue.get("vuln_hint")
        or "general"
    )
    starter_assets = burp_starter_assets(vuln_class, payload_like=payload)

    recommendations = []
    for entry in _capability_profiles(vuln_class):
        capability_name = entry["capability"]
        capability_state = capability_map.get(capability_name) or {}
        allowed = bool(capability_state.get("allowed"))
        asset_binding = _recommended_asset_binding(entry["tool"], starter_assets)
        recommendations.append({
            "tool": entry["tool"],
            "capability": capability_name,
            "available": allowed,
            "why": entry["why"],
            "manual_step": entry["manual_step"],
            "expected_signal": entry["expected_signal"],
            "stop_when": entry["stop_when"],
            "mcp_tool_name": capability_state.get("tool_name", ""),
            "mode": capability_state.get("mode", "manual"),
            "recommended_asset_type": asset_binding.get("asset_type", ""),
            "recommended_asset_id": asset_binding.get("asset_id", ""),
            "recommended_asset_name": asset_binding.get("asset_name", ""),
            "recommended_asset_path": asset_binding.get("asset_path", ""),
        })

    return {
        "primary_context_source": "burp_mcp" if capability_inspection.get("server_name") else "request-only",
        "recommendations": recommendations,
        "starter_assets": starter_assets,
        "curated_bapp_categories": [
            "passive signal collection",
            "API visibility",
            "Collaborator-style evidence",
            "payload encoding and decoding",
            "reporting and export",
        ],
        "external_tool_recommendations": external_tool_recommendations(vuln_class),
    }


def burp_starter_assets(vuln_class: str = "", *, payload_like=None) -> dict[str, Any]:
    normalized = _normalize_vuln_class(vuln_class)
    partition_key = partition_from_payload(payload_like) if payload_like is not None else ""
    custom_manifest = _load_json(CUSTOM_SCAN_CHECKS_DIR / "manifest.json")
    bambda_manifest = _load_json(BAMBDA_DIR / "manifest.json")
    custom_feedback = asset_feedback_scores(
        partition_key=partition_key,
        vuln_class=normalized,
        asset_type="custom_scan_check",
    )
    bambda_feedback = asset_feedback_scores(
        partition_key=partition_key,
        vuln_class=normalized,
        asset_type="bambda",
    )
    custom_scan_checks = [
        _decorate_asset_feedback(item, custom_feedback.get(str(item.get("id", "")), {}), manifest_index=index)
        for index, item in enumerate(custom_manifest.get("packs", []))
        if not normalized or normalized in [str(v).lower() for v in item.get("applies_to", [])]
    ]
    bambda_packs = [
        _decorate_asset_feedback(item, bambda_feedback.get(str(item.get("id", "")), {}), manifest_index=index)
        for index, item in enumerate(bambda_manifest.get("packs", []))
        if not normalized or normalized in [str(v).lower() for v in item.get("applies_to", [])]
    ]
    custom_scan_checks.sort(key=_custom_scan_check_sort_key)
    bambda_packs.sort(key=_bambda_sort_key)
    custom_scan_checks = [_clean_asset_metadata(item) for item in custom_scan_checks[:8]]
    bambda_packs = [_clean_asset_metadata(item) for item in bambda_packs[:8]]
    feedback_applied = any((item.get("feedback_score") or 0) != 0 for item in [*custom_scan_checks, *bambda_packs])
    return {
        "manifest_version": {
            "custom_scan_checks": custom_manifest.get("manifest_version", ""),
            "bambda": bambda_manifest.get("manifest_version", ""),
        },
        "custom_scan_checks": custom_scan_checks,
        "bambda_packs": bambda_packs,
        "recommended_import_order": _recommended_import_order(custom_scan_checks, bambda_packs),
        "usage_notes": _starter_usage_notes(normalized, feedback_applied=feedback_applied),
        "feedback_partition_key": partition_key,
        "feedback_applied": feedback_applied,
        "paths": {
            "custom_scan_checks_dir": str(CUSTOM_SCAN_CHECKS_DIR),
            "bambda_dir": str(BAMBDA_DIR),
            "root_dir": str(ASSETS_DIR),
            "readme": str(ASSETS_DIR / "README.md"),
            "custom_scan_checks_readme": str(CUSTOM_SCAN_CHECKS_DIR / "README.md"),
            "bambda_readme": str(BAMBDA_DIR / "README.md"),
        },
    }


def external_tool_recommendations(vuln_class: str) -> list[dict[str, Any]]:
    normalized = (vuln_class or "general").strip().lower()
    tool_names = CLASS_TOOL_MAP.get(normalized, ["curl", "jq", "httpx", "ffuf", "nuclei"])
    bounded = []
    for name in tool_names[:6]:
        definition = TOOL_DEFINITIONS.get(name)
        if not definition:
            continue
        bounded.append({
            "name": name,
            "summary": definition["summary"],
            "repo_url": definition["repo_url"],
            "install_hint": definition["install_hint"],
        })
    if normalized in {"sqli", "injection"}:
        bounded.append({
            "name": "sqlmap",
            "summary": "Only after a concrete manual hypothesis and explicit scope allowance.",
            "repo_url": TOOL_DEFINITIONS["sqlmap"]["repo_url"],
            "install_hint": TOOL_DEFINITIONS["sqlmap"]["install_hint"],
        })
    return bounded[:8]


def _capability_profiles(vuln_class: str) -> list[dict[str, str]]:
    generic = [
        {
            "tool": "Repeater",
            "capability": "send_to_repeater",
            "why": "Use Repeater for one bounded change at a time on the scanner-marked request family.",
            "manual_step": "Open the planned tab set, send the baseline first, then send only one variant before comparing the diff.",
            "expected_signal": "Stable status, body, or trust-boundary delta tied to one exact mutation.",
            "stop_when": "A single reproducible high-signal delta is captured.",
        },
        {
            "tool": "Logger",
            "capability": "proxy_history",
            "why": "Use Logger or proxy history to compare session, role, or state transitions on the same endpoint.",
            "manual_step": "Filter the matching requests and compare the baseline against the strongest variant side by side.",
            "expected_signal": "Clean request-response diffs with less noise than repeated manual note taking.",
            "stop_when": "You have one clear baseline and one stronger proof artifact.",
        },
        {
            "tool": "Custom Scan Check",
            "capability": "scanner_issues",
            "why": "Use a trusted custom check when the same vuln family repeats and you want consistent low-noise validation.",
            "manual_step": "Import the matching starter check pack, run it only on the bounded request family, and review the issue details before escalating.",
            "expected_signal": "Repeatable scanner signal for the same class without broad fuzzing.",
            "stop_when": "The check adds one useful proof artifact or no longer improves signal.",
        },
        {
            "tool": "Bambda",
            "capability": "active_editor",
            "why": "Use a Bambda for extraction, tagging, and request marking when you need more context rather than more payloads.",
            "manual_step": "Import the matching Bambda pack, run it in the relevant view, and use it to mark identifiers, reflection points, or role-sensitive fields.",
            "expected_signal": "Cleaner target selection and lower-noise manual follow-up.",
            "stop_when": "The marked context is precise enough for one bounded next step.",
        },
    ]
    by_class = {
        "idor": [
            {
                "tool": "Intruder",
                "capability": "start_intruder_attack",
                "why": "Use Intruder only for bounded identifier validation after one manual role-separated diff exists.",
                "manual_step": "Queue a very small identifier list or object family list from the marked field and compare only status and ownership-related fields.",
                "expected_signal": "A second unauthorized object or list-scoped authorization mismatch.",
                "stop_when": "You prove the boundary cleanly or the identifier family stops producing meaningful deltas.",
            },
        ],
        "bola": [
            {
                "tool": "Intruder",
                "capability": "start_intruder_attack",
                "why": "Use Intruder only for narrow API object validation once the first unauthorized object is confirmed.",
                "manual_step": "Test a very small object set from the same tenant or adjacent tenant scope; do not broaden beyond the exact operation family.",
                "expected_signal": "Another unauthorized object fetch or update in the same API operation.",
                "stop_when": "The pattern is reproducible enough for reporting.",
            },
        ],
        "stored-xss": [
            {
                "tool": "Logger",
                "capability": "proxy_history",
                "why": "Use Logger or history to keep the storage request and the privileged/shared viewer request tied together.",
                "manual_step": "Mark the storage request, then locate the matching viewer request and keep both in one evidence chain.",
                "expected_signal": "A clean storage artifact plus a separate privileged render artifact.",
                "stop_when": "You have one bounded shared or admin-view render proof.",
            },
        ],
        "ssrf": [
            {
                "tool": "Collaborator",
                "capability": "collaborator_interactions",
                "why": "Use Collaborator when the safest next proof is a bounded callback or fetch confirmation.",
                "manual_step": "Generate one payload, place it only in the scanner-marked sink, and correlate the callback with the exact request variant.",
                "expected_signal": "A single callback or interaction tied to one request change.",
                "stop_when": "A bounded callback is confirmed or the sink shows no callback behavior.",
            },
        ],
        "xxe": [
            {
                "tool": "Collaborator",
                "capability": "collaborator_interactions",
                "why": "Use Collaborator only when parser behavior is already confirmed and you need one bounded out-of-band confirmation.",
                "manual_step": "Send one benign parser-controlled variant and correlate any callback with that exact request.",
                "expected_signal": "One parser-linked callback or benign reachability artifact.",
                "stop_when": "The parser behavior is clearly proven or the callback path is absent.",
            },
        ],
    }
    return [*generic, *(by_class.get(vuln_class, []))]


def _recommended_asset_binding(tool_name: str, starter_assets: dict[str, Any]) -> dict[str, str]:
    tool = (tool_name or "").strip().lower()
    if tool == "custom scan check":
        first = next(iter(starter_assets.get("custom_scan_checks") or []), {})
        return {
            "asset_type": "custom_scan_check",
            "asset_id": str(first.get("id", "")),
            "asset_name": str(first.get("name", "")),
            "asset_path": str(first.get("path", "")),
        }
    if tool == "bambda":
        first = next(iter(starter_assets.get("bambda_packs") or []), {})
        return {
            "asset_type": "bambda",
            "asset_id": str(first.get("id", "")),
            "asset_name": str(first.get("name", "")),
            "asset_path": str(first.get("path", "")),
        }
    return {}


def _recommended_import_order(custom_scan_checks: list[dict[str, Any]], bambda_packs: list[dict[str, Any]]) -> list[str]:
    order = []
    if bambda_packs:
        order.append(f"Import Bambda pack first: {bambda_packs[0].get('name', 'starter pack')}")
    if custom_scan_checks:
        order.append(f"Then import custom scan check: {custom_scan_checks[0].get('name', 'starter check')}")
    order.append("Use MCP-hydrated scanner context to scope the check to one bounded request family.")
    order.append("Stop after one reproducible high-signal artifact is captured.")
    return order


def _starter_usage_notes(vuln_class: str, *, feedback_applied: bool = False) -> list[str]:
    notes = [
        "These packs are tuned starter assets, not blanket scans. Keep them scoped to the MCP-selected issue family.",
        "Prefer one passive or bounded active custom check plus one extraction-oriented Bambda, not multiple broad packs at once.",
        "Use Burp MCP context and panel-state output to confirm the exact request family before importing a pack.",
    ]
    if feedback_applied:
        notes.append("Pack ordering now reflects prior target-specific signal and false-positive feedback for this vuln family.")
    if vuln_class in {"idor", "bola", "api-bola", "mass-assignment"}:
        notes.append("For object-boundary classes, pair identifier-marking Bambdas with one role-separated boundary check.")
    if vuln_class in {"stored-xss", "xss"}:
        notes.append("For stored XSS, separate storage-path evidence from viewer-path evidence and stop once one privileged or shared render is proven.")
    if vuln_class in {"ssrf", "xxe"}:
        notes.append("For SSRF and XXE, keep callback checks bounded and correlate the interaction with one exact request variant.")
    return notes


def _normalize_vuln_class(vuln_class: str) -> str:
    normalized = (vuln_class or "").strip().lower()
    alias_map = {
        "authorization": "idor",
        "access-control": "idor",
        "access control": "idor",
        "stored xss": "stored-xss",
        "auth bypass": "auth-bypass",
        "business logic": "business-logic",
        "mass assignment": "mass-assignment",
    }
    return alias_map.get(normalized, normalized)


def _decorate_asset_feedback(item: dict[str, Any], feedback: dict[str, Any], *, manifest_index: int = 0) -> dict[str, Any]:
    value = dict(item)
    labels = dict(feedback.get("labels") or {})
    value["_manifest_index"] = manifest_index
    value["feedback_score"] = int(feedback.get("score") or 0)
    value["feedback_partition_score"] = int(feedback.get("partition_score") or 0)
    value["feedback_class_score"] = int(feedback.get("class_score") or 0)
    value["positive_feedback_count"] = int(feedback.get("positive_count") or 0)
    value["negative_feedback_count"] = int(feedback.get("negative_count") or 0)
    value["feedback_labels"] = labels
    return value


def _custom_scan_check_sort_key(item: dict[str, Any]) -> tuple[int, int, int, str]:
    noise_rank = {"low": 0, "medium": 1, "high": 2}.get(str(item.get("noise_profile", "")).strip().lower(), 3)
    scan_mode_rank = {"passive": 0, "bounded-active": 1}.get(str(item.get("scan_mode", "")).strip().lower(), 2)
    return (
        -int(item.get("feedback_score") or 0),
        noise_rank,
        scan_mode_rank,
        int(item.get("_manifest_index") or 0),
    )


def _bambda_sort_key(item: dict[str, Any]) -> tuple[int, int]:
    return (
        -int(item.get("feedback_score") or 0),
        int(item.get("_manifest_index") or 0),
    )


def _clean_asset_metadata(item: dict[str, Any]) -> dict[str, Any]:
    value = dict(item)
    value.pop("_manifest_index", None)
    return value


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
