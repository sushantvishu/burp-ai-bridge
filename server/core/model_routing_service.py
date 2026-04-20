from __future__ import annotations

from typing import Any

from server.core.runtime_model_override_service import get_active_ollama_model, read_runtime_model_override
from server.settings import (
    AUTO_MODEL_ROUTING_ENABLED,
    MODEL_ROUTING_DEEP_MIN_SIGNAL_COUNT,
    MODEL_ROUTING_DEEP_SCORE_THRESHOLD,
    MODEL_ROUTING_FAST_SCORE_THRESHOLD,
    OLLAMA_CODE_MODEL,
    OLLAMA_DEEP_MODEL,
    OLLAMA_FAST_MODEL,
)

HIGH_RISK_CLASSES = {
    "access-control",
    "authentication",
    "business-logic",
    "deserialization",
    "graphql",
    "http-request-smuggling",
    "jwt-token",
    "mass-assignment",
    "race-condition",
    "sqli",
    "ssrf",
    "ssti",
    "xxe",
}


def choose_ollama_model_for_request(
    payload,
    *,
    profile_name: str = "",
    rule_context: dict | None = None,
    fallback: dict | None = None,
) -> dict[str, Any]:
    active_model = get_active_ollama_model()
    override = read_runtime_model_override()
    manual_override = str((override or {}).get("active_model") or "").strip()
    route = "active-default"
    score = 0
    reasons: list[str] = []
    signal_count = 0

    if manual_override:
        return {
            "model": active_model,
            "route": "manual-override",
            "score": 0,
            "request_type": _request_type(payload),
            "signal_count": 0,
            "reasons": [f"Manual runtime model override is active: {manual_override}."],
        }

    if not AUTO_MODEL_ROUTING_ENABLED:
        return {
            "model": active_model,
            "route": "auto-routing-disabled",
            "score": 0,
            "request_type": _request_type(payload),
            "signal_count": 0,
            "reasons": ["Automatic local-model routing is disabled in configuration."],
        }

    normalized_profile = (profile_name or "").strip().lower()
    if "deep-escalation" in normalized_profile:
        score += 2
        signal_count += 1
        reasons.append("The selected profile is the deep escalation/reporting profile.")
    elif "coder-assist" in normalized_profile:
        return {
            "model": OLLAMA_CODE_MODEL or active_model,
            "route": "profile-code",
            "score": 0,
            "request_type": _request_type(payload),
            "signal_count": 0,
            "reasons": ["The selected profile is for bridge/code maintenance work."],
        }
    elif "low-resource" in normalized_profile:
        return {
            "model": OLLAMA_FAST_MODEL or active_model,
            "route": "profile-fast",
            "score": 0,
            "request_type": _request_type(payload),
            "signal_count": 0,
            "reasons": ["The selected profile prefers the lighter local model for CPU-bound triage."],
        }

    annotations = {str(item).strip().lower() for item in (getattr(payload, "annotations", None) or []) if str(item).strip()}
    source_tool = (getattr(payload, "source_tool", "") or "").strip().lower()
    request_type = _request_type(payload)
    time_budget = "balanced"
    if "time_budget_fast" in annotations:
        time_budget = "fast"
    elif "time_budget_deep" in annotations:
        time_budget = "deep"
    scanner_context = "scanner" in source_tool or any("scanner" in item or "audit_issue" in item for item in annotations)
    operator_followup = "operator_followup" in annotations
    workflow_notes = bool(getattr(payload, "issue_workflow_notes", None))
    notebook_text = bool((getattr(payload, "investigation_notebook_text", "") or "").strip())
    if scanner_context:
        score += 2
        signal_count += 1
        reasons.append("Burp Scanner or Dashboard issue context is attached.")

    collaborator_evidence = bool((getattr(payload, "collaborator_evidence_text", "") or "").strip())
    logger_evidence = bool((getattr(payload, "logger_evidence_text", "") or "").strip())
    response_delta_evidence = bool((getattr(payload, "response_delta_text", "") or "").strip())
    timeline_evidence = bool(getattr(payload, "evidence_timeline_entries", None))
    bapp_context = bool((getattr(payload, "bapp_findings_text", "") or "").strip())
    observed_evidence = any([collaborator_evidence, logger_evidence, response_delta_evidence, timeline_evidence])

    if collaborator_evidence:
        score += 2
        signal_count += 1
        reasons.append("Collaborator evidence is present.")
    if logger_evidence:
        score += 1
        signal_count += 1
        reasons.append("Logger or manual diff evidence is present.")
    if response_delta_evidence:
        score += 1
        signal_count += 1
        reasons.append("An explicit response delta was supplied.")
    if timeline_evidence:
        score += 1
        signal_count += 1
        reasons.append("An evidence timeline is attached.")
    if bapp_context:
        score += 1
        signal_count += 1
        reasons.append("Supplemental BApp or scanner finding text is attached.")
    if workflow_notes:
        score += 1
        signal_count += 1
        reasons.append("Prior investigation workflow notes are attached.")
    if notebook_text:
        score += 1
        signal_count += 1
        reasons.append("A persistent investigation notebook is attached.")

    matched = list((rule_context or {}).get("matched_recipes", []) or [])
    high_risk_class = ""
    if matched:
        score += 1
        signal_count += 1
        reasons.append("Deterministic playbooks matched the exchange.")
        top_class = str(matched[0].get("vuln_class") or "").strip().lower()
        if top_class in HIGH_RISK_CLASSES:
            high_risk_class = top_class
            score += 1
            signal_count += 1
            reasons.append(f"The matched vulnerability class `{top_class}` benefits from deeper reasoning and stricter report wording.")

    confidence_lines = list((fallback or {}).get("confidence_by_class", []) or [])
    if any("0.8" in item or "0.9" in item or "high" in item.lower() for item in confidence_lines):
        score += 1
        signal_count += 1
        reasons.append("The deterministic baseline already shows relatively strong confidence.")

    deep_threshold = max(1, int(MODEL_ROUTING_DEEP_SCORE_THRESHOLD or 1))
    deep_min_signals = max(1, int(MODEL_ROUTING_DEEP_MIN_SIGNAL_COUNT or 1))
    fast_threshold = max(0, int(MODEL_ROUTING_FAST_SCORE_THRESHOLD or 0))
    deep_eligible_case = bool(scanner_context and observed_evidence)
    scanner_followup_deep_case = bool(scanner_context and operator_followup and (workflow_notes or notebook_text))

    if time_budget == "deep":
        return {
            "model": OLLAMA_DEEP_MODEL or active_model,
            "route": "budget-deep",
            "score": score,
            "request_type": request_type,
            "signal_count": signal_count,
            "reasons": [
                "The operator selected the deep time budget, so the bridge is allowed to use the deeper local model immediately."
            ]
            + reasons[:5],
        }

    if time_budget == "fast":
        fast_model = OLLAMA_FAST_MODEL or active_model
        fast_route_model = fast_model if request_type in {"proxy", "repeater", "intruder", "unknown"} else active_model
        fast_route = "budget-fast" if fast_route_model == fast_model else "budget-fast-primary"
        return {
            "model": fast_route_model,
            "route": fast_route,
            "score": score,
            "request_type": request_type,
            "signal_count": signal_count,
            "reasons": [
                "The operator selected the fast time budget, so the bridge disables deep routing for this request."
            ]
            + reasons[:5],
        }

    if scanner_followup_deep_case:
        return {
            "model": OLLAMA_DEEP_MODEL or active_model,
            "route": "scanner-follow-up-deep",
            "score": score,
            "request_type": request_type,
            "signal_count": signal_count,
            "reasons": [
                "This is an operator follow-up on a selected scanner issue with preserved investigation context, so the bridge uses the deeper local model."
            ]
            + reasons[:5],
        }

    if scanner_context and not observed_evidence:
        reasons.append("Scanner context is present, but there is no observed evidence yet, so the bridge stays on the lighter primary model.")

    if score >= deep_threshold and signal_count >= deep_min_signals and deep_eligible_case:
        route = "auto-deep"
        return {
            "model": OLLAMA_DEEP_MODEL or active_model,
            "route": route,
            "score": score,
            "request_type": request_type,
            "signal_count": signal_count,
            "reasons": reasons[:6] or ["High-signal evidence justified the deeper local model."],
        }

    if request_type in {"repeater", "intruder", "proxy", "unknown"} and score <= fast_threshold:
        return {
            "model": OLLAMA_FAST_MODEL or active_model,
            "route": "triage-fast",
            "score": score,
            "request_type": request_type,
            "signal_count": signal_count,
            "reasons": reasons[:6] or ["Low-signal triage request was routed to the fast model."],
        }

    return {
        "model": active_model,
        "route": "triage-default" if request_type in {"scanner", "repeater", "intruder", "proxy", "unknown"} else route,
        "score": score,
        "request_type": request_type,
        "signal_count": signal_count,
        "reasons": reasons[:6] or ["No strong evidence required routing away from the active local model."],
    }


def _request_type(payload) -> str:
    source_tool = (getattr(payload, "source_tool", "") or "").strip().lower()
    annotations = {str(item).strip().lower() for item in (getattr(payload, "annotations", None) or []) if str(item).strip()}
    if "scanner" in source_tool or any("scanner" in item or "audit_issue" in item for item in annotations):
        return "scanner"
    if "repeater" in source_tool:
        return "repeater"
    if "intruder" in source_tool:
        return "intruder"
    if "proxy" in source_tool:
        return "proxy"
    if source_tool:
        return source_tool
    return "unknown"
