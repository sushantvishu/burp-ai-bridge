from urllib.parse import urlparse

from server.privacy_utils import normalize_privacy_mode
from server.profiles import normalize_profile_name
from server.core.runtime_model_override_service import get_active_ollama_model
from server.settings import PRIVACY_MODE, SKIP_MODEL_FOR_LOW_SIGNAL

STATIC_ASSET_EXTENSIONS = {
    ".webmanifest", ".json", ".map", ".txt", ".xml", ".css", ".js",
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
}


def apply_memory_hints(aggregate: dict, memory_summary: dict, append_manual_tooling, append_manual_commands) -> dict:
    if not memory_summary.get("total_hits"):
        return aggregate

    enriched = dict(aggregate)
    analysis = enriched.get("analysis", "")
    analysis = (
        f"{analysis}\n\nPrior local memory:\n"
        f"- {memory_summary['note']}"
    )
    if memory_summary.get("top_targets"):
        analysis += "\n- Similar prior targets: " + ", ".join(memory_summary["top_targets"])
    if memory_summary.get("preferred_kb_titles"):
        analysis += "\n- Confirmed local KB notes to prioritize: " + ", ".join(memory_summary["preferred_kb_titles"])
    if memory_summary.get("deprioritized_kb_titles"):
        analysis += "\n- Local KB notes recently deprioritized: " + ", ".join(memory_summary["deprioritized_kb_titles"])
    enriched["analysis"] = append_manual_tooling(analysis, enriched.get("manual_tooling", []))
    enriched["analysis"] = append_manual_commands(enriched["analysis"], enriched.get("manual_commands", []))

    questions = list(enriched.get("questions_for_user", []))
    if memory_summary.get("exact_matches"):
        exact_match_question = (
            "Do you want to compare this response against prior captures of the same normalized endpoint to confirm whether the behavior is stable or role-dependent?"
        )
        if exact_match_question not in questions:
            questions.append(exact_match_question)
    enriched["questions_for_user"] = questions[:3]
    return enriched


def apply_operator_context(aggregate: dict, payload) -> dict:
    enriched = dict(aggregate)
    operator_answers = getattr(payload, "operator_answers", None) or {}
    tool_help_text = getattr(payload, "tool_help_text", "") or ""
    context_lines = []

    if operator_answers:
        context_lines.append("Operator answers received:")
        for question, answer in operator_answers.items():
            normalized_answer = (answer or "").strip()
            if normalized_answer:
                context_lines.append(f"- {question}: {normalized_answer}")

    if tool_help_text.strip():
        context_lines.append(
            "Tool help text received for command shaping. Use it only to choose safe syntax and conservative rate limits, not to evade defensive controls."
        )
    if (getattr(payload, "scope_includes_text", "") or "").strip() or (getattr(payload, "scope_excludes_text", "") or "").strip():
        context_lines.append("Program scope details were provided and should constrain any proposed follow-up.")
    if (getattr(payload, "rate_limit_text", "") or "").strip() or (getattr(payload, "max_concurrency_text", "") or "").strip():
        context_lines.append("Program rate or concurrency limits were provided and should bound any suggested command.")
    if (getattr(payload, "custom_headers_text", "") or "").strip():
        context_lines.append("Custom headers were provided and should be carried into compatible command templates.")
    if (getattr(payload, "tool_results_text", "") or "").strip():
        context_lines.append("Manual tool results or file references were supplied for evidence-based follow-up.")
    if (getattr(payload, "loaded_burp_tools_text", "") or "").strip():
        context_lines.append("Loaded Burp tools or BApps were supplied and should be preferred before missing external tools.")
    if (getattr(payload, "response_delta_text", "") or "").strip():
        context_lines.append("An explicit response-delta note was supplied for the latest approved comparison.")
    if (getattr(payload, "logger_evidence_text", "") or "").strip():
        context_lines.append("Logger++ evidence was supplied and should be treated as higher-signal request or response diff evidence.")
    if (getattr(payload, "collaborator_evidence_text", "") or "").strip():
        context_lines.append("Collaborator-related observations were supplied for passive interpretation and report wording.")
    if getattr(payload, "evidence_timeline_entries", None):
        context_lines.append(
            f"Evidence timeline entries were supplied ({len(getattr(payload, 'evidence_timeline_entries', []))} item(s)) and should be used as a sequence of prior observations."
        )
    if getattr(payload, "issue_workflow_notes", None):
        context_lines.append(
            f"Prior investigation workflow notes were supplied ({len(getattr(payload, 'issue_workflow_notes', []))} item(s)) and should be used as carry-forward context for the next exact step."
        )
    if (getattr(payload, "investigation_notebook_text", "") or "").strip():
        context_lines.append("A persistent investigation notebook was supplied and should be treated as the longer-running case memory for this finding.")

    if context_lines:
        enriched["analysis"] = f"{enriched.get('analysis', '')}\n\n" + "\n".join(context_lines)
        questions = list(enriched.get("questions_for_user", []))
        if operator_answers:
            confirmation_question = "Do you want the next follow-up to narrow to one confirmed hypothesis based on your answers?"
            if confirmation_question not in questions:
                questions.append(confirmation_question)
        enriched["questions_for_user"] = questions[:3]

    return enriched


def fallback_analysis(
    payload,
    rule_context: dict,
    memory_summary: dict,
    *,
    reason: str | None = None,
    append_manual_tooling,
    append_manual_commands,
    append_direct_follow_up_answer,
) -> dict:
    aggregate = dict(rule_context["aggregate"])
    aggregate = apply_memory_hints(aggregate, memory_summary, append_manual_tooling, append_manual_commands)
    aggregate = apply_operator_context(aggregate, payload)
    aggregate["analysis"] = append_direct_follow_up_answer(aggregate.get("analysis", ""), payload, rule_context)
    complexity = rule_context["complexity"]
    profile_name = normalize_profile_name(getattr(payload, "selected_profile", ""))
    review_scope = rule_context.get("review_scope", {})
    aggregate["analysis"] = (
        f"Profile: {profile_name}\n"
        f"Review scope classes: {', '.join(review_scope.get('allowed_classes', [])) or '<none>'}\n"
        f"Model: {get_active_ollama_model()}\n"
        f"Complexity estimate: {complexity['level']} ({complexity['eta']}). "
        f"{complexity['recommendation']}\n\n{aggregate['analysis']}"
    )
    if reason:
        aggregate["analysis"] = f"{aggregate['analysis']}\n\nModel refinement unavailable: {reason}"
        questions = list(aggregate.get("questions_for_user", []))
        complexity_question = (
            "Do you want to reduce scope and test one request or one hypothesis at a time to shorten local analysis time?"
        )
        if complexity_question not in questions:
            questions.append(complexity_question)
        aggregate["questions_for_user"] = questions[:3]
    return aggregate


def build_kb_query(payload, rule_context: dict) -> str:
    recipe_titles = [recipe["title"] for recipe in rule_context["matched_recipes"][:3]]
    param_names = rule_context["features"]["param_names"][:6]
    query_parts = [
        payload.target_url or "",
        payload.http_method or "",
        " ".join(recipe_titles),
        " ".join(param_names),
    ]
    return " ".join(part for part in query_parts if part).strip()


def looks_like_static_asset(payload, rule_context: dict) -> bool:
    parsed = urlparse(getattr(payload, "target_url", "") or "")
    path = (parsed.path or "").lower()
    if any(path.endswith(extension) for extension in STATIC_ASSET_EXTENSIONS):
        return True

    response_content_type = (rule_context["features"].get("response_content_type") or "").lower()
    request_content_type = (rule_context["features"].get("request_content_type") or "").lower()
    if any(marker in response_content_type for marker in ("image/", "font/", "text/css", "javascript", "manifest")):
        return True
    if path.endswith("/site.webmanifest") or path.endswith("/manifest.json"):
        return True
    return False


def has_extra_operator_context(payload) -> bool:
    return any([
        bool(getattr(payload, "operator_answers", None)),
        bool((getattr(payload, "tool_help_text", "") or "").strip()),
        bool((getattr(payload, "scope_includes_text", "") or "").strip()),
        bool((getattr(payload, "scope_excludes_text", "") or "").strip()),
        bool((getattr(payload, "rate_limit_text", "") or "").strip()),
        bool((getattr(payload, "max_concurrency_text", "") or "").strip()),
        bool((getattr(payload, "custom_headers_text", "") or "").strip()),
        bool((getattr(payload, "program_policy_text", "") or "").strip()),
        bool((getattr(payload, "saved_program_policy_text", "") or "").strip()),
        bool((getattr(payload, "tool_results_text", "") or "").strip()),
        bool((getattr(payload, "burp_config_export_text", "") or "").strip()),
        bool((getattr(payload, "burp_screenshot_audit_text", "") or "").strip()),
        bool((getattr(payload, "loaded_burp_tools_text", "") or "").strip()),
        bool((getattr(payload, "program_screenshot_audit_text", "") or "").strip()),
        bool((getattr(payload, "response_delta_text", "") or "").strip()),
        bool((getattr(payload, "bapp_findings_text", "") or "").strip()),
        bool((getattr(payload, "logger_evidence_text", "") or "").strip()),
        bool((getattr(payload, "collaborator_evidence_text", "") or "").strip()),
        bool(getattr(payload, "evidence_timeline_entries", None)),
        bool(getattr(payload, "issue_workflow_notes", None)),
        bool((getattr(payload, "investigation_notebook_text", "") or "").strip()),
    ])


def skip_model_reason(payload, rule_context: dict) -> str | None:
    if not SKIP_MODEL_FOR_LOW_SIGNAL:
        return None

    if looks_like_static_asset(payload, rule_context):
        if has_extra_operator_context(payload):
            return None
        return "The selected exchange looks like a static asset or manifest and no extra operator context was supplied, so model refinement was skipped."

    if rule_context["complexity"]["level"] == "low" and not rule_context["matched_recipes"] and not has_extra_operator_context(payload):
        return "No strong deterministic signal or extra operator context was present, so model refinement was skipped."

    return None


def effective_privacy_mode(payload) -> str:
    return normalize_privacy_mode(getattr(payload, "privacy_mode_override", "") or PRIVACY_MODE, PRIVACY_MODE)
