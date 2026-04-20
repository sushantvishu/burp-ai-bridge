import json

import requests

from server.core.burp_context_service import get_dashboard_issue_context
from server.core.escalation_service import normalize_vuln_class
from server.core.investigation_intelligence_service import (
    build_investigation_intelligence,
    summarize_branch_guard,
    summarize_confidence_calibration,
    summarize_contradiction_assessment,
    summarize_counter_hypothesis,
    summarize_cross_issue_cluster,
    summarize_evidence_sufficiency,
    summarize_impact_path_ranking,
    summarize_phase_state,
    summarize_report_bundle,
    summarize_response_diff_semantics,
    summarize_vulnerability_state_machine,
)
from server.mcp_client import MCPConfigurationError, MCPError
from server.review_dataset import query_review_examples


def execute_advisory_flow(payload, *, helpers: dict, constants: dict) -> dict:
    request_id = getattr(payload, "request_id", "") or ""
    privacy_mode = helpers["effective_privacy_mode"](payload)
    profile_name = helpers["normalize_profile_name"](getattr(payload, "selected_profile", ""))
    profile = helpers["get_profile"](profile_name)
    rule_context = helpers["build_rule_context"](payload)
    fingerprint = helpers["build_endpoint_fingerprint"](payload, rule_context)
    similar_hits = helpers["find_similar_history"](fingerprint, limit=profile["memory_top_k"])
    memory_summary = helpers["summarize_similar_findings"](similar_hits)
    history_correlation = helpers["describe_history_correlation"](fingerprint, similar_hits)
    kb_query = helpers["build_kb_query"](payload, rule_context)
    if kb_query:
        kb_search = helpers["search_notes_detailed"](kb_query, top_k=profile["kb_top_k"])
    else:
        kb_search = {"context": "No context found.", "hits": []}
    kb_context = kb_search["context"]
    guidance_db = helpers["query_guidance_packs"](
        [recipe.get("vuln_class", "general") for recipe in rule_context.get("matched_recipes", [])[:3]],
        top_k=3,
    )
    review_dataset = query_review_examples(
        vuln_classes=[recipe.get("vuln_class", "general") for recipe in rule_context.get("matched_recipes", [])[:3]],
        partition_key=fingerprint.get("memory_partition_key", ""),
        limit=3,
    )
    collaborator_summary = helpers["summarize_collaborator_evidence"](
        getattr(payload, "collaborator_evidence_text", "")
    )
    screenshot_review = helpers["review_burp_settings_screenshots"](payload, privacy_mode)
    fallback = helpers["fallback_analysis"](
        payload,
        rule_context,
        memory_summary,
        append_manual_tooling=helpers["append_manual_tooling"],
        append_manual_commands=helpers["append_manual_commands"],
        append_direct_follow_up_answer=helpers["append_direct_follow_up_answer"],
    )
    if screenshot_review.get("summary"):
        fallback["analysis"] = (
            f"{fallback['analysis']}\n\nBurp settings screenshot vision summary:\n"
            f"{screenshot_review['summary']}"
        )
    elif screenshot_review.get("status") and (getattr(payload, "burp_screenshot_audit_text", "") or "").strip():
        fallback["analysis"] = f"{fallback['analysis']}\n\nBurp settings screenshot review: {screenshot_review['status']}"
    fallback["burp_screenshot_review_status"] = (
        screenshot_review.get("status") or "No screenshot vision review was performed."
    )
    skip_reason = helpers["skip_model_reason"](payload, rule_context)
    follow_up_request = helpers["suggestion_follow_up_request"](payload)

    raw_request = helpers["summarize_http_message"](
        helpers["sanitize_http_message"](payload.raw_request, privacy_mode),
        "Raw request",
        constants["max_request_header_lines"],
        constants["max_request_body_preview_chars"],
    )
    raw_response = helpers["summarize_http_message"](
        helpers["sanitize_http_message"](payload.raw_response, privacy_mode),
        "Raw response",
        constants["max_response_header_lines"],
        constants["max_response_body_preview_chars"],
    )

    prompt_sections = {
        "target_url": payload.target_url,
        "http_method": payload.http_method,
        "source_tool": payload.source_tool,
        "use_burp_mcp_context": bool(getattr(payload, "use_burp_mcp_context", False)),
        "annotations_text": ", ".join(payload.annotations or []) or "<none>",
        "profile_name": profile_name,
        "allowed_classes_text": ", ".join(rule_context["review_scope"]["allowed_classes"]) or "<none>",
        "suppressed_classes_text": ", ".join(rule_context["review_scope"]["suppressed_classes"]) or "<none>",
        "privacy_mode": privacy_mode,
        "complexity_level": rule_context["complexity"]["level"],
        "complexity_eta": rule_context["complexity"]["eta"],
        "complexity_recommendation": rule_context["complexity"]["recommendation"],
        "operator_answers_text": helpers["format_operator_answers"](getattr(payload, "operator_answers", None)),
        "tool_help_summary": helpers["tool_help_summary"](getattr(payload, "tool_help_text", "")),
        "inventory_summary": helpers["inventory_summary_text"](),
        "loaded_burp_tools_summary": helpers["sanitize_free_text"](
            helpers["loaded_burp_tools_summary"](getattr(payload, "loaded_burp_tools_text", "")),
            privacy_mode,
        ),
        "program_context": helpers["format_program_context"](payload),
        "tool_results_summary": helpers["sanitize_free_text"](
            helpers["tool_results_summary"](getattr(payload, "tool_results_text", "")),
            privacy_mode,
        ),
        "burp_config_summary": helpers["sanitize_free_text"](
            helpers["burp_config_export_summary"](getattr(payload, "burp_config_export_text", "")),
            privacy_mode,
        ),
        "burp_screenshot_summary": helpers["sanitize_free_text"](
            helpers["burp_screenshot_audit_summary"](getattr(payload, "burp_screenshot_audit_text", "")),
            privacy_mode,
        ),
        "program_screenshot_summary": helpers["sanitize_free_text"](
            helpers["burp_screenshot_audit_summary"](getattr(payload, "program_screenshot_audit_text", "")),
            privacy_mode,
        ),
        "vision_summary": helpers["sanitize_free_text"](
            screenshot_review.get("summary")
            or screenshot_review.get("status")
            or "No local screenshot review was performed.",
            privacy_mode,
        ),
        "bapp_findings_summary": helpers["sanitize_free_text"](
            helpers["bapp_findings_summary"](getattr(payload, "bapp_findings_text", "")),
            privacy_mode,
        ),
        "logger_evidence_summary": helpers["sanitize_free_text"](
            helpers["logger_evidence_summary"](getattr(payload, "logger_evidence_text", "")),
            privacy_mode,
        ),
        "collaborator_evidence_summary": helpers["sanitize_free_text"](
            helpers["collaborator_evidence_summary"](getattr(payload, "collaborator_evidence_text", "")),
            privacy_mode,
        ),
        "evidence_timeline_summary": helpers["sanitize_free_text"](
            helpers["evidence_timeline_summary"](getattr(payload, "evidence_timeline_entries", None)),
            privacy_mode,
        ),
        "issue_workflow_notes_summary": helpers["sanitize_free_text"](
            "\n".join(
                f"- {str(item).strip()}"
                for item in (getattr(payload, "issue_workflow_notes", None) or [])[:8]
                if str(item).strip()
            ) or "No prior investigation workflow notes supplied.",
            privacy_mode,
        ),
        "investigation_notebook_summary": helpers["sanitize_free_text"](
            getattr(payload, "investigation_notebook_text", "") or "No persistent investigation notebook supplied.",
            privacy_mode,
        ),
        "follow_up_request": follow_up_request or "No explicit suggestion follow-up request supplied.",
        "follow_up_instruction_block": helpers["follow_up_prompt_instructions"](payload),
        "scanner_issue_context": helpers["scanner_issue_context"](payload),
        "burp_origin_context": helpers["burp_origin_context"](payload),
        "response_delta_summary": helpers["sanitize_free_text"](
            getattr(payload, "response_delta_text", "") or "No explicit response delta supplied.",
            privacy_mode,
        ),
        "observations_text": helpers["format_list"](rule_context["features"]["observations"]),
        "fingerprint": fingerprint,
        "recipe_block": helpers["format_recipe_block"](rule_context["matched_recipes"]),
        "rule_baseline": rule_context["aggregate"],
        "memory_block": helpers["format_memory_block"](similar_hits, memory_summary),
        "kb_context": kb_context,
        "kb_hits": [
            {
                "title": item.get("title") or item.get("file") or "",
                "tags": item.get("tags", []),
                "source": item.get("source", ""),
                "score": item.get("score", 0.0),
            }
            for item in kb_search.get("hits", [])[:4]
        ],
        "guidance_db_context": guidance_db.get("context", ""),
        "guidance_db_hits": guidance_db.get("hits", [])[:3],
        "review_dataset_summary": review_dataset.get("summary", ""),
        "review_dataset_hits": review_dataset.get("items", [])[:3],
        "reference_links": rule_context["aggregate"].get("source_links", [])[:8],
        "local_resource_hints": rule_context["aggregate"].get("local_resource_hints", [])[:6],
        "raw_request_summary": raw_request,
        "raw_response_summary": raw_response,
    }
    prompt_investigation_intelligence = build_investigation_intelligence(
        payload,
        rule_context=rule_context,
        prompt_sections=prompt_sections,
    )
    prompt_sections["investigation_phase_summary"] = summarize_phase_state(
        prompt_investigation_intelligence.get("phase_state") or {}
    )
    prompt_sections["contradiction_summary"] = summarize_contradiction_assessment(
        prompt_investigation_intelligence.get("contradiction_assessment") or {}
    )
    prompt_sections["evidence_sufficiency_summary"] = summarize_evidence_sufficiency(
        prompt_investigation_intelligence.get("evidence_sufficiency") or {}
    )
    prompt_sections["branch_guard_summary"] = summarize_branch_guard(
        prompt_investigation_intelligence.get("branch_guard") or {}
    )
    prompt_sections["vulnerability_state_summary"] = summarize_vulnerability_state_machine(
        prompt_investigation_intelligence.get("vulnerability_state_machine") or {}
    )
    prompt_sections["counter_hypothesis_summary"] = summarize_counter_hypothesis(
        prompt_investigation_intelligence.get("counter_hypothesis") or {}
    )
    prompt_sections["confidence_calibration_summary"] = summarize_confidence_calibration(
        prompt_investigation_intelligence.get("confidence_calibration") or {}
    )
    prompt_sections["cross_issue_cluster_summary"] = summarize_cross_issue_cluster(
        prompt_investigation_intelligence.get("cross_issue_cluster") or {}
    )
    prompt_sections["response_diff_semantics_summary"] = summarize_response_diff_semantics(
        prompt_investigation_intelligence.get("response_diff_semantics") or {}
    )
    prompt_sections["impact_path_ranking_summary"] = summarize_impact_path_ranking(
        prompt_investigation_intelligence.get("impact_path_ranking") or {}
    )
    prompt_sections["report_bundle_summary"] = summarize_report_bundle(
        prompt_investigation_intelligence.get("report_bundle") or {}
    )
    scanner_marked_case_bundle = _build_scanner_marked_case_bundle(
        payload=payload,
        rule_context=rule_context,
        investigation_intelligence=prompt_investigation_intelligence,
    )
    prompt_sections["scanner_marked_case_bundle"] = scanner_marked_case_bundle
    prompt_sections["scanner_marked_case_summary"] = _summarize_scanner_marked_case_bundle(
        scanner_marked_case_bundle
    )
    fallback = _apply_scanner_marked_case_to_fallback(fallback, scanner_marked_case_bundle)
    prompt = helpers["build_analysis_prompt"](prompt_sections)

    confirmation_playbooks = rule_context["aggregate"].get("confirmation_playbooks", [])[:6]

    if skip_reason:
        fallback["analysis"] = f"{fallback['analysis']}\n\nModel refinement skipped: {skip_reason}"
        fallback["investigation_phase_state"] = prompt_investigation_intelligence.get("phase_state") or {}
        fallback["contradiction_assessment"] = prompt_investigation_intelligence.get("contradiction_assessment") or {}
        fallback["evidence_sufficiency"] = prompt_investigation_intelligence.get("evidence_sufficiency") or {}
        fallback["branch_guard"] = prompt_investigation_intelligence.get("branch_guard") or {}
        fallback["vulnerability_state_machine"] = prompt_investigation_intelligence.get("vulnerability_state_machine") or {}
        fallback["counter_hypothesis"] = prompt_investigation_intelligence.get("counter_hypothesis") or {}
        fallback["confidence_calibration"] = prompt_investigation_intelligence.get("confidence_calibration") or {}
        fallback["cross_issue_cluster"] = prompt_investigation_intelligence.get("cross_issue_cluster") or {}
        fallback["response_diff_semantics"] = prompt_investigation_intelligence.get("response_diff_semantics") or {}
        fallback["impact_path_ranking"] = prompt_investigation_intelligence.get("impact_path_ranking") or {}
        fallback["report_bundle"] = prompt_investigation_intelligence.get("report_bundle") or {}
        provider_trace = [
            helpers["format_model_trace_entry"]("deterministic", "ready", "Prepared the rule-based advisory baseline."),
            helpers["format_model_trace_entry"]("model", "skipped", skip_reason),
        ]
        provider_failover = helpers["build_provider_failover"](
            [],
            [{"provider": "model", "status": "skipped", "detail": skip_reason}],
            "deterministic",
            True,
            list(constants["model_required_fields"]),
        )
        execution_summary = helpers["build_model_execution_summary"](
            "deterministic",
            provider_trace,
            True,
            [],
            list(constants["model_required_fields"]),
        )
        return helpers["finalize_fallback_response"](
            fallback,
            history_correlation,
            confirmation_playbooks,
            "deterministic",
            execution_summary,
            provider_trace,
            True,
            provider_failover=provider_failover,
            request_id=request_id,
        )

    provider_trace = [
        helpers["format_model_trace_entry"]("deterministic", "ready", "Prepared the rule-based advisory baseline.")
    ]
    configured_provider_order = helpers["configured_model_providers"]()
    provider_order = [provider for provider in configured_provider_order if provider == "mcp"]
    provider_outcomes: list[dict] = []
    successful_providers: list[str] = []
    provider_candidate: dict = {}
    burp_context_request = bool(getattr(payload, "use_burp_mcp_context", False)) and (
        (getattr(payload, "source_tool", "") or "").strip().lower() in {"scanner", "repeater", "proxy", "intruder", "dashboard"}
        or any("scanner" in str(item).lower() or "audit_issue" in str(item).lower() for item in (getattr(payload, "annotations", None) or []))
    )

    if "ollama" in configured_provider_order:
        provider_outcomes.append({
            "provider": "ollama",
            "status": "skipped",
            "detail": "MCP-only advisory execution is active, so the Ollama provider was skipped.",
        })
        provider_trace.append(
            helpers["format_model_trace_entry"](
                "ollama",
                "skipped",
                "MCP-only advisory execution is active, so the Ollama provider was skipped.",
            )
        )
    if burp_context_request and "mcp" in provider_order:
        provider_trace.append(
            helpers["format_model_trace_entry"](
                "mcp",
                "info",
                "Burp MCP context is attached and will be passed through to the MCP provider.",
            )
        )

    for provider in provider_order:
        try:
            if provider == "mcp":
                candidate, detail = helpers["call_mcp_provider"](
                    prompt,
                    payload,
                    profile_name,
                    privacy_mode,
                    fallback,
                    rule_context,
                )
            elif provider == "ollama":
                candidate, detail = helpers["call_ollama_provider"](
                    prompt,
                    payload,
                    profile_name,
                    fallback,
                    rule_context,
                )
            else:
                provider_trace.append(
                    helpers["format_model_trace_entry"](
                        provider,
                        "skipped",
                        "Unsupported provider entry in MODEL_PROVIDER_ORDER.",
                    )
                )
                continue
        except MCPConfigurationError as exc:
            detail = str(exc)
            provider_outcomes.append({"provider": provider, "status": "skipped", "detail": detail})
            provider_trace.append(helpers["format_model_trace_entry"](provider, "skipped", detail))
            continue
        except requests.exceptions.ReadTimeout:
            detail = f"Ollama timed out after {constants['ollama_timeout_seconds']} seconds."
            provider_outcomes.append({"provider": provider, "status": "failed", "detail": detail})
            provider_trace.append(
                helpers["format_model_trace_entry"](
                    provider,
                    "failed",
                    detail,
                )
            )
            continue
        except requests.exceptions.RequestException as exc:
            detail = helpers["format_ollama_request_error"](exc)
            provider_outcomes.append({"provider": provider, "status": "failed", "detail": detail})
            provider_trace.append(
                helpers["format_model_trace_entry"](
                    provider,
                    "failed",
                    detail,
                )
            )
            continue
        except json.JSONDecodeError:
            detail = "The local model returned invalid JSON."
            provider_outcomes.append({"provider": provider, "status": "failed", "detail": detail})
            provider_trace.append(
                helpers["format_model_trace_entry"](
                    provider,
                    "failed",
                    detail,
                )
            )
            continue
        except (MCPError, ValueError) as exc:
            detail = str(exc)
            provider_outcomes.append({"provider": provider, "status": "failed", "detail": detail})
            provider_trace.append(helpers["format_model_trace_entry"](provider, "failed", detail))
            continue

        candidate_with_planner, planner_error = helpers["enforce_candidate_planner_schema"](candidate)
        if planner_error:
            provider_outcomes.append({"provider": provider, "status": "failed", "detail": planner_error})
            provider_trace.append(
                helpers["format_model_trace_entry"](
                    provider,
                    "failed",
                    planner_error,
                )
            )
            continue

        normalized_candidate = helpers["normalize_model_candidate"](candidate_with_planner)
        if not normalized_candidate:
            detail = "The provider returned no usable advisory fields."
            provider_outcomes.append({"provider": provider, "status": "failed", "detail": detail})
            provider_trace.append(
                helpers["format_model_trace_entry"](
                    provider,
                    "failed",
                    detail,
                )
            )
            continue

        provider_candidate, adopted_fields = helpers["merge_model_candidates"](
            provider_candidate,
            normalized_candidate,
        )
        if provider not in successful_providers:
            successful_providers.append(provider)

        missing_fields = helpers["missing_model_fields"](provider_candidate)
        if missing_fields:
            adopted_detail = ", ".join(adopted_fields) or "no new fields"
            provider_outcomes.append({
                "provider": provider,
                "status": "partial",
                "detail": detail,
                "adopted_fields": adopted_fields,
                "missing_fields": missing_fields,
            })
            provider_trace.append(
                helpers["format_model_trace_entry"](
                    provider,
                    "partial",
                    f"{detail} Adopted fields: {adopted_detail}. Still missing: {', '.join(missing_fields)}.",
                )
            )
            continue

        provider_outcomes.append({
            "provider": provider,
            "status": "used",
            "detail": detail,
            "adopted_fields": adopted_fields,
            "missing_fields": [],
        })
        provider_trace.append(helpers["format_model_trace_entry"](provider, "used", detail))
        break

    provider_investigation_intelligence = (
        build_investigation_intelligence(
            payload,
            rule_context=rule_context,
            prompt_sections=prompt_sections,
            provider_candidate=provider_candidate,
        )
        if provider_candidate
        else prompt_investigation_intelligence
    )

    final_investigation_intelligence = (
        build_investigation_intelligence(
            payload,
            rule_context=rule_context,
            prompt_sections=prompt_sections,
            provider_candidate=provider_candidate,
        )
        if provider_candidate
        else prompt_investigation_intelligence
    )

    missing_fields = helpers["missing_model_fields"](provider_candidate)
    backend_parts = list(successful_providers)
    if not backend_parts:
        backend = "deterministic"
    elif missing_fields:
        backend = "+".join(backend_parts + ["deterministic"])
    else:
        backend = "+".join(backend_parts)
    execution_summary = helpers["build_model_execution_summary"](
        backend,
        provider_trace,
        bool(missing_fields),
        successful_providers,
        missing_fields,
    )
    provider_failover = helpers["build_provider_failover"](
        provider_order,
        provider_outcomes,
        backend,
        bool(missing_fields),
        missing_fields,
    )

    if not provider_candidate:
        fallback["investigation_phase_state"] = final_investigation_intelligence.get("phase_state") or {}
        fallback["contradiction_assessment"] = final_investigation_intelligence.get("contradiction_assessment") or {}
        fallback["evidence_sufficiency"] = final_investigation_intelligence.get("evidence_sufficiency") or {}
        fallback["branch_guard"] = final_investigation_intelligence.get("branch_guard") or {}
        fallback["vulnerability_state_machine"] = final_investigation_intelligence.get("vulnerability_state_machine") or {}
        fallback["counter_hypothesis"] = final_investigation_intelligence.get("counter_hypothesis") or {}
        fallback["confidence_calibration"] = final_investigation_intelligence.get("confidence_calibration") or {}
        fallback["cross_issue_cluster"] = final_investigation_intelligence.get("cross_issue_cluster") or {}
        fallback["response_diff_semantics"] = final_investigation_intelligence.get("response_diff_semantics") or {}
        fallback["impact_path_ranking"] = final_investigation_intelligence.get("impact_path_ranking") or {}
        fallback["report_bundle"] = final_investigation_intelligence.get("report_bundle") or {}
        return helpers["finalize_fallback_response"](
            fallback,
            history_correlation,
            confirmation_playbooks,
            backend,
            execution_summary,
            provider_trace,
            True,
            provider_failover=provider_failover,
            request_id=request_id,
        )

    analysis = provider_candidate.get("analysis") or fallback["analysis"]
    primary_next_action = provider_candidate.get("primary_next_action") or fallback.get("primary_next_action", "")
    request_plan = provider_candidate.get("request_plan") or fallback.get("request_plan", [])
    potential_vulnerabilities = (
        provider_candidate.get("potential_vulnerabilities") or fallback["potential_vulnerabilities"]
    )
    primary_next_action, request_plan, potential_vulnerabilities = _apply_scanner_marked_case_to_result_fields(
        scanner_marked_case_bundle,
        primary_next_action=primary_next_action,
        request_plan=request_plan,
        potential_vulnerabilities=potential_vulnerabilities,
    )
    nuclei_tags = provider_candidate.get("nuclei_tags") or fallback["nuclei_tags"]
    seclists_path = provider_candidate.get("seclists_path") or fallback["seclists_path"]
    questions_for_user = provider_candidate.get("questions_for_user") or fallback["questions_for_user"]
    source_links = provider_candidate.get("source_links") or fallback["source_links"]

    analysis = helpers["build_result_analysis"](
        analysis,
        memory_summary=memory_summary,
        payload=payload,
        profile_name=profile_name,
        rule_context=rule_context,
        screenshot_review=screenshot_review,
        collaborator_summary=collaborator_summary,
        append_manual_tooling=helpers["append_manual_tooling"],
        append_manual_commands=helpers["append_manual_commands"],
        append_direct_follow_up_answer=helpers["append_direct_follow_up_answer"],
    )

    result = {
        "analysis": analysis,
        "primary_next_action": primary_next_action,
        "request_plan": request_plan[:6] if isinstance(request_plan, list) else fallback.get("request_plan", [])[:6],
        "tool_availability_summary": rule_context["aggregate"].get("tool_availability_summary", ""),
        "potential_vulnerabilities": potential_vulnerabilities[:5],
        "nuclei_tags": nuclei_tags,
        "seclists_path": seclists_path,
        "questions_for_user": questions_for_user[:3],
        "source_links": source_links[:8],
        "manual_tooling": rule_context["aggregate"].get("manual_tooling", [])[:8],
        "manual_commands": rule_context["aggregate"].get("manual_commands", [])[:8],
        "payload_recommendations": rule_context["aggregate"].get("payload_recommendations", [])[:8],
        "local_resource_hints": rule_context["aggregate"].get("local_resource_hints", [])[:6],
        "bcheck_recommendations": rule_context["aggregate"].get("bcheck_recommendations", [])[:4],
        "impact_paths": (
            list((final_investigation_intelligence.get("impact_path_ranking") or {}).get("ranked_path_texts") or [])
            or rule_context["aggregate"].get("impact_paths", [])
        )[:6],
        "burp_settings_recommendations": rule_context["aggregate"].get("burp_settings_recommendations", [])[:8],
        "project_readiness_summary": rule_context["aggregate"].get("project_readiness_summary", ""),
        "project_readiness_checks": rule_context["aggregate"].get("project_readiness_checks", [])[:8],
        "burp_action_checklist": rule_context["aggregate"].get("burp_action_checklist", [])[:10],
        "burp_screenshot_review_status": (
            screenshot_review.get("status") or "No screenshot vision review was performed."
        ),
        "suggestion_queue": rule_context["aggregate"].get("suggestion_queue", [])[:6],
        "confidence_by_class": rule_context["aggregate"].get("confidence_by_class", [])[:6],
        "history_correlation": history_correlation[:6],
        "confirmation_playbooks": confirmation_playbooks,
        "investigation_phase_state": final_investigation_intelligence.get("phase_state") or {},
        "contradiction_assessment": final_investigation_intelligence.get("contradiction_assessment") or {},
        "evidence_sufficiency": final_investigation_intelligence.get("evidence_sufficiency") or {},
        "branch_guard": final_investigation_intelligence.get("branch_guard") or {},
        "vulnerability_state_machine": final_investigation_intelligence.get("vulnerability_state_machine") or {},
        "counter_hypothesis": final_investigation_intelligence.get("counter_hypothesis") or {},
        "confidence_calibration": final_investigation_intelligence.get("confidence_calibration") or {},
        "cross_issue_cluster": final_investigation_intelligence.get("cross_issue_cluster") or {},
        "response_diff_semantics": final_investigation_intelligence.get("response_diff_semantics") or {},
        "impact_path_ranking": final_investigation_intelligence.get("impact_path_ranking") or {},
        "report_bundle": final_investigation_intelligence.get("report_bundle") or {},
    }
    return helpers["attach_execution_metadata"](
        result,
        backend,
        execution_summary,
        provider_trace,
        bool(missing_fields),
        provider_failover=provider_failover,
        request_id=request_id,
    )


def _is_burp_originated_request(payload) -> bool:
    source_tool = str(getattr(payload, "source_tool", "") or "").strip().lower()
    annotations = {
        str(item).strip().lower()
        for item in (getattr(payload, "annotations", None) or [])
        if str(item).strip()
    }
    return bool(
        source_tool in {"scanner", "repeater", "intruder", "proxy", "dashboard", "logger"}
        or bool(getattr(payload, "use_burp_mcp_context", False))
        or any(token in annotations for token in {"tool_scanner", "tool_repeater", "tool_intruder", "scanner_context", "repeater_context"})
    )


def _build_scanner_marked_case_bundle(*, payload, rule_context: dict, investigation_intelligence: dict) -> dict:
    from server.core.burp_capability_service import recommend_burp_capabilities
    from server.core.repeater_guidance_service import build_repeater_escalation_plan

    issue_context = get_dashboard_issue_context(payload)
    if not issue_context.get("found") and not _is_burp_originated_request(payload):
        return {}

    matched_recipes = list(rule_context.get("matched_recipes", []) or [])
    fallback_recipe_class = str((matched_recipes[0] if matched_recipes else {}).get("vuln_class") or "").strip()
    vuln_class = normalize_vuln_class(
        issue_context.get("vuln_hint")
        or ((investigation_intelligence.get("vulnerability_state_machine") or {}).get("vuln_class"))
        or fallback_recipe_class
        or "general"
    )
    impact_ranking = investigation_intelligence.get("impact_path_ranking") or {}
    repeater_plan = build_repeater_escalation_plan(
        payload,
        advisory={
            "primary_next_action": rule_context.get("aggregate", {}).get("primary_next_action", ""),
        },
        impact={
            "dashboard_issue": {"vuln_hint": vuln_class},
            "baseline_confirmation": impact_ranking.get("top_path", ""),
        },
    )
    capability_bundle = recommend_burp_capabilities(
        payload,
        impact={"dashboard_issue": {"vuln_hint": vuln_class}},
    )
    mutation_plan = list(repeater_plan.get("repeater_mutation_plan") or [])
    primary_mutation = mutation_plan[0] if mutation_plan else {}
    starter_bundle = capability_bundle.get("starter_assets") or {}
    starter_assets = []
    custom_scan_checks = list(starter_bundle.get("custom_scan_checks") or [])
    bambda_packs = list(starter_bundle.get("bambda_packs") or [])
    if custom_scan_checks:
        starter_assets.append(str(custom_scan_checks[0].get("name") or "Custom scan check"))
    if bambda_packs:
        starter_assets.append(str(bambda_packs[0].get("name") or "Bambda pack"))

    confidence = str(issue_context.get("confidence") or "").strip().lower()
    likely_real = confidence in {"firm", "certain"} or bool(issue_context.get("evidence_items"))
    if issue_context.get("found"):
        confirmation_outlook = (
            "Burp already marked this issue with strong confidence, so treat it as likely real but still require one bounded confirmation artifact."
            if likely_real
            else "Treat the scanner finding as an anchored suspicion and rule out a false positive with one bounded confirmation on the same sink or object boundary."
        )
    else:
        confirmation_outlook = (
            "Treat this as a Burp-originated anchored request family: confirm the observed behavior on the same sink or boundary, then move directly into the strongest bounded impact path."
        )
    primary_burp = next(
        (
            item for item in (capability_bundle.get("recommendations") or [])
            if str(item.get("tool") or "").strip()
        ),
        {},
    )
    resource_priority = [
        "Start from the exact Burp Scanner issue anchor and highlighted request family.",
        "Use the Repeater mutation plan before broader tool expansion.",
        "Use starter Burp assets, local KB hits, guidance packs, and review examples before wider exploration.",
    ]
    return {
        "status": "active",
        "issue_name": issue_context.get("issue_name", "") or "Burp-originated request family",
        "severity": issue_context.get("severity", "") or "info",
        "confidence": issue_context.get("confidence", "") or "operator-selected",
        "vuln_class": vuln_class,
        "origin_type": "scanner-marked" if issue_context.get("found") else "burp-originated",
        "confirmation_outlook": confirmation_outlook,
        "next_confirmation_instruction": str(primary_mutation.get("instruction") or "").strip(),
        "next_confirmation_signal": str(primary_mutation.get("expected_signal") or "").strip(),
        "next_impact_path": str(
            impact_ranking.get("top_path")
            or next(iter(impact_ranking.get("ranked_path_texts") or []), "")
        ).strip(),
        "issue_chain_hint": str(next(iter(repeater_plan.get("issue_chain_strategy") or []), "")).strip(),
        "primary_burp_tool": str(primary_burp.get("tool") or "").strip(),
        "primary_burp_step": str(primary_burp.get("manual_step") or "").strip(),
        "starter_assets": starter_assets[:3],
        "resource_priority": resource_priority,
    }


def _summarize_scanner_marked_case_bundle(bundle: dict) -> str:
    if not bundle or bundle.get("status") != "active":
        return "No scanner-marked case bundle was derived."

    lines = [
        "- Burp-origin case logic is active. Treat the selected Burp request family as the anchor finding rather than rediscovering the bug family from scratch.",
        f"- Selected issue: {bundle.get('issue_name', 'scanner-marked issue')} [{bundle.get('severity', 'info')}/{bundle.get('confidence', 'tentative')}] -> normalized class: {bundle.get('vuln_class', 'general')}.",
        f"- False-positive triage rule: {bundle.get('confirmation_outlook', '')}",
    ]
    if bundle.get("next_confirmation_instruction"):
        lines.append(f"- First bounded confirmation move: {bundle.get('next_confirmation_instruction')}")
    if bundle.get("next_confirmation_signal"):
        lines.append(f"- Confirmation signal to capture: {bundle.get('next_confirmation_signal')}")
    if bundle.get("next_impact_path"):
        lines.append(f"- After confirmation, prefer this in-scope impact evidence path: {bundle.get('next_impact_path')}")
    if bundle.get("issue_chain_hint"):
        lines.append(f"- Secondary chain hint only after the baseline is stable: {bundle.get('issue_chain_hint')}")
    if bundle.get("primary_burp_tool"):
        lines.append(
            f"- Burp-first tool to prefer next: {bundle.get('primary_burp_tool')} -> {bundle.get('primary_burp_step', '').strip()}"
        )
    starter_assets = list(bundle.get("starter_assets") or [])
    if starter_assets:
        lines.append("- Local Burp starter assets to prefer before broader exploration: " + ", ".join(starter_assets))
    for item in list(bundle.get("resource_priority") or [])[:3]:
        lines.append(f"- {item}")
    return "\n".join(lines)


def _apply_scanner_marked_case_to_fallback(fallback: dict, bundle: dict) -> dict:
    if not bundle or bundle.get("status") != "active":
        return fallback

    updated = dict(fallback)
    summary = _summarize_scanner_marked_case_bundle(bundle)
    analysis = str(updated.get("analysis") or "").strip()
    if summary and summary not in analysis:
        updated["analysis"] = (analysis + "\n\nScanner-marked case bundle:\n" + summary).strip()
    current_action = str(updated.get("primary_next_action") or "").strip()
    if (
        bundle.get("next_confirmation_instruction")
        and (
            not current_action
            or not _text_matches_vuln_class(current_action, str(bundle.get("vuln_class") or ""))
        )
    ):
        updated["primary_next_action"] = bundle["next_confirmation_instruction"]
    potentials = list(updated.get("potential_vulnerabilities") or [])
    if bundle.get("vuln_class") and not any(
        _text_matches_vuln_class(item, str(bundle.get("vuln_class") or ""))
        for item in potentials
    ):
        issue_name = str(bundle.get("issue_name") or "Burp-selected issue").strip()
        updated["potential_vulnerabilities"] = [f"[{bundle.get('vuln_class')}] {issue_name}"]
    return updated


def _apply_scanner_marked_case_to_result_fields(
    bundle: dict,
    *,
    primary_next_action,
    request_plan,
    potential_vulnerabilities,
) -> tuple[str, list[str], list[str]]:
    if not bundle or bundle.get("status") != "active":
        return (
            str(primary_next_action or "").strip(),
            list(request_plan or []) if isinstance(request_plan, list) else [],
            list(potential_vulnerabilities or []) if isinstance(potential_vulnerabilities, list) else [],
        )

    vuln_class = normalize_vuln_class(str(bundle.get("vuln_class") or "general"))
    normalized_action = str(primary_next_action or "").strip()
    normalized_plan = [
        str(item).strip()
        for item in (list(request_plan or []) if isinstance(request_plan, list) else [])
        if str(item).strip()
    ]
    normalized_potentials = [
        str(item).strip()
        for item in (list(potential_vulnerabilities or []) if isinstance(potential_vulnerabilities, list) else [])
        if str(item).strip()
    ]

    if vuln_class == "general":
        return normalized_action, normalized_plan, normalized_potentials

    if not _text_matches_vuln_class(normalized_action, vuln_class) and bundle.get("next_confirmation_instruction"):
        normalized_action = str(bundle.get("next_confirmation_instruction") or "").strip()

    if not any(_text_matches_vuln_class(item, vuln_class) for item in normalized_potentials):
        issue_name = str(bundle.get("issue_name") or "Burp-selected issue").strip()
        normalized_potentials = [f"[{vuln_class}] {issue_name}"]

    if normalized_action and not any(_text_matches_vuln_class(item, vuln_class) for item in normalized_plan):
        normalized_plan = [
            "Keep the selected Burp issue as the anchor request family.",
            normalized_action,
        ]
        confirmation_signal = str(bundle.get("next_confirmation_signal") or "").strip()
        if confirmation_signal:
            normalized_plan.append("Capture this confirmation signal: " + confirmation_signal)
        next_impact_path = str(bundle.get("next_impact_path") or "").strip()
        if next_impact_path:
            normalized_plan.append("After confirmation, move to: " + next_impact_path)

    return normalized_action, normalized_plan[:6], normalized_potentials[:5]


def _text_matches_vuln_class(text: str, vuln_class: str) -> bool:
    normalized_text = str(text or "").strip().lower()
    normalized_class = normalize_vuln_class(vuln_class)
    if not normalized_text or normalized_class == "general":
        return False

    class_tokens = {
        "xss": ("cross-site scripting", "xss", "render", "reflected", "stored"),
        "authorization": ("idor", "direct object reference", "access control", "unauthorized", "cross-tenant", "cross-user"),
        "authentication": ("authentication", "session", "login", "logout", "credential", "token"),
        "ssrf": ("ssrf", "server-side request forgery", "backend fetch", "callback", "collaborator"),
        "injection": ("sql injection", "sqli", "query influence", "backend interpreted", "boolean diff", "time-based"),
        "template-injection": ("template injection", "ssti", "template"),
        "xxe": ("xxe", "xml external entity", "doctype", "entity"),
        "race-condition": ("race", "concurrency", "timing"),
    }
    return any(token in normalized_text for token in class_tokens.get(normalized_class, (normalized_class,)))
