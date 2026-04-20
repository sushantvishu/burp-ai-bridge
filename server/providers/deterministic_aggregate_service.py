from server.core.model_strategy_service import build_model_strategy
from server.core.next_try_service import build_next_try_matrix, build_reporting_impact_notes


def build_aggregate_recipe_output(
    payload,
    features: dict,
    matched_recipes: list[dict],
    review_scope: dict,
    bapp_summary: dict,
    *,
    helpers: dict,
) -> dict:
    context_notes = []
    profile = review_scope["profile"]
    model_strategy = build_model_strategy(profile)
    allowed_classes = review_scope["allowed_classes"]
    suppressed_classes = review_scope["suppressed_classes"]
    loaded_burp_tools, preferred_burp_tools = helpers["loaded_burp_helpers"](payload, matched_recipes, bapp_summary)
    collaborator_summary = helpers["summarize_collaborator_evidence"](
        getattr(payload, "collaborator_evidence_text", "") or ""
    )
    scanner_classes = sorted(helpers["scanner_aligned_classes"](payload, bapp_summary))
    guidance_seed_classes = scanner_classes or [recipe.get("vuln_class", "general") for recipe in matched_recipes[:3]]
    guidance_db = helpers["query_guidance_packs"](guidance_seed_classes, top_k=3)

    context_notes.append(f"Selected profile: {profile['name']}")
    context_notes.append("Review scope classes: " + ", ".join(allowed_classes))
    context_notes.append("Request identity: " + helpers["request_identity_summary"](features, payload))
    if suppressed_classes:
        context_notes.append("Suppressed classes: " + ", ".join(suppressed_classes))
    if scanner_classes:
        context_notes.append("Burp Scanner already marked this request as: " + ", ".join(scanner_classes))
    if (getattr(payload, "scope_includes_text", "") or "").strip():
        context_notes.append("Program scope was provided and should constrain the next step.")
    if (getattr(payload, "scope_excludes_text", "") or "").strip():
        context_notes.append("Out-of-scope targets were provided and must be avoided.")
    if (getattr(payload, "rate_limit_text", "") or "").strip() or (getattr(payload, "max_concurrency_text", "") or "").strip():
        context_notes.append("Rate and concurrency limits were supplied for safe command shaping.")
    if (getattr(payload, "custom_headers_text", "") or "").strip():
        context_notes.append("Custom program headers were supplied for compatible tool usage.")
    if (getattr(payload, "tool_results_text", "") or "").strip():
        context_notes.append("Manual tool results or file references were shared for evidence-based follow-up.")
    if (getattr(payload, "response_delta_text", "") or "").strip():
        context_notes.append("An explicit operator response-delta note was supplied for this request.")
    if bapp_summary["summary_lines"]:
        context_notes.append("Burp scan or BApp findings were supplied and correlated with this request.")
    if loaded_burp_tools.get("detected_tools"):
        context_notes.append("Loaded Burp tools or BApps were supplied and should be preferred before missing external tools.")
    if (getattr(payload, "logger_evidence_text", "") or "").strip():
        context_notes.append("Logger++-style evidence was supplied and should be treated as high-signal diff evidence.")
    if collaborator_summary.get("summary_lines"):
        context_notes.extend(collaborator_summary["summary_lines"][:2])
    if scanner_classes and collaborator_summary.get("has_positive_interaction"):
        context_notes.append("Treat the selected Burp finding and Collaborator callbacks as one combined evidence chain for confirmation.")

    if not matched_recipes:
        manual_tooling = helpers["manual_tooling_for_matches"](features, matched_recipes)
        repeater_guidance = helpers["repeater_guidance"](features, matched_recipes)
        payload_recommendations = helpers["payload_recommendations"](features, matched_recipes)
        local_resource_hints = helpers["build_local_resource_hints"](matched_recipes)
        bcheck_entries = helpers["recommend_bchecks"](features, matched_recipes, allowed_classes)
        bcheck_recommendations = helpers["summarize_recommendations"](bcheck_entries)
        manual_commands = helpers["label_manual_commands"](
            helpers["command_templates"](
                payload,
                features,
                matched_recipes,
                "misconfig,exposure",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
            ),
            payload,
        )
        primary_next_action, request_plan = helpers["build_request_plan"](
            None,
            features,
            manual_tooling,
            manual_commands,
            payload_recommendations,
            preferred_burp_tools,
            payload,
        )
        impact_paths = helpers["build_impact_paths"](matched_recipes, bapp_summary)
        readiness_summary, readiness_checks = helpers["project_readiness"](
            payload,
            matched_recipes,
            preferred_burp_tools,
            bcheck_recommendations,
        )
        burp_action_checklist = helpers["build_burp_action_checklist"](
            payload,
            matched_recipes,
            preferred_burp_tools,
            bcheck_recommendations,
            readiness_summary,
        )
        burp_settings_recommendations = helpers["build_burp_settings_recommendations"](
            payload,
            matched_recipes,
            bcheck_recommendations,
            loaded_burp_tools,
            preferred_burp_tools,
        )
        return {
            "analysis": (
                "No strong rule-based vulnerability playbook matched this single HTTP exchange. Continue with manual "
                "context gathering and compare other authenticated and unauthenticated variants before drawing conclusions."
                + (
                    "\n\nPreferred Burp tools already loaded:\n- " + "\n- ".join(preferred_burp_tools)
                    if preferred_burp_tools else ""
                )
                + (
                    "\n\nSuggested Kali WSL tools for safe follow-up:\n- " + "\n- ".join(manual_tooling)
                    if manual_tooling else ""
                )
                + (
                    "\n\nSuggested Burp Repeater follow-up:\n- " + "\n- ".join(repeater_guidance)
                    if repeater_guidance else ""
                )
                + (
                    "\n\nSuggested Kali WSL command templates:\n- " + "\n- ".join(manual_commands)
                    if manual_commands else ""
                )
                + (
                    "\n\nSuggested payload starter lists:\n- " + "\n- ".join(payload_recommendations)
                    if payload_recommendations else ""
                )
                + (
                    "\n\nRelevant upstream BChecks you can import or enable:\n- " + "\n- ".join(bcheck_recommendations)
                    if bcheck_recommendations else ""
                )
                + (
                    "\n\nBurp scan or BApp findings:\n- " + "\n- ".join(bapp_summary["summary_lines"])
                    if bapp_summary["summary_lines"] else ""
                )
                + (
                    "\n\nProgram context notes:\n- " + "\n- ".join(context_notes)
                    if context_notes else ""
                )
                + (
                    "\n\nStructured guidance database:\n- " + "\n- ".join(guidance_db["context"].splitlines()[:8])
                    if guidance_db.get("context") and guidance_db["context"] != "No structured methodology guidance found." else ""
                )
            ),
            "primary_next_action": primary_next_action,
            "request_plan": request_plan,
            "tool_availability_summary": helpers["inventory_summary_text"](),
            "potential_vulnerabilities": [
                "No high-confidence issue from this single exchange; gather adjacent requests, auth transitions, and parameter variations."
            ],
            "nuclei_tags": "misconfig,exposure",
            "seclists_path": "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "questions_for_user": [
                "What nearby endpoints or request variants are in scope for manual comparison?",
                "Does this endpoint behave differently for authenticated, unauthenticated, or different-role sessions?",
            ],
            "source_links": ([entry["source_url"] for entry in bcheck_entries[:2] if entry.get("source_url")] + guidance_db.get("reference_links", []))[:8],
            "manual_tooling": manual_tooling,
            "manual_commands": manual_commands,
            "payload_recommendations": payload_recommendations[:8],
            "local_resource_hints": local_resource_hints[:6],
            "guidance_db_context": guidance_db.get("context", ""),
            "guidance_db_hits": guidance_db.get("hits", [])[:3],
            "model_strategy": model_strategy,
            "bcheck_recommendations": bcheck_recommendations[:4],
            "impact_paths": impact_paths[:6],
            "burp_settings_recommendations": burp_settings_recommendations[:8],
            "project_readiness_summary": readiness_summary,
            "project_readiness_checks": readiness_checks[:8],
            "burp_action_checklist": burp_action_checklist[:10],
            "suggestion_queue": [
                "Primary track [general]: capture one untouched baseline in Burp Repeater, then vary one approved parameter, auth state, or nearby endpoint at a time and compare status, headers, length, timing, and body deltas.",
                "Intruder note [general]: only send a parameter to Intruder if you already know which field changes behavior. Otherwise stay in Repeater first and use a very short custom list built from the captured baseline values.",
                "AI follow-up [general]: if you want the next advisory to pick the exact parameter and payload family, submit a follow-up with the field you plan to test, the payloads already tried, and the observed response delta.",
                "BCheck assist [general]: if Burp Scanner custom checks are allowed, enable the closest upstream BCheck before expanding into broader manual testing.",
                "Open the Scan Scope tab in Operator Constraints if you want to suppress vulnerability classes for this specific request.",
            ],
            "next_try_matrix": build_next_try_matrix(
                vuln_class="general",
                title="general follow-up",
                primary_next_action=primary_next_action,
                request_plan=request_plan,
                payload_recommendations=payload_recommendations,
                impact_paths=impact_paths,
            ),
            "reporting_impact_notes": build_reporting_impact_notes(vuln_class="general"),
            "confidence_by_class": ["general: 0.25 confidence - no strong deterministic playbook matched yet."],
            "confirmation_playbooks": helpers["build_confirmation_playbooks"]([]),
        }

    top_matches = matched_recipes[:4]
    analysis_parts = ["Matched VA playbooks based on deterministic signals:"]
    for recipe in top_matches:
        evidence_text = "; ".join(recipe["evidence"]) if recipe["evidence"] else "general request/response context"
        vuln_class = recipe.get("vuln_class", "general")
        analysis_parts.append(f"- [{vuln_class}] {recipe['title']}: {recipe['summary']} Evidence: {evidence_text}.")

    vulnerabilities = [
        f"[{recipe.get('vuln_class', 'general')}] {recipe['title']} ({recipe.get('severity', 'info')}): {recipe['summary']}"
        for recipe in top_matches
    ]
    if bapp_summary["findings"]:
        analysis_parts.extend([
            "",
            "Burp scan or BApp findings correlated with this request:",
            *[
                f"- [{item['vuln_class']}] {item['tool']}: {item['summary']} Evidence: {item['evidence']}"
                for item in bapp_summary["findings"][:4]
            ],
        ])
        for item in bapp_summary["findings"]:
            vulnerability = f"[{item['vuln_class']}] {item['tool']} passive finding (info): {item['summary']}"
            if vulnerability not in vulnerabilities:
                vulnerabilities.append(vulnerability)

    manual_tooling = helpers["manual_tooling_for_matches"](features, matched_recipes)
    repeater_guidance = helpers["repeater_guidance"](features, matched_recipes)
    payload_recommendations = helpers["payload_recommendations"](features, top_matches)
    local_resource_hints = helpers["build_local_resource_hints"](top_matches)
    nuclei_tags = []
    seclists_path = None
    questions = []
    source_links = []

    for recipe in top_matches:
        for tag in recipe.get("nuclei_tags", []):
            if tag not in nuclei_tags:
                nuclei_tags.append(tag)
        if not seclists_path and recipe.get("seclists_path"):
            seclists_path = recipe["seclists_path"]
        for question in recipe.get("operator_questions", []):
            if question not in questions:
                questions.append(question)
        for link in recipe.get("source_refs", []):
            if link not in source_links:
                source_links.append(link)
    for link in bapp_summary["source_links"]:
        if link not in source_links:
            source_links.append(link)

    final_nuclei_tags = ",".join(nuclei_tags[:5]) or "misconfig,exposure"
    final_seclists_path = seclists_path or "/usr/share/seclists/Discovery/Web-Content/common.txt"
    manual_commands = helpers["label_manual_commands"](
        helpers["command_templates"](payload, features, matched_recipes, final_nuclei_tags, final_seclists_path),
        payload,
    )
    bcheck_entries = helpers["recommend_bchecks"](features, top_matches, allowed_classes)
    bcheck_recommendations = helpers["summarize_recommendations"](bcheck_entries)
    impact_paths = helpers["build_impact_paths"](top_matches, bapp_summary)
    readiness_summary, readiness_checks = helpers["project_readiness"](
        payload,
        top_matches,
        preferred_burp_tools,
        bcheck_recommendations,
    )
    burp_action_checklist = helpers["build_burp_action_checklist"](
        payload,
        top_matches,
        preferred_burp_tools,
        bcheck_recommendations,
        readiness_summary,
    )
    burp_settings_recommendations = helpers["build_burp_settings_recommendations"](
        payload,
        top_matches,
        bcheck_recommendations,
        loaded_burp_tools,
        preferred_burp_tools,
    )
    primary_next_action, request_plan = helpers["build_request_plan"](
        top_matches[0] if top_matches else None,
        features,
        manual_tooling,
        manual_commands,
        payload_recommendations,
        preferred_burp_tools,
        payload,
    )

    if preferred_burp_tools:
        analysis_parts.extend(["", "Preferred Burp tools already loaded:", *[f"- {item}" for item in preferred_burp_tools]])
    if manual_tooling:
        analysis_parts.extend(["", "Suggested Kali WSL tools for safe follow-up:", *[f"- {item}" for item in manual_tooling]])
    if repeater_guidance:
        analysis_parts.extend(["", "Suggested Burp Repeater follow-up:", *[f"- {item}" for item in repeater_guidance]])
    if manual_commands:
        analysis_parts.extend(["", "Suggested Kali WSL command templates:", *[f"- {item}" for item in manual_commands]])
    if payload_recommendations:
        analysis_parts.extend(["", "Suggested payload starter lists:", *[f"- {item}" for item in payload_recommendations]])
    if bcheck_recommendations:
        analysis_parts.extend(["", "Relevant upstream BChecks you can import or enable:", *[f"- {item}" for item in bcheck_recommendations]])
        for entry in bcheck_entries[:2]:
            if entry.get("source_url") and entry["source_url"] not in source_links:
                source_links.append(entry["source_url"])
    for recommendation in helpers["recommend_tools"](features, top_matches)[:3]:
        if recommendation.get("repo_url") and recommendation["repo_url"] not in source_links:
            source_links.append(recommendation["repo_url"])
    if context_notes:
        analysis_parts.extend(["", "Program context notes:", *[f"- {item}" for item in context_notes]])
    if local_resource_hints:
        analysis_parts.extend(["", "Local escalation resources:", *[f"- {item}" for item in local_resource_hints]])
    if guidance_db.get("context") and guidance_db["context"] != "No structured methodology guidance found.":
        analysis_parts.extend(["", "Structured guidance database:", *[f"- {line}" for line in guidance_db["context"].splitlines()[:8]]])

    confidence_by_class = []
    suggestion_queue = []
    seen_classes = []
    ranked_unique_recipes = []
    for recipe in top_matches:
        vuln_class = recipe.get("vuln_class", "general")
        if vuln_class in seen_classes:
            continue
        seen_classes.append(vuln_class)
        ranked_unique_recipes.append(recipe)
        raw_score, confidence_reasons = helpers["score_recipe_confidence"](
            payload,
            recipe,
            features,
            bapp_summary,
            collaborator_summary,
        )
        confidence_by_class.append(
            f"{vuln_class}: {raw_score:.2f} confidence - {recipe['title']} | Why: " + "; ".join(confidence_reasons[:4])
        )

    if ranked_unique_recipes:
        suggestion_queue.extend(
            helpers["apply_source_tool_bias"](
                payload,
                helpers["build_primary_suggestion_steps"](ranked_unique_recipes[0], features),
            )
        )
        for recipe in ranked_unique_recipes[1:2]:
            vuln_class = recipe.get("vuln_class", "general")
            suggestion_queue.append(
                f"Secondary track [{vuln_class}] {recipe['title']}: keep this as the next branch only if the primary track does not explain the response."
            )
    if bapp_summary["findings"]:
        suggestion_queue.append(
            "Correlate the selected Burp finding with the matching Burp history entries before adding more manual evidence."
        )
    if preferred_burp_tools:
        suggestion_queue.append(
            "Loaded Burp helpers: start with " + ", ".join(item.split(":", 1)[0] for item in preferred_burp_tools[:3]) + " before adding external tooling."
        )
    if bcheck_recommendations:
        suggestion_queue.append(
            "BCheck assist: enable the closest matching upstream BCheck if custom scanner checks are allowed for this target, then compare its finding with your manual evidence."
        )
    if not suggestion_queue:
        suggestion_queue.append("Compare one approved manual variation against the baseline request in Burp Repeater and Burp HTTP history.")
    suggestion_queue.append(
        "Use the Scan Scope tab to remove any vulnerability classes you do not want considered for this request."
    )

    confirmation_playbooks = helpers["build_confirmation_playbooks"](top_matches)
    primary_recipe = ranked_unique_recipes[0] if ranked_unique_recipes else (top_matches[0] if top_matches else {})
    primary_vuln_class = primary_recipe.get("vuln_class", "general")
    primary_title = primary_recipe.get("title", primary_vuln_class)

    return {
        "analysis": "\n".join(analysis_parts),
        "primary_next_action": primary_next_action,
        "request_plan": request_plan,
        "tool_availability_summary": helpers["inventory_summary_text"](),
        "potential_vulnerabilities": vulnerabilities[:5],
        "nuclei_tags": final_nuclei_tags,
        "seclists_path": final_seclists_path,
        "questions_for_user": questions[:3] or ["What request variants or role changes can you compare against this endpoint?"],
        "source_links": source_links[:8],
        "manual_tooling": manual_tooling,
        "manual_commands": manual_commands,
        "payload_recommendations": payload_recommendations[:8],
        "local_resource_hints": local_resource_hints[:6],
        "guidance_db_context": guidance_db.get("context", ""),
        "guidance_db_hits": guidance_db.get("hits", [])[:3],
        "model_strategy": model_strategy,
        "bcheck_recommendations": bcheck_recommendations[:4],
        "impact_paths": impact_paths[:6],
        "burp_settings_recommendations": burp_settings_recommendations[:8],
        "project_readiness_summary": readiness_summary,
        "project_readiness_checks": readiness_checks[:8],
        "burp_action_checklist": burp_action_checklist[:10],
        "suggestion_queue": suggestion_queue[:6],
        "next_try_matrix": build_next_try_matrix(
            vuln_class=primary_vuln_class,
            title=primary_title,
            primary_next_action=primary_next_action,
            request_plan=request_plan,
            payload_recommendations=payload_recommendations,
            impact_paths=impact_paths,
        ),
        "reporting_impact_notes": build_reporting_impact_notes(
            vuln_class=primary_vuln_class,
            business_impact_expansion_paths=impact_paths[:3],
        ),
        "confidence_by_class": confidence_by_class[:6],
        "confirmation_playbooks": confirmation_playbooks[:6],
    }
