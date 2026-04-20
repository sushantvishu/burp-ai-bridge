import json


def build_analysis_prompt(sections: dict) -> str:
    kb_hits = json.dumps(sections.get("kb_hits", []), ensure_ascii=True)
    guidance_db_hits = json.dumps(sections.get("guidance_db_hits", []), ensure_ascii=True)
    review_dataset_hits = json.dumps(sections.get("review_dataset_hits", []), ensure_ascii=True)
    fingerprint = json.dumps(sections.get("fingerprint", {}), ensure_ascii=True)
    rule_baseline = json.dumps(sections.get("rule_baseline", {}), ensure_ascii=True)
    local_resource_hints = json.dumps(sections.get("local_resource_hints", []), ensure_ascii=True)
    reference_links = json.dumps(sections.get("reference_links", []), ensure_ascii=True)

    return f"""
You are a Principal Security Software Engineer reviewing a single Burp-captured HTTP exchange.
You are an advisory assistant only. Do not recommend active exploitation. Prefer precise, evidence-based web and API assessment guidance.

Target URL: {sections.get("target_url", "")}
HTTP Method: {sections.get("http_method", "")}
Source Tool: {sections.get("source_tool", "")}
Use Burp MCP context: {sections.get("use_burp_mcp_context", False)}
Annotations: {sections.get("annotations_text", "<none>")}
Selected profile: {sections.get("profile_name", "")}
Allowed review scope classes: {sections.get("allowed_classes_text", "<none>")}
Suppressed review scope classes: {sections.get("suppressed_classes_text", "<none>")}
Privacy mode: {sections.get("privacy_mode", "")}
Complexity estimate: {sections.get("complexity_level", "")} ({sections.get("complexity_eta", "")})
Complexity guidance: {sections.get("complexity_recommendation", "")}

Operator answers:
{sections.get("operator_answers_text", "")}

Optional tool help text summary:
{sections.get("tool_help_summary", "")}

Auto-detected Kali WSL tool inventory:
{sections.get("inventory_summary", "")}

Loaded Burp tools or BApps:
{sections.get("loaded_burp_tools_summary", "")}

Program context:
{sections.get("program_context", "")}

Manual tool results or shared file references:
{sections.get("tool_results_summary", "")}

Burp config export audit input:
{sections.get("burp_config_summary", "")}

Burp settings screenshot audit input:
{sections.get("burp_screenshot_summary", "")}

Bug bounty program screenshot audit input:
{sections.get("program_screenshot_summary", "")}

Burp settings screenshot vision summary:
{sections.get("vision_summary", "")}

BApp findings:
{sections.get("bapp_findings_summary", "")}

Logger++ evidence:
{sections.get("logger_evidence_summary", "")}

Collaborator evidence:
{sections.get("collaborator_evidence_summary", "")}

Evidence timeline:
{sections.get("evidence_timeline_summary", "")}

Investigation workflow notes:
{sections.get("issue_workflow_notes_summary", "")}

Persistent investigation notebook:
{sections.get("investigation_notebook_summary", "")}

Explicit investigation phase state:
{sections.get("investigation_phase_summary", "No explicit phase state was derived.")}

Contradiction alerts:
{sections.get("contradiction_summary", "No contradiction assessment was derived.")}

Evidence sufficiency:
{sections.get("evidence_sufficiency_summary", "No evidence sufficiency state was derived.")}

Dead-end / no-repeat guard:
{sections.get("branch_guard_summary", "No no-repeat guard state was derived.")}

Per-vulnerability state machine:
{sections.get("vulnerability_state_summary", "No per-vulnerability state machine was derived.")}

Counter-hypothesis pass:
{sections.get("counter_hypothesis_summary", "No counter-hypothesis state was derived.")}

Historical confidence calibration:
{sections.get("confidence_calibration_summary", "No historical confidence calibration was derived.")}

Cross-issue cluster:
{sections.get("cross_issue_cluster_summary", "No cross-issue cluster was derived.")}

Response-diff semantics:
{sections.get("response_diff_semantics_summary", "No response-diff semantics were derived.")}

Program-aware impact path ranking:
{sections.get("impact_path_ranking_summary", "No program-aware impact path ranking was derived.")}

Live report bundle:
{sections.get("report_bundle_summary", "No live report bundle was derived.")}

Suggestion-specific follow-up request:
{sections.get("follow_up_request", "No explicit suggestion follow-up request supplied.")}

Suggestion-specific instruction block:
{sections.get("follow_up_instruction_block", "")}

Burp Scanner issue context:
{sections.get("scanner_issue_context", "")}

Burp tool-origin context:
{sections.get("burp_origin_context", "")}

Scanner-marked case bundle:
{sections.get("scanner_marked_case_summary", "No scanner-marked case bundle was derived.")}

Observed response delta from the operator:
{sections.get("response_delta_summary", "")}

Deterministic observations:
{sections.get("observations_text", "")}

Endpoint fingerprint:
{fingerprint}

Matched VA playbooks:
{sections.get("recipe_block", "")}

Rule-based baseline response:
{rule_baseline}

Retrieved prior similar findings from local memory:
{sections.get("memory_block", "")}

Retrieved local knowledge base context:
{sections.get("kb_context", "")}

Local knowledge base hits:
{kb_hits}

Structured local guidance database:
{sections.get("guidance_db_context", "")}

Structured local guidance database hits:
{guidance_db_hits}

Local review dataset summary:
{sections.get("review_dataset_summary", "")}

Local review dataset hits:
{review_dataset_hits}

Local escalation resources from deterministic guidance:
{local_resource_hints}

Curated reference links from deterministic guidance:
{reference_links}

Raw request summary:
{sections.get("raw_request_summary", "")}

Raw response summary:
{sections.get("raw_response_summary", "")}

Instructions:
- Keep the analysis grounded in the evidence and matched playbooks.
- For Burp-originated requests with Burp MCP enabled, treat Burp Scanner issue context, MCP-hydrated history, and the selected request as the primary source of truth before generic model intuition.
- Use the local knowledge base context when it is relevant, but do not repeat it blindly if it does not fit this exchange.
- Use the structured local guidance database as a methodology scaffold for validation, impact wording, workflow ordering, and payload sequencing when it matches the vulnerability class.
- Use the local review dataset to stay close to previously confirmed Burp workflows on the same target partition, but do not blindly copy a prior conclusion if this evidence is weaker.
- Use the curated reference links and local escalation resources to ground the next safe confirmation step when the local model is uncertain.
- If local memory shows similar prior findings, use that to prioritize likely vuln classes and to de-prioritize patterns that received negative feedback before.
- Use operator answers to narrow the hypothesis and reduce unnecessary follow-up.
- If tool help text is supplied, use it only to shape safe, low-rate, in-scope command syntax. Do not optimize for bypassing WAF, IDS, or other defensive controls.
- Respect in-scope and out-of-scope details strictly.
- If rate limits, concurrency limits, or custom headers are provided, reflect them in safe command suggestions where supported.
- If manual tool results are provided, analyze them as evidence and use them to decide the next single step instead of restarting from scratch.
- If loaded Burp tools or BApps are provided, prefer them before recommending missing external tools. Rank already loaded Burp helpers ahead of absent Kali tools when they can answer the same question.
- If a Burp config export is supplied, treat it as the strongest source of truth for current Burp settings and explicitly recommend which settings to keep, change, or leave manual.
- If Burp settings screenshot audit notes are supplied, treat them as operator-provided observations about the Settings UI. Do not pretend you saw more than what is described there.
- If a screenshot vision summary is supplied, treat it as evidence extracted from the provided screenshot files only. Do not claim that unseen Burp settings were reviewed.
- If an evidence timeline is supplied, use it as the ordered history of approved manual observations and focus the next step on the newest unresolved signal.
- If investigation workflow notes are supplied, treat them as prior AI-turn or operator-turn context and continue from the latest unresolved step instead of restarting from scratch.
- If a persistent investigation notebook is supplied, treat it as the longer-running case memory for this finding and preserve its escalation path across later follow-up turns.
- Treat the explicit investigation phase state as the current operating phase unless the attached evidence clearly supports a later phase.
- If contradiction alerts are present, resolve them before making stronger impact or reporting claims.
- Use the evidence sufficiency state to decide whether to stay in confirmation, move to impact, or assemble reporting evidence.
- If the no-repeat guard blocks the current branch, explicitly deprioritize that branch and move to the next best bounded hypothesis instead of replaying it.
- Follow the per-vulnerability state machine when choosing the next step, preferred evidence, and blocked moves for this issue family.
- Use the counter-hypothesis pass to test the strongest alternate explanation before finalizing the claim, and say what evidence is still needed to reject it.
- Use the historical confidence calibration to adjust certainty and step ordering; prefer historically successful mutation families and deprioritize families with weak local outcomes.
- If a cross-issue cluster is present, treat the Burp scanner siblings as one evolving case model, but keep one bounded request family active at a time.
- Use the response-diff semantics to name what actually changed, not only that the status or length changed.
- Use the program-aware impact path ranking to prioritize the most reward-relevant in-scope path, not only the technically possible path.
- Use the live report bundle as the default checklist for what proof is already clean, what is still missing, and how to package the next Burp-native evidence artifact for a bug bounty submission.
- If BApp findings are supplied, correlate them with the captured request and use them as additional passive evidence.
- If Logger++ evidence is supplied, treat its status, header, length, timing, and comment deltas as higher-signal evidence than generic notes.
- If the payload came from a Burp Scanner issue, treat that finding as the starting hypothesis and focus on confirmation steps, matching BChecks, and the next single validation action.
- If a scanner-marked case bundle is present, start by deciding whether the selected Burp issue looks likely real or likely false positive from the exact sink, object boundary, or highlighted evidence that Burp attached.
- If the scanner-marked issue looks likely real, move directly from bounded confirmation into the strongest in-scope impact-evidence path on the same issue family. Do not stop at generic rediscovery advice.
- Prefer the provided Repeater mutation plan, Burp-first tool recommendation, starter assets, local KB hits, guidance packs, and review examples before suggesting broader expansion.
- On later follow-up turns, do not reset to generic confirmation advice if the finding is already likely real. Move to the next stronger in-scope impact evidence artifact or the next missing report-bundle artifact.
- If the finding is already confirmed, prefer the strongest bounded impact-evidence path that stays on the same request family, trust boundary, or workflow.
- Use sibling Burp findings only when they strengthen the same reportable case; do not drift into unrelated bug families or invent exploit chains.
- Do not switch away from the selected Burp Scanner issue family just because sibling findings exist on the same path, unless the attached evidence clearly contradicts the selected issue.
- If Collaborator observations are supplied, interpret them conservatively as pasted evidence only. Do not suggest new callback collection or payload generation.
- Do not escalate into exploit instructions. Stay focused on safe confirmation, report-quality evidence capture, and in-scope business impact reasoning or related subdomian but defined in-scope(Ask the user in this case).
- Use reference links and local resources as methodology support only. Do not suggest internet exploit searches or public exploit mining.
- Improve the baseline if you can, but do not invent issues with no support in the exchange.
- Prefer auth, session, CSRF, access control, misconfiguration, and input-handling findings over generic statements.
- Optimize for a bug-bounty-quality outcome: first confirm the finding safely, then identify the strongest likely impact path that stays in scope and reward-relevant.
- If the likely issue has weak or no practical impact, say that plainly and redirect the operator toward the next better hypothesis instead of overselling it.
- When useful, describe the Burp-native workflow in phases: New Scan handoff, Repeater confirmation, Intruder expansion, and reporting evidence capture.
- For Burp-originated requests, keep the answer anchored to the same request family and explain how sibling Burp findings strengthen the same report rather than restarting as separate unrelated issues.
- Name the exact evidence the operator should capture for a report: baseline request, changed request, response delta, authorization difference, sensitive data exposed, state change, or business impact.
- Prefer impact-bearing escalation paths that bug-bounty programs care about: unauthorized data access, privilege expansion, cross-tenant access, state change, secret exposure, server-side fetches, or durable workflow abuse.
- If the operator asks for Burp steps, answer with exact execution order, exact tab sequence, exact insertion point or header to edit first, and exact comparison checks after each send.
- If the operator asks for Intruder guidance, name the attack type, the payload position strategy, the payload order, and the grep or diff checks explicitly.
- If the operator asks for payloads, return them in the order they should be tried, not as an unordered idea list.
- If the operator asks for Kali tools or commands, name the first command to run now and the second command only if the first produces a useful delta.
- Preserve or improve the suggested Kali WSL tool recommendations rather than deleting them.
- Questions must be practical follow-up questions for a tester using Burp and Kali WSL.
- If complexity is medium or high, explicitly suggest testing one endpoint or hypothesis at a time.
- If a known pattern matched before, mention that explicitly in the analysis.
- If the rule-based baseline is already the best answer, keep it close to that baseline.
- Include a strict `planner` JSON object with these exact fields:
  - `vuln_type` (string)
  - `confidence` (number from 0 to 1)
  - `parameters` (array of strings)
  - `attack_plan` (array of strings)
  - `next_action` (string)
  - `priority` (one of low, medium, high, critical)

Return ONLY valid JSON with this schema:
{{
  "analysis": "Concrete security assessment for this exchange.",
  "primary_next_action": "One concise next move for the operator.",
  "request_plan": ["Target parameter", "Primary mode", "Best command", "Starter payloads"],
  "potential_vulnerabilities": ["Specific hypothesis 1", "Specific hypothesis 2"],
  "planner": {{
    "vuln_type": "access-control",
    "confidence": 0.82,
    "parameters": ["id"],
    "attack_plan": ["capture baseline", "mutate id", "compare auth boundary"],
    "next_action": "mutate id in repeater and compare role responses",
    "priority": "high"
  }},
  "nuclei_tags": "comma,separated,tags",
  "seclists_path": "/usr/share/seclists/Discovery/Web-Content/example.txt",
  "questions_for_user": ["Specific follow-up question 1", "Specific follow-up question 2"],
  "source_links": ["https://example.com/reference1", "https://example.com/reference2"]
}}
"""


def build_result_analysis(
    analysis: str,
    *,
    memory_summary: dict,
    payload,
    profile_name: str,
    rule_context: dict,
    screenshot_review: dict,
    collaborator_summary: dict,
    append_manual_tooling,
    append_manual_commands,
    append_direct_follow_up_answer,
) -> str:
    if memory_summary.get("total_hits"):
        analysis = (
            f"{analysis}\n\nPrior local memory:\n"
            f"- {memory_summary['note']}"
        )
        if memory_summary.get("top_targets"):
            analysis += "\n- Similar prior targets: " + ", ".join(memory_summary["top_targets"])
    if getattr(payload, "operator_answers", None):
        analysis += "\n\nOperator answers received and applied where relevant."
    analysis += f"\nSelected profile: {profile_name}."
    analysis += "\nReview scope classes considered: " + ", ".join(rule_context["review_scope"]["allowed_classes"]) + "."
    if rule_context["review_scope"]["suppressed_classes"]:
        analysis += "\nSuppressed classes from your review scope: " + ", ".join(rule_context["review_scope"]["suppressed_classes"]) + "."
    if (getattr(payload, "tool_help_text", "") or "").strip():
        analysis += "\nTool help text was considered for safe command shaping."
    if (getattr(payload, "loaded_burp_tools_text", "") or "").strip():
        analysis += "\nLoaded Burp tools or BApps were considered and ranked ahead of missing external tools where they fit the next step."
    if (getattr(payload, "scope_includes_text", "") or "").strip() or (getattr(payload, "scope_excludes_text", "") or "").strip():
        analysis += "\nProgram scope details were considered."
    if (getattr(payload, "rate_limit_text", "") or "").strip() or (getattr(payload, "max_concurrency_text", "") or "").strip():
        analysis += "\nRate and concurrency limits were considered."
    if (getattr(payload, "custom_headers_text", "") or "").strip():
        analysis += "\nCustom headers were considered for compatible commands."
    if (getattr(payload, "tool_results_text", "") or "").strip():
        analysis += "\nManual tool results or shared file references were analyzed where relevant."
    if (getattr(payload, "burp_config_export_text", "") or "").strip():
        analysis += "\nBurp config export settings were reviewed as direct configuration evidence."
    if (getattr(payload, "burp_screenshot_audit_text", "") or "").strip():
        analysis += "\nBurp settings screenshot notes were reviewed as operator-supplied UI observations."
    if (getattr(payload, "saved_program_policy_text", "") or "").strip():
        analysis += "\nSaved bug bounty program rules were incorporated from AI-Bridge project settings."
    if (getattr(payload, "program_screenshot_audit_text", "") or "").strip():
        analysis += "\nBug bounty program screenshot notes were reviewed as project-level evidence."
    if screenshot_review.get("summary"):
        analysis += "\nLocal screenshot vision review was incorporated into the Burp settings guidance."
    elif screenshot_review.get("status") and (getattr(payload, "burp_screenshot_audit_text", "") or "").strip():
        analysis += "\nBurp screenshot review note: " + screenshot_review["status"]
    if (getattr(payload, "response_delta_text", "") or "").strip():
        analysis += "\nOperator-supplied response deltas were considered."
    if (getattr(payload, "bapp_findings_text", "") or "").strip():
        analysis += "\nBApp findings were correlated with this request where relevant."
    if (getattr(payload, "logger_evidence_text", "") or "").strip():
        analysis += "\nLogger++ evidence was incorporated as higher-signal diff evidence."
    if (getattr(payload, "collaborator_evidence_text", "") or "").strip():
        analysis += "\nCollaborator observations were interpreted as pasted evidence and incorporated conservatively."
        for note in collaborator_summary["confidence_notes"]:
            analysis += "\n- " + note
    if getattr(payload, "evidence_timeline_entries", None):
        analysis += f"\nEvidence timeline entries considered: {len(getattr(payload, 'evidence_timeline_entries', []))}."
    if getattr(payload, "issue_workflow_notes", None):
        analysis += f"\nInvestigation workflow notes considered: {len(getattr(payload, 'issue_workflow_notes', []))}."
    if (getattr(payload, "investigation_notebook_text", "") or "").strip():
        analysis += "\nPersistent investigation notebook context was considered for long multi-turn continuity."
    if (getattr(payload, "tool_results_text", "") or "").strip() or getattr(payload, "issue_workflow_notes", None):
        analysis += "\nExplicit investigation phase, contradiction, evidence sufficiency, no-repeat guard, state-machine, counter-hypothesis, confidence calibration, cross-issue clustering, response-diff semantics, and impact-path ranking were applied."
    analysis = append_manual_tooling(analysis, rule_context["aggregate"].get("manual_tooling", []))
    analysis = append_manual_commands(analysis, rule_context["aggregate"].get("manual_commands", []))
    return append_direct_follow_up_answer(analysis, payload, rule_context)
