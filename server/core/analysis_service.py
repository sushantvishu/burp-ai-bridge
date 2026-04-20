from datetime import datetime, timezone
from types import SimpleNamespace

from server.burp_mcp_context import augment_payload_with_burp_mcp
from server.capabilities.burp import normalize_burp_payload_contract
from server.capabilities.knowledge import search_local_knowledge
from server.core.burp_context_service import (
    get_dashboard_issue_context,
    get_related_dashboard_issue_contexts,
    get_logger_deltas,
    get_project_config_snapshot,
    get_recent_proxy_history,
    get_repeater_request,
    summarize_burp_context,
)
from server.core.reference_enrichment_service import enrich_advisory_with_references
from server.local_guidance_db import query_guidance_packs
from server.memory_partition import partition_from_payload
from server.providers.advisory_provider import analyze_security_advisory
from server.providers.deterministic_provider import build_deterministic_context
from server.providers.whitebox_provider import build_whitebox_enrichment
from server.review_dataset import query_review_examples
from server.settings import (
    ANALYSIS_LOOP_ENABLED,
    ANALYSIS_LOOP_HARD_STEP_CAP,
    ANALYSIS_LOOP_MAX_STEPS,
    ANALYSIS_LOOP_SCANNER_MAX_STEPS,
)
from server.state.models import AnalysisRun, EvidenceItem, Hypothesis


_PAYLOAD_DEFAULTS = {
    "request_id": "",
    "snapshot_id": "",
    "raw_request": "",
    "raw_response": "",
    "target_url": "",
    "http_method": "",
    "source_tool": "",
    "use_burp_mcp_context": False,
    "annotations": [],
    "batch_id": "",
    "batch_index": 0,
    "batch_total": 0,
    "operator_answers": {},
    "tool_help_text": "",
    "scope_includes_text": "",
    "scope_excludes_text": "",
    "rate_limit_text": "",
    "max_concurrency_text": "",
    "custom_headers_text": "",
    "program_policy_text": "",
    "program_platform": "",
    "program_policy_template": "",
    "burp_config_export_text": "",
    "tool_results_text": "",
    "burp_config_export_text": "",
    "burp_screenshot_audit_text": "",
    "loaded_burp_tools_text": "",
    "saved_program_policy_text": "",
    "program_screenshot_audit_text": "",
    "response_delta_text": "",
    "evidence_timeline_entries": [],
    "bapp_findings_text": "",
    "logger_evidence_text": "",
    "collaborator_evidence_text": "",
    "privacy_mode_override": "",
    "selected_profile": "",
    "enable_js_endpoint_extraction": False,
    "enable_race_signal_checks": False,
    "review_scope_include_classes": [],
    "review_scope_exclude_classes": [],
    "browser_verification_allowed": False,
    "browser_allowed_workflows": [],
    "browser_verification_notes": "",
    "baseline_response_text": "",
    "issue_workflow_notes": [],
    "investigation_notebook_text": "",
    "repeater_variant_observations": [],
    "burp_mcp_context_checked": False,
    "burp_mcp_context_applied": False,
    "burp_mcp_context_status": "",
    "burp_dashboard_issue": {},
    "burp_related_scanner_issues": [],
    "proxy_history_entries": [],
    "logger_entries": [],
    "repeater_requests": [],
    "project_config_snapshot": {},
}


def coerce_payload(payload_like) -> SimpleNamespace:
    if isinstance(payload_like, SimpleNamespace):
        source = vars(payload_like)
    elif isinstance(payload_like, dict):
        source = dict(payload_like)
    elif hasattr(payload_like, "model_dump"):
        source = payload_like.model_dump()
    elif hasattr(payload_like, "dict"):
        source = payload_like.dict()
    else:
        source = {name: getattr(payload_like, name) for name in _PAYLOAD_DEFAULTS if hasattr(payload_like, name)}

    source = augment_payload_with_burp_mcp(source)
    source = normalize_burp_payload_contract(source)
    source["burp_mcp_context_checked"] = True
    payload = {}
    for key, default in _PAYLOAD_DEFAULTS.items():
        value = source.get(key, default)
        if value is None:
            value = default
        payload[key] = value
    return SimpleNamespace(**payload)


def analyze_advisory(payload_like) -> dict:
    payload = coerce_payload(payload_like)
    advisory = analyze_security_advisory(payload)
    return enrich_advisory_with_references(payload, advisory)


def analyze_exchange(payload_like) -> dict:
    payload = coerce_payload(payload_like)
    advisory = enrich_advisory_with_references(payload, analyze_security_advisory(payload))
    run = build_analysis_run(payload, advisory)
    return {
        "advisory": advisory,
        "run": run.to_dict(),
    }


def analyze_exchange_bounded(payload_like, *, step_cap: int | None = None) -> dict:
    payload = coerce_payload(payload_like)
    base = analyze_exchange(payload)
    advisory = dict(base.get("advisory") or {})
    run = dict(base.get("run") or {})
    max_steps = _analysis_loop_step_cap(payload, requested=step_cap)
    if max_steps <= 0 or not ANALYSIS_LOOP_ENABLED:
        _attach_workflow_loop_phase(
            run,
            {
                "enabled": False,
                "step_cap": 0,
                "step_count": 0,
                "stop_reason": "disabled",
                "steps": [],
            },
        )
        return {"advisory": advisory, "run": run}

    from server.core import issue_workflow_service as _issue_workflow

    steps: list[dict] = []
    seen_observations: set[str] = set()
    stop_reason = "step-cap-reached"
    for step_index in range(1, max_steps + 1):
        planned_action = str(advisory.get("primary_next_action") or "").strip()
        observation = _issue_workflow.build_workflow_observation(payload)
        observation_fingerprint = str(observation.get("observation_fingerprint") or "").strip()
        repeated_observation = bool(observation_fingerprint and observation_fingerprint in seen_observations)
        if observation_fingerprint:
            seen_observations.add(observation_fingerprint)

        refined_action = _refine_action_from_observation(planned_action, observation)
        if refined_action and refined_action != planned_action:
            advisory["primary_next_action"] = refined_action
        else:
            refined_action = planned_action

        steps.append(
            {
                "step": step_index,
                "phase": "plan-act-observe-refine",
                "planned_action": planned_action,
                "workflow_status": observation.get("workflow_status", "planned"),
                "next_tab_name": observation.get("next_tab_name", ""),
                "next_tab_signal": observation.get("next_tab_signal", ""),
                "strongest_delta_score": float(observation.get("strongest_delta_score", 0.0) or 0.0),
                "observation_fingerprint": observation_fingerprint,
                "refined_action": refined_action,
                "report_ready": bool(observation.get("report_ready", False)),
            }
        )

        if bool(observation.get("report_ready")):
            stop_reason = "report-ready"
            break
        if float(observation.get("strongest_delta_score", 0.0) or 0.0) >= 2.5:
            stop_reason = "high-signal-observed"
            break
        if repeated_observation:
            stop_reason = "no-new-observation"
            break
        if not bool(observation.get("next_tab_has_request")):
            stop_reason = "no-next-step"
            break

    loop_phase = {
        "enabled": True,
        "step_cap": max_steps,
        "step_count": len(steps),
        "stop_reason": stop_reason,
        "steps": steps,
    }
    _attach_workflow_loop_phase(run, loop_phase)
    return {"advisory": advisory, "run": run}


def build_analysis_run(payload, advisory: dict) -> AnalysisRun:
    rule_context = build_deterministic_context(payload)
    dashboard_issue = get_dashboard_issue_context(payload)
    related_scanner_issues = get_related_dashboard_issue_contexts(payload)
    burp_context = summarize_burp_context(payload)
    kb_query = _build_kb_query(payload, rule_context)
    kb_search = search_local_knowledge(kb_query, top_k=3)
    memory_partition_key = partition_from_payload(payload)
    guidance_db = query_guidance_packs(
        [item.get("vuln_class", "general") for item in rule_context.get("matched_recipes", [])[:3]],
        partition_key=memory_partition_key,
        top_k=3,
    )
    review_dataset = query_review_examples(
        vuln_classes=[item.get("vuln_class", "general") for item in rule_context.get("matched_recipes", [])[:3]],
        partition_key=memory_partition_key,
        limit=3,
    )
    whitebox = build_whitebox_enrichment(kb_query)
    hypotheses = _build_hypotheses(payload, rule_context, advisory)
    evidence = _build_evidence(payload, rule_context, advisory, kb_search, whitebox)
    input_context = {
        "request_id": getattr(payload, "request_id", "") or "",
        "target_url": getattr(payload, "target_url", "") or "",
        "http_method": getattr(payload, "http_method", "") or "",
        "source_tool": getattr(payload, "source_tool", "") or "",
        "selected_profile": getattr(payload, "selected_profile", "") or "",
        "review_scope_include_classes": list(getattr(payload, "review_scope_include_classes", []) or []),
        "review_scope_exclude_classes": list(getattr(payload, "review_scope_exclude_classes", []) or []),
        "operator_answers": dict(getattr(payload, "operator_answers", {}) or {}),
        "program_limits": {
            "scope_includes_text": getattr(payload, "scope_includes_text", "") or "",
            "scope_excludes_text": getattr(payload, "scope_excludes_text", "") or "",
            "rate_limit_text": getattr(payload, "rate_limit_text", "") or "",
            "max_concurrency_text": getattr(payload, "max_concurrency_text", "") or "",
            "custom_headers_text": getattr(payload, "custom_headers_text", "") or "",
            "program_policy_text": getattr(payload, "program_policy_text", "") or "",
            "program_platform": getattr(payload, "program_platform", "") or "",
            "program_policy_template": getattr(payload, "program_policy_template", "") or "",
            "browser_verification_allowed": bool(getattr(payload, "browser_verification_allowed", False)),
            "browser_allowed_workflows": list(getattr(payload, "browser_allowed_workflows", []) or []),
        },
        "burp_context": burp_context,
        "related_scanner_issues": related_scanner_issues,
        "memory_partition_key": memory_partition_key,
    }
    phase_results = {
        "ingest": {
            "target_url": getattr(payload, "target_url", "") or "",
            "http_method": getattr(payload, "http_method", "") or "",
            "source_tool": getattr(payload, "source_tool", "") or "",
            "received_at": datetime.now(timezone.utc).isoformat(),
            "dashboard_issue": {
                "found": bool(dashboard_issue.get("found")),
                "issue_id": dashboard_issue.get("issue_id", ""),
                "issue_name": dashboard_issue.get("issue_name", ""),
                "severity": dashboard_issue.get("severity", ""),
                "confidence": dashboard_issue.get("confidence", ""),
                "affected_urls": (dashboard_issue.get("affected_urls") or [])[:4],
            },
            "related_scanner_issues": [
                {
                    "issue_id": item.get("issue_id", ""),
                    "issue_name": item.get("issue_name", ""),
                    "severity": item.get("severity", ""),
                    "confidence": item.get("confidence", ""),
                    "vuln_hint": item.get("vuln_hint", ""),
                }
                for item in related_scanner_issues[:4]
            ],
        },
        "enrich": {
            "observations": rule_context.get("features", {}).get("observations", [])[:12],
            "matched_playbooks": [item.get("title", "") for item in rule_context.get("matched_recipes", [])[:6]],
            "tool_summary": advisory.get("tool_availability_summary", ""),
            "burp_context": burp_context,
            "kb_hits": [
                {
                    "title": item.get("title") or item.get("file") or "",
                    "tags": item.get("tags", []),
                    "score": item.get("score", 0.0),
                }
                for item in kb_search.get("hits", [])[:4]
            ],
            "guidance_db_hits": [
                {
                    "name": item.get("name", ""),
                    "style": item.get("style", ""),
                    "matched_classes": item.get("matched_classes", []),
                    "reference_links": item.get("reference_links", [])[:3],
                }
                for item in guidance_db.get("hits", [])[:3]
            ],
            "review_dataset": {
                "count": review_dataset.get("count", 0),
                "summary": review_dataset.get("summary", ""),
                "recent_examples": [
                    {
                        "scanner_issue_name": item.get("scanner_issue_name", ""),
                        "outcome_label": item.get("outcome_label", ""),
                        "vuln_classes": item.get("vuln_classes", []),
                    }
                    for item in review_dataset.get("items", [])[:3]
                ],
            },
            "whitebox": {
                "enabled": whitebox.get("enabled", False),
                "summary": whitebox.get("summary", ""),
                "signals": whitebox.get("signals", [])[:6],
                "files": whitebox.get("files", [])[:8],
            },
        },
        "hypothesize": {
            "count": len(hypotheses),
            "classes": [item.vuln_class for item in hypotheses],
            "top_hypotheses": [
                {
                    "id": item.id,
                    "vuln_class": item.vuln_class,
                    "confidence": item.confidence,
                    "status": item.status,
                }
                for item in hypotheses[:4]
            ],
        },
    }
    fallback_reason = advisory.get("model_execution_summary", "") if advisory.get("fallback_used") else ""
    run = AnalysisRun(
        phases=phase_results,
        request_id=getattr(payload, "request_id", "") or "",
        input_context=input_context,
        phase_results=phase_results,
        hypotheses=hypotheses,
        evidence=evidence,
        provider_trace=list(advisory.get("model_execution_trace", []) or []),
        final_recommendation=advisory.get("primary_next_action", ""),
        fallback_reason=fallback_reason,
    )
    run_dict = run.to_dict()
    payload_dict = vars(payload).copy()
    payload_dict["burp_mcp_context_applied"] = True

    from server.core.impact_service import rank_impact_paths
    from server.core.validation_service import validate_hypothesis

    validation = validate_hypothesis(payload_dict, advisory=advisory, run=run_dict)
    impact = rank_impact_paths(payload_dict, advisory=advisory, run=run_dict)
    phase_results["validate"] = {
        "validation_status": validation.get("validation_status", ""),
        "confidence": validation.get("confidence", 0.0),
        "evidence_count": validation.get("evidence_count", 0),
        "evidence_sources": validation.get("evidence_sources", [])[:6],
        "missing_evidence": validation.get("missing_evidence", [])[:4],
        "confirmation_requirements": validation.get("confirmation_requirements", [])[:4],
        "safest_next_proof": validation.get("safest_next_proof", ""),
    }
    phase_results["impact"] = {
        "reportable": bool(impact.get("reportable")),
        "reportability": impact.get("reportability", ""),
        "business_impact_class": impact.get("business_impact_class", ""),
        "recommended_path": impact.get("recommended_path", ""),
        "ranked_impact_paths": impact.get("ranked_impact_paths", [])[:6],
        "evidence_gaps": impact.get("evidence_gaps", [])[:4],
        "safe_vapt_escalation_steps": impact.get("safe_vapt_escalation_steps", [])[:6],
        "baseline_confirmation": impact.get("baseline_confirmation", ""),
        "business_impact_expansion_paths": impact.get("business_impact_expansion_paths", [])[:4],
        "required_evidence_for_upgrade": impact.get("required_evidence_for_upgrade", [])[:4],
        "stop_conditions": impact.get("stop_conditions", [])[:4],
    }
    phase_results["report"] = {
        "backend": advisory.get("analysis_backend", ""),
        "fallback_used": bool(advisory.get("fallback_used")),
        "provider_trace_count": len(advisory.get("model_execution_trace", []) or []),
        "kb_sources_used": [item.get("file") or item.get("title") or "" for item in kb_search.get("hits", [])[:4]],
        "primary_next_action": advisory.get("primary_next_action", ""),
        "reporting_checklist": advisory.get("burp_action_checklist", [])[:6],
        "source_links": advisory.get("source_links", [])[:6],
        "validation_status": validation.get("validation_status", ""),
        "reportable": bool(impact.get("reportable")),
    }
    run.phases = phase_results
    run.phase_results = phase_results
    return run


def _build_hypotheses(payload, rule_context: dict, advisory: dict) -> list[Hypothesis]:
    confirmation_playbooks = advisory.get("confirmation_playbooks", []) or []
    impact_paths = advisory.get("impact_paths", []) or []
    confidence_map = _parse_confidence_entries(advisory.get("confidence_by_class", []) or [])
    vulnerabilities = advisory.get("potential_vulnerabilities", []) or []
    dashboard_issue = get_dashboard_issue_context(payload)
    related_scanner_issues = get_related_dashboard_issue_contexts(payload)
    hypotheses: list[Hypothesis] = []

    for index, item in enumerate(vulnerabilities[:6], start=1):
        vuln_class = _vuln_class_from_entry(item)
        confidence = confidence_map.get(vuln_class, 0.5)
        hypotheses.append(
            Hypothesis(
                id=f"hyp-{index}",
                vuln_class=vuln_class,
                summary=item,
                confidence=confidence,
                evidence_for=rule_context.get("features", {}).get("observations", [])[:4],
                impact_paths=impact_paths[:3],
                next_checks=confirmation_playbooks[:2] or advisory.get("questions_for_user", [])[:2],
            )
        )

    if dashboard_issue.get("found"):
        issue_class = dashboard_issue.get("vuln_hint") or "general"
        existing_classes = {item.vuln_class for item in hypotheses}
        issue_name = dashboard_issue.get("issue_name") or "scanner finding"
        summary = f"[{issue_class}] Burp Dashboard flagged {issue_name}"
        if issue_class not in existing_classes or not hypotheses:
            hypotheses.append(
                Hypothesis(
                    id=f"hyp-{len(hypotheses) + 1}",
                    vuln_class=issue_class,
                    summary=summary,
                    confidence=confidence_map.get(issue_class, _dashboard_confidence_score(dashboard_issue)),
                    evidence_for=[
                        f"Burp Dashboard: {issue_name}",
                        *(dashboard_issue.get("evidence_items") or [])[:2],
                        *(rule_context.get("features", {}).get("observations", [])[:2]),
                    ][:4],
                    impact_paths=impact_paths[:3],
                    next_checks=confirmation_playbooks[:2] or advisory.get("questions_for_user", [])[:2],
                )
            )
    for item in related_scanner_issues[:3]:
        issue_class = item.get("vuln_hint") or "general"
        issue_name = item.get("issue_name") or "related scanner finding"
        if any(existing.vuln_class == issue_class and issue_name.lower() in existing.summary.lower() for existing in hypotheses):
            continue
        hypotheses.append(
            Hypothesis(
                id=f"hyp-{len(hypotheses) + 1}",
                vuln_class=issue_class,
                summary=f"[related:{issue_class}] Burp also flagged {issue_name}",
                confidence=confidence_map.get(issue_class, _dashboard_confidence_score(item) - 0.05),
                evidence_for=[
                    f"Burp related issue: {issue_name}",
                    *(item.get("evidence_items") or [])[:2],
                ][:3],
                impact_paths=impact_paths[:2],
                next_checks=confirmation_playbooks[:2] or advisory.get("questions_for_user", [])[:2],
            )
        )
    return hypotheses


def _build_evidence(payload, rule_context: dict, advisory: dict, kb_search: dict | None = None, whitebox: dict | None = None) -> list[EvidenceItem]:
    evidence: list[EvidenceItem] = []
    dashboard_issue = get_dashboard_issue_context(payload)
    related_scanner_issues = get_related_dashboard_issue_contexts(payload)
    proxy_history = get_recent_proxy_history(payload, limit=4)
    logger_entries = get_logger_deltas(payload, limit=4)
    repeater_requests = get_repeater_request(payload, limit=3)
    project_config = get_project_config_snapshot(payload)

    if dashboard_issue.get("found"):
        summary = f"{dashboard_issue.get('issue_name') or 'Burp issue'} ({dashboard_issue.get('severity') or 'info'}/{dashboard_issue.get('confidence') or 'tentative'})"
        notes = dashboard_issue.get("detail") or dashboard_issue.get("background") or ""
        evidence.append(
            EvidenceItem(
                source="burp-dashboard",
                summary=summary,
                evidence_type="scanner",
                confidence=_dashboard_confidence_score(dashboard_issue),
                request_ref=((dashboard_issue.get("request_refs") or [""])[0] or ""),
                response_ref=((dashboard_issue.get("response_refs") or [""])[0] or ""),
                notes=notes,
            )
        )
        for item in (dashboard_issue.get("evidence_items") or [])[:2]:
            evidence.append(
                EvidenceItem(
                    source="burp-dashboard",
                    summary=item,
                    evidence_type="scanner",
                    confidence=_dashboard_confidence_score(dashboard_issue),
                    notes=dashboard_issue.get("issue_name", ""),
                )
            )
    for issue in related_scanner_issues[:3]:
        evidence.append(
            EvidenceItem(
                source="burp-dashboard-related",
                summary=f"Related Burp issue: {issue.get('issue_name') or 'scanner finding'}",
                evidence_type="scanner",
                confidence=max(0.4, _dashboard_confidence_score(issue) - 0.1),
                request_ref=((issue.get("request_refs") or [""])[0] or ""),
                response_ref=((issue.get("response_refs") or [""])[0] or ""),
                notes=issue.get("detail") or issue.get("target_url") or "",
            )
        )

    for observation in rule_context.get("features", {}).get("observations", [])[:8]:
        evidence.append(EvidenceItem(source="rule-engine", summary=observation, evidence_type="derived", confidence=0.65))

    response_delta = (getattr(payload, "response_delta_text", "") or "").strip()
    if response_delta:
        evidence.append(EvidenceItem(source="operator-delta", summary=response_delta, evidence_type="manual-diff", confidence=0.7, delta=response_delta))

    for item in (getattr(payload, "evidence_timeline_entries", None) or [])[:6]:
        normalized = (item or "").strip()
        if normalized:
            evidence.append(EvidenceItem(source="timeline", summary=normalized, evidence_type="timeline", confidence=0.6))

    for source_name, entries, confidence in [
        ("proxy", proxy_history.get("entries", []), 0.68),
        ("logger", logger_entries.get("entries", []), 0.72),
        ("repeater", repeater_requests.get("entries", []), 0.75),
    ]:
        for entry in entries[:3]:
            evidence.append(
                EvidenceItem(
                    source=source_name,
                    summary=entry.get("summary") or entry.get("url") or f"{source_name} entry",
                    evidence_type=_evidence_type_for_source(source_name, entry),
                    confidence=confidence,
                    request_ref=entry.get("request_ref", ""),
                    response_ref=entry.get("response_ref", ""),
                    notes=entry.get("notes") or entry.get("url") or "",
                    timestamp=entry.get("timestamp", ""),
                )
            )

    for warning in (project_config.get("config_warnings") or [])[:3]:
        evidence.append(
            EvidenceItem(
                source="project-config",
                summary=warning,
                evidence_type="config",
                confidence=0.55,
                notes=project_config.get("selected_profile", ""),
            )
        )

    for source_name, attr_name in [
        ("bapp", "bapp_findings_text"),
        ("logger", "logger_evidence_text"),
        ("collaborator", "collaborator_evidence_text"),
    ]:
        value = (getattr(payload, attr_name, "") or "").strip()
        if value:
            evidence.append(
                EvidenceItem(
                    source=source_name,
                    summary=value[:240],
                    evidence_type=_evidence_type_for_source(source_name, {"summary": value}),
                    confidence=0.72,
                )
            )

    for hit in (kb_search or {}).get("hits", [])[:3]:
        title = hit.get("title") or hit.get("file") or "kb-note"
        tags = ", ".join(hit.get("tags", []) or [])
        summary = f"{title}: {hit.get('text', '')[:180]}".strip()
        notes = f"tags={tags}" if tags else ""
        evidence.append(EvidenceItem(source="local-kb", summary=summary, evidence_type="knowledge-base", confidence=0.58, notes=notes))

    if (whitebox or {}).get("enabled"):
        for signal in (whitebox or {}).get("signals", [])[:3]:
            evidence.append(EvidenceItem(source="whitebox", summary=signal, evidence_type="whitebox", confidence=0.55))

    if not evidence:
        evidence.append(
            EvidenceItem(
                source="analysis",
                summary=advisory.get("analysis", "")[:240] or "No extra evidence supplied.",
                evidence_type="derived",
                confidence=0.45,
            )
        )
    return evidence[:12]


def _evidence_type_for_source(source_name: str, entry: dict | None = None) -> str:
    normalized = (source_name or "").strip().lower()
    if normalized == "proxy":
        return "traffic-history"
    if normalized == "logger":
        return "manual-diff"
    if normalized == "repeater":
        summary = ((entry or {}).get("summary") or "").lower()
        if any(token in summary for token in ("role", "account", "tenant", "cross-user", "cross-account")):
            return "role-compare"
        return "manual-diff"
    if normalized == "collaborator":
        return "callback"
    if normalized == "bapp":
        return "scanner"
    return "operator-note"


def _build_kb_query(payload, rule_context: dict) -> str:
    dashboard_issue = get_dashboard_issue_context(payload)
    recipe_titles = [recipe.get("title", "") for recipe in rule_context.get("matched_recipes", [])[:3]]
    param_names = rule_context.get("features", {}).get("param_names", [])[:6]
    path = rule_context.get("features", {}).get("path", "") or ""
    observations = rule_context.get("features", {}).get("observations", [])[:4]
    query_parts = [
        getattr(payload, "target_url", "") or "",
        getattr(payload, "http_method", "") or "",
        path,
        " ".join(recipe_titles),
        " ".join(param_names),
        " ".join(observations),
        dashboard_issue.get("issue_name", ""),
        dashboard_issue.get("detail", ""),
    ]
    return " ".join(part for part in query_parts if part).strip()


def _parse_confidence_entries(entries: list[str]) -> dict[str, float]:
    confidence_map: dict[str, float] = {}
    for entry in entries:
        if ":" not in entry:
            continue
        label, _, remainder = entry.partition(":")
        value = 0.5
        marker = "confidence -"
        if marker in remainder:
            prefix = remainder.split(marker, 1)[0].strip()
            try:
                value = float(prefix)
            except ValueError:
                value = 0.5
        confidence_map[label.strip()] = value
    return confidence_map


def _vuln_class_from_entry(entry: str) -> str:
    text = (entry or "").strip()
    if text.startswith("[") and "]" in text:
        return text[1:text.index("]")].strip() or "general"
    return "general"


def _dashboard_confidence_score(dashboard_issue: dict) -> float:
    severity = (dashboard_issue.get("severity") or "").strip().lower()
    confidence = (dashboard_issue.get("confidence") or "").strip().lower()
    if confidence in {"certain", "firm"}:
        return 0.9
    if confidence in {"high", "strong", "confirmed"}:
        return 0.84
    if confidence in {"tentative", "medium"}:
        return 0.7
    if severity in {"high", "critical"}:
        return 0.78
    if severity == "medium":
        return 0.7
    return 0.62


def _analysis_loop_step_cap(payload, *, requested: int | None = None) -> int:
    if not ANALYSIS_LOOP_ENABLED:
        return 0
    requested_cap = int(requested) if requested is not None else 0
    source_tool = (getattr(payload, "source_tool", "") or "").strip().lower()
    default_cap = ANALYSIS_LOOP_SCANNER_MAX_STEPS if "scanner" in source_tool else ANALYSIS_LOOP_MAX_STEPS
    cap = requested_cap if requested_cap > 0 else default_cap
    hard_cap = max(1, int(ANALYSIS_LOOP_HARD_STEP_CAP or 1))
    return max(1, min(int(cap or 1), hard_cap))


def _refine_action_from_observation(planned_action: str, observation: dict) -> str:
    base = (planned_action or "").strip() or "Capture one clean baseline comparison."
    next_tab = str(observation.get("next_tab_name") or "").strip()
    signal = str(observation.get("next_tab_signal") or "").strip()
    if not next_tab:
        return base
    suffix = f" Focus next on `{next_tab}`."
    if signal:
        suffix += f" Validate signal: {signal}."
    if suffix.strip() in base:
        return base
    return f"{base}{suffix}"


def _attach_workflow_loop_phase(run: dict, loop_phase: dict) -> None:
    phases = dict(run.get("phases") or {})
    phase_results = dict(run.get("phase_results") or {})
    phases["workflow_loop"] = dict(loop_phase)
    phase_results["workflow_loop"] = dict(loop_phase)
    run["phases"] = phases
    run["phase_results"] = phase_results
