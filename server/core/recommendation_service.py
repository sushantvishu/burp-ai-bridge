from server.bcheck_catalog import recommend_bchecks
from server.core.best_next_step_service import build_one_best_next_step
from server.core.burp_context_service import get_dashboard_issue_context
from server.core.reference_enrichment_service import curated_references_for_class
from server.core.action_labels import label_actions
from server.core.analysis_service import coerce_payload
from server.issue_family_memory import summarize_issue_family_memory
from server.rule_engine import build_rule_context


def recommend_bchecks_for_exchange(payload_like) -> dict:
    payload = coerce_payload(payload_like)
    rule_context = build_rule_context(payload)
    aggregate = rule_context.get("aggregate", {})
    matched_recipes = rule_context.get("matched_recipes", [])
    review_scope = rule_context.get("review_scope", {}) or {}
    issue = get_dashboard_issue_context(payload)
    vuln_class = (
        (issue.get("vuln_hint") or "")
        or (review_scope.get("allowed_classes") or ["general"])[0]
        or "general"
    )
    issue_family_memory = summarize_issue_family_memory(
        payload,
        issue_id=issue.get("issue_id", ""),
        vuln_classes=[vuln_class],
    )
    official_candidates = recommend_bchecks(
        rule_context.get("features", {}),
        matched_recipes,
        list(review_scope.get("allowed_classes", []) or []),
        limit=6,
    )
    official_candidates = _apply_bcheck_learning(official_candidates, issue_family_memory)
    selected_official = official_candidates[0] if official_candidates else {}
    one_best_next_step = build_one_best_next_step(
        title=(
            f"Import and run {selected_official.get('name')} on the current issue family."
            if selected_official else
            "Keep the current issue family narrow before adding an official PortSwigger BCheck."
        ),
        source="official-bcheck-selector" if selected_official else "review-scope",
        why=(
            selected_official.get("why", "")
            if selected_official else
            "The current context is not yet narrow enough for a high-signal official BCheck."
        ),
        manual_step=(
            f"Import {selected_official.get('relative_path')} into Burp custom scan checks and run it only on the scanner-marked request family."
            if selected_official else
            "Keep the issue scoped to one bounded request family, then ask for the official BCheck selector again."
        ),
        expected_signal=(
            selected_official.get("usage_hint", "")
            if selected_official else
            "One repeatable low-noise signal tied to the same route family."
        ),
        stop_when=(
            "One useful proof artifact is added, or the check stays noisy on this issue family."
            if selected_official else
            "The request family is narrowed enough for one official check."
        ),
        supporting_references=_selection_references(selected_official, vuln_class),
    )
    return {
        "target_url": getattr(payload, "target_url", "") or "",
        "recommended_bchecks": list(aggregate.get("bcheck_recommendations") or [])[:6],
        "matched_playbooks": [item.get("title", "") for item in matched_recipes[:6]],
        "review_scope_include_classes": list(getattr(payload, "review_scope_include_classes", []) or []),
        "official_bcheck_candidates": official_candidates[:4],
        "selected_official_bcheck": selected_official,
        "issue_family_memory": issue_family_memory,
        "one_best_next_step": one_best_next_step,
        "curated_reference_links": _selection_references(selected_official, vuln_class),
    }


def review_project_readiness(payload_like) -> dict:
    payload = coerce_payload(payload_like)
    rule_context = build_rule_context(payload)
    aggregate = rule_context.get("aggregate", {})
    checks = list(aggregate.get("project_readiness_checks") or [])[:8]
    return {
        "target_url": getattr(payload, "target_url", "") or "",
        "project_readiness_summary": aggregate.get("project_readiness_summary", ""),
        "project_readiness_checks": checks,
        "labeled_project_readiness_checks": label_actions(checks, fallback_used=False)[:8],
        "burp_action_checklist": list(aggregate.get("burp_action_checklist") or [])[:8],
        "bcheck_recommendations": list(aggregate.get("bcheck_recommendations") or [])[:4],
    }


def _apply_bcheck_learning(candidates: list[dict], issue_family_memory: dict) -> list[dict]:
    suppressed = set(issue_family_memory.get("suppressed_bcheck_ids") or [])
    preferred = set(issue_family_memory.get("preferred_bcheck_ids") or [])
    score_by_bcheck = dict((issue_family_memory.get("bcheck_learning_summary") or {}).get("score_by_bcheck") or {})
    ranked = []
    for entry in candidates:
        value = dict(entry)
        relative_path = str(value.get("relative_path") or value.get("id") or "").strip()
        adjustment = int(score_by_bcheck.get(relative_path, 0) or 0)
        if relative_path in preferred:
            adjustment += 2
        if relative_path in suppressed:
            adjustment -= 4
        value["learning_adjustment"] = adjustment
        value["suppressed_for_issue_family"] = relative_path in suppressed
        value["preferred_for_issue_family"] = relative_path in preferred
        value["selection_references"] = _selection_references(value, value.get("vuln_classes", ["general"])[0] if value.get("vuln_classes") else "general")
        ranked.append(value)
    ranked.sort(
        key=lambda item: (
            -(float(item.get("score", 0.0) or 0.0) + float(item.get("learning_adjustment", 0.0) or 0.0)),
            bool(item.get("suppressed_for_issue_family")),
            str(item.get("relative_path", "")),
        )
    )
    return ranked


def _selection_references(selected_official: dict[str, object], vuln_class: str) -> list[str]:
    links = []
    source_url = str(selected_official.get("source_url") or "").strip() if selected_official else ""
    if source_url:
        links.append(source_url)
    for link in curated_references_for_class(vuln_class):
        if link not in links:
            links.append(link)
    return links[:6]
