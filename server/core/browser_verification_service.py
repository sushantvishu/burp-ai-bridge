from typing import Any

from server.core.action_labels import label_action, label_actions
from server.core.analysis_service import analyze_exchange, build_analysis_run, coerce_payload
from server.core.burp_context_service import get_dashboard_issue_context
from server.core.impact_service import rank_impact_paths
from server.core.program_policy_service import build_program_policy_context
from server.core.validation_service import validate_hypothesis


_BROWSER_FRIENDLY_CLASSES = {"authorization", "idor", "xss", "csrf", "authentication", "session-management"}
_HIGH_IMPACT_CLASSES = {"authorization", "idor", "authentication", "session-management", "xss", "csrf"}


def build_browser_verification_plan(
    payload_like,
    *,
    advisory: dict | None = None,
    run: dict | None = None,
    validation: dict | None = None,
    impact: dict | None = None,
) -> dict[str, Any]:
    payload = coerce_payload(payload_like)
    if advisory is None:
        analysis_bundle = analyze_exchange(payload)
        advisory = analysis_bundle["advisory"]
        run = analysis_bundle["run"]
    elif run is None or not isinstance(run, dict):
        run = build_analysis_run(payload, advisory).to_dict()

    validation = validation or validate_hypothesis(payload, advisory=advisory or {}, run=run or {})
    impact = impact or rank_impact_paths(payload, advisory=advisory or {}, run=run or {})
    dashboard_issue = get_dashboard_issue_context(payload)
    policy = build_program_policy_context(payload)

    hypothesis = validation.get("hypothesis") or {}
    vuln_class = (
        (hypothesis.get("vuln_class") or "")
        or dashboard_issue.get("vuln_hint")
        or "general"
    ).strip().lower()
    allowed_workflows = _normalize_list(getattr(payload, "browser_allowed_workflows", []) or [])
    explicit_allow = bool(getattr(payload, "browser_verification_allowed", False))
    eligible = _is_browser_confirmation_candidate(vuln_class, validation, impact, dashboard_issue)
    allowed = bool(eligible and explicit_allow and allowed_workflows)
    requires_manual_session = vuln_class in {"authorization", "idor", "authentication", "session-management", "csrf"}

    goal = _verification_goal(vuln_class, validation, impact)
    checkpoints = _build_checkpoints(vuln_class, dashboard_issue, impact)
    evidence_to_capture = _build_evidence_targets(vuln_class, impact)
    stop_conditions = _build_stop_conditions(policy, allowed_workflows, vuln_class, impact)
    policy_notes = (
        list(policy.get("browser_verification_rules", []) or [])[:3]
        + list(policy.get("safe_testing_notes", []) or [])[:2]
        + list(policy.get("rate_limit_guidance", []) or [])[:2]
    )

    if not eligible:
        reason = "Browser confirmation is not the next best proof for the current finding state."
        suggested_steps = [reason]
        labeled_steps = [label_action(reason, "manual-review-required")]
    elif not explicit_allow or not allowed_workflows:
        reason = "Browser confirmation requires explicit opt-in plus a named allowed workflow list."
        suggested_steps = [
            "Out of scope until the allowed browser workflow list is explicit.",
            "Name the exact pages or flows that are permitted for manual confirmation.",
        ]
        labeled_steps = [
            label_action(suggested_steps[0], "out-of-scope-risk"),
            label_action(suggested_steps[1], "needs-confirmation"),
        ]
    else:
        reason = "Browser confirmation can proceed within the named workflows only."
        suggested_steps = _build_suggested_steps(goal, allowed_workflows, checkpoints, evidence_to_capture, stop_conditions)
        labeled_steps = label_actions(suggested_steps, fallback_used=bool(advisory.get("fallback_used")))[:8]

    return {
        "target_url": getattr(payload, "target_url", "") or "",
        "program_platform": policy.get("name", "generic"),
        "eligible": bool(eligible),
        "allowed": allowed,
        "reason": reason,
        "verification_goal": goal,
        "validation_status": validation.get("validation_status", ""),
        "reportability": impact.get("reportability", ""),
        "requires_manual_session": requires_manual_session,
        "allowed_workflows": allowed_workflows[:6],
        "checkpoints": checkpoints[:6],
        "evidence_to_capture": evidence_to_capture[:6],
        "policy_notes": policy_notes[:6],
        "stop_conditions": stop_conditions[:6],
        "out_of_scope_risks": list(policy.get("out_of_scope_risks", []) or [])[:6],
        "suggested_steps": suggested_steps[:8],
        "labeled_steps": labeled_steps[:8],
    }


def _normalize_list(items: list[str]) -> list[str]:
    result: list[str] = []
    for item in items:
        normalized = (item or "").strip()
        if normalized and normalized not in result:
            result.append(normalized)
    return result


def _is_browser_confirmation_candidate(vuln_class: str, validation: dict, impact: dict, dashboard_issue: dict) -> bool:
    if vuln_class in _BROWSER_FRIENDLY_CLASSES:
        return True
    if (validation.get("validation_status") or "").strip().lower() in {"needs-confirmation", "high-signal"}:
        return True
    if (impact.get("reportability") or "").strip().lower() == "medium":
        return True
    severity = (dashboard_issue.get("severity") or "").strip().lower()
    return severity in {"medium", "high", "critical"}


def _verification_goal(vuln_class: str, validation: dict, impact: dict) -> str:
    if vuln_class in {"authorization", "idor"}:
        return "Confirm the same object or action across the allowed roles without broadening access attempts."
    if vuln_class == "xss":
        return "Confirm the rendering context and whether the sink is reachable from the allowed shared or privileged view."
    if vuln_class in {"authentication", "session-management"}:
        return "Confirm which authenticated state or role reaches the same response path and whether the UI reflects that boundary."
    if vuln_class == "csrf":
        return "Confirm one low-risk state-changing workflow and whether the browser-side control is visibly absent."
    if (impact.get("reportability") or "").strip().lower() == "medium":
        return "Resolve the missing workflow or auth-state ambiguity with one bounded browser confirmation."
    return "Confirm the user-facing workflow state that matches the Burp evidence bundle."


def _build_checkpoints(vuln_class: str, dashboard_issue: dict, impact: dict) -> list[str]:
    checkpoints = [
        "Start from the same asset and request context already captured in Burp.",
        "Record the exact page, role, and visible state before changing any input.",
    ]
    if vuln_class in {"authorization", "idor"}:
        checkpoints.extend([
            "Confirm the visible object identifier or action target matches the Burp request.",
            "Check whether the same object appears under a different allowed identity without modifying it.",
        ])
    elif vuln_class == "xss":
        checkpoints.extend([
            "Confirm whether the input reaches HTML, attribute, script, or text context.",
            "Record which role or workflow can see the rendered output.",
        ])
    elif vuln_class in {"authentication", "session-management"}:
        checkpoints.extend([
            "Confirm whether the UI session state matches the HTTP state seen in Burp.",
            "Record the login boundary, role indicator, or session marker that changes.",
        ])
    elif vuln_class == "csrf":
        checkpoints.extend([
            "Confirm the browser workflow is low-risk and reversible.",
            "Check whether the page or request visibly lacks an anti-CSRF control.",
        ])
    else:
        checkpoints.append("Check whether the same visible workflow state explains the Burp-side delta.")

    recommended_path = (impact.get("recommended_path") or "").strip()
    if recommended_path:
        checkpoints.append(f"Keep the confirmation aligned to this path: {recommended_path}")
    issue_name = (dashboard_issue.get("issue_name") or "").strip()
    if issue_name:
        checkpoints.append(f"Preserve the same issue focus as the scanner context: {issue_name}")
    return checkpoints


def _build_evidence_targets(vuln_class: str, impact: dict) -> list[str]:
    items = [
        "A screenshot or note showing the exact allowed page and session or role state.",
        "One baseline artifact and one comparison artifact tied back to the Burp request or response refs.",
    ]
    if vuln_class in {"authorization", "idor", "authentication", "session-management"}:
        items.append("A role-separated comparison that shows the same object or page under two permitted identities.")
    if vuln_class == "xss":
        items.append("A benign proof that shows the rendering context without executing a harmful payload chain.")
    if vuln_class == "csrf":
        items.append("A note showing the low-risk workflow, visible control state, and whether a CSRF token is absent.")
    safest_next_proof = (impact.get("safest_next_proof") or "").strip()
    if safest_next_proof:
        items.append(f"Keep the browser proof consistent with the safest next proof: {safest_next_proof}")
    items.extend(list(impact.get("required_evidence_for_upgrade") or [])[:2])
    return _normalize_list(items)


def _build_stop_conditions(policy: dict, allowed_workflows: list[str], vuln_class: str, impact: dict) -> list[str]:
    items = [
        "Stop if the next click, submission, or replay would cause destructive, financial, messaging, or irreversible state changes.",
        "Stop if the proof would leave the named allowed workflows or touch third-party assets.",
    ]
    if allowed_workflows:
        items.append("Stop if the workflow changes from the explicit allow-list: " + ", ".join(allowed_workflows[:3]))
    if vuln_class not in _HIGH_IMPACT_CLASSES:
        items.append("Stop if the browser check starts to look like broad discovery rather than bounded confirmation.")
    items.extend(list(impact.get("stop_conditions") or [])[:2])
    items.extend(list(policy.get("out_of_scope_risks", []) or [])[:2])
    return _normalize_list(items)


def _build_suggested_steps(
    goal: str,
    allowed_workflows: list[str],
    checkpoints: list[str],
    evidence_to_capture: list[str],
    stop_conditions: list[str],
) -> list[str]:
    steps = [
        f"Review only these allowed workflows before opening the browser: {', '.join(allowed_workflows[:4])}.",
        goal,
        checkpoints[0] if checkpoints else "",
        checkpoints[1] if len(checkpoints) > 1 else "",
        evidence_to_capture[0] if evidence_to_capture else "",
        stop_conditions[0] if stop_conditions else "",
    ]
    return [item for item in steps if (item or "").strip()]
