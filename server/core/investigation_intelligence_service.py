from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from server.core.burp_context_service import get_dashboard_issue_context, get_related_dashboard_issue_contexts
from server.core.impact_upgrade_service import (
    build_impact_upgrade_planner,
    build_program_specific_impact_wording,
    build_submission_value_score,
)
from server.core.program_policy_service import assess_high_risk_escalation_policy, build_program_policy_context
from server.memory_partition import partition_from_payload
from server.negative_reasoning_memory import summarize_negative_reasoning
from server.repeater_learning import summarize_repeater_learning
from server.review_dataset import query_review_examples


_PHASE_ORDER = {
    "triage": 0,
    "confirmation": 1,
    "impact": 2,
    "reporting": 3,
}

_PHASE_REASONING = {
    "triage": "Pin one bounded hypothesis and capture a clean baseline before widening the case.",
    "confirmation": "Capture one reproducible observed signal or corroborating source before stronger impact claims.",
    "impact": "Use the confirmed signal to prove the strongest bounded business-impact path that stays in scope.",
    "reporting": "The evidence is strong enough to assemble report wording, artifacts, and claim boundaries.",
}

_EVIDENCE_WEIGHTS = {
    "response-delta": 1.2,
    "logger-evidence": 1.0,
    "collaborator-evidence": 1.35,
    "evidence-timeline": 0.7,
    "scanner-baseline": 0.55,
    "workflow-memory": 0.35,
    "bapp-findings": 0.35,
}

_CONFIRMATION_MARKERS = (
    "confirm",
    "confirmation",
    "validate",
    "baseline",
    "compare",
    "diff",
    "reproduce",
    "exact change",
    "next exact",
    "next request change",
)
_IMPACT_MARKERS = (
    "impact",
    "cross-tenant",
    "cross user",
    "cross-user",
    "privilege",
    "admin",
    "unauthorized",
    "exposure",
    "state change",
    "blast radius",
    "tenant",
    "severity",
)
_REPORTING_MARKERS = (
    "write-up",
    "writeup",
    "report-ready",
    "report ready",
    "title",
    "summary",
    "wording",
    "submission",
    "triage note",
    "evidence bundle",
)
_NEGATIVE_MARKERS = (
    "no signal",
    "no delta",
    "same result",
    "same response",
    "did not reproduce",
    "not reproducible",
    "dead end",
    "dead-end",
    "failed",
    "inconclusive",
    "preview only",
    "still the same",
)
_POSITIVE_MARKERS = (
    "confirmed",
    "reproduced",
    "role diff",
    "role-separated",
    "cross-tenant",
    "unauthorized",
    "callback",
    "rendered",
    "executed",
    "state change",
    "admin viewer",
    "shared viewer",
    "privileged",
)

_CLASS_ALIASES = {
    "auth": "authentication",
    "idor": "authorization",
    "access-control": "authorization",
    "broken-access-control": "authorization",
    "auth-bypass": "authentication",
    "session-management": "authentication",
    "sqli": "injection",
    "sql-injection": "injection",
    "ssti": "template-injection",
    "server-side-template-injection": "template-injection",
}

_CLUSTER_JOIN_COMPATIBILITY = {
    "authorization": {"authorization", "information-disclosure", "secret-exposure", "authentication", "mass-assignment"},
    "authentication": {"authentication", "authorization", "secret-exposure", "csrf", "jwt-token"},
    "xss": {"xss", "template-injection", "information-disclosure", "security-misconfiguration"},
    "ssrf": {"ssrf", "xxe", "open-redirect", "security-misconfiguration"},
    "template-injection": {"template-injection", "xss", "information-disclosure"},
    "injection": {"injection", "information-disclosure", "mass-assignment", "security-misconfiguration"},
    "race-condition": {"race-condition", "business-logic", "authorization"},
    "business-logic": {"business-logic", "race-condition", "authorization", "mass-assignment"},
    "xxe": {"xxe", "ssrf", "information-disclosure"},
}

_POSITIVE_OUTCOME_LABELS = {"confirmed-reportable", "confirmed-bounded"}

_RESPONSE_SEMANTIC_KEYWORDS = {
    "auth-boundary": ("unauthorized", "forbidden", "role-separated", "other user's", "other tenant", "cross-tenant", "cross-user", "permission"),
    "sink-context-shift": ("attribute context", "script context", "html context", "rendered", "reflection", "reflected", "sink", "viewer", "encoded"),
    "data-exposure": ("visible", "exposed", "profile data", "invoice", "object data", "fields", "pii", "secret", "token", "returned data"),
    "state-change": ("updated", "changed", "saved", "deleted", "created", "submitted", "role changed", "password changed", "email changed", "state change"),
    "parser-behavior": ("parser", "doctype", "entity", "xml", "json", "deserialize", "syntax error", "parse error", "normalized", "validation"),
    "backend-fetch": ("backend fetch", "outbound fetch", "callback", "collaborator", "oast", "dns interaction", "http interaction", "server fetched"),
    "cache-variance": ("cache", "etag", "vary", "age", "stale", "cached", "cache-control"),
    "redirect-flow": ("redirect", "location", "oauth", "returnurl", "callback", "forwarded"),
    "timing-variance": ("timing", "latency", "delay", "seconds", " ms", "response time"),
}

_STATE_MACHINES = {
    "xss": {
        "family": "rendering-sink",
        "triage": {
            "goal": "Confirm the reflection or render sink without broadening payload complexity.",
            "preferred_evidence": ["Response delta showing the sink location.", "One benign marker tied to the render path."],
            "allowed_moves": ["Locate the exact rendering context.", "Keep the same sink and compare one bounded marker."],
            "blocked_moves": ["Privilege-impact claims without a shared or privileged viewer.", "Weaponized payload chaining."],
            "next_if_stalled": "Deprioritize the current sink-only branch and test whether the same content reaches a shared, admin, or support viewer path.",
        },
        "confirmation": {
            "goal": "Prove the exact sink context and whether another viewer can reach it.",
            "preferred_evidence": ["A stable context shift or render artifact.", "A note tying the sink to a viewer workflow."],
            "allowed_moves": ["Confirm shared or privileged render reach.", "Keep the proof benign and compare contexts only."],
            "blocked_moves": ["Severity promotion without cross-user or privileged reach.", "Session-targeted exploit payloads."],
            "next_if_stalled": "Move to the strongest alternate explanation: preview-only or self-view render with no cross-user impact.",
        },
        "impact": {
            "goal": "Tie the render path to a meaningful shared or privileged workflow.",
            "preferred_evidence": ["Shared-view or admin-view render artifact.", "One bounded impact statement tied to the workflow."],
            "allowed_moves": ["Document the highest-value viewer workflow.", "Capture the minimum report-ready evidence bundle."],
            "blocked_moves": ["General exploit chains.", "Claims beyond the observed viewer boundary."],
            "next_if_stalled": "Deprioritize the current XSS impact branch and compare access-control or workflow-trust alternatives on the same content path.",
        },
        "reporting": {
            "goal": "Assemble clean viewer-path evidence and bounded impact wording.",
            "preferred_evidence": ["Viewer role artifact.", "Report-ready statement tied to the render path."],
            "allowed_moves": ["Package the proof cleanly.", "Limit the claim to the observed viewer boundary."],
            "blocked_moves": ["New exploit branches.", "Broader impact claims without another viewer artifact."],
            "next_if_stalled": "If report wording is weak, step back to impact and collect one clearer shared-view artifact.",
        },
        "alternative_explanation": "The content is only reflected or previewed for the submitting user and does not cross into a shared or privileged viewer.",
        "alternative_class": "preview-only rendering",
        "rejection_markers": ("admin viewer", "shared viewer", "moderator", "privileged render", "cross-user render"),
    },
    "authorization": {
        "family": "object-boundary",
        "triage": {
            "goal": "Pin the object or action boundary before claiming broken authorization.",
            "preferred_evidence": ["Scanner issue anchor.", "One object or action identifier tied to the same route."],
            "allowed_moves": ["Keep the same route and compare one bounded identity variant.", "Confirm the object owner boundary."],
            "blocked_moves": ["Cross-tenant claims without a role-separated artifact.", "Bulk or destructive object changes."],
            "next_if_stalled": "Deprioritize the current object branch and test whether the issue is actually input-handling or viewer-trust noise on the same endpoint.",
        },
        "confirmation": {
            "goal": "Capture one clean role-separated or tenant-separated boundary failure.",
            "preferred_evidence": ["403/200 or redacted/full-object diff.", "Object ownership note."],
            "allowed_moves": ["Compare exactly one second identity or tenant.", "Keep the same object family."],
            "blocked_moves": ["Tenant-wide claims without a second bounded artifact.", "Privilege-change actions."],
            "next_if_stalled": "Move to the strongest alternate explanation: legitimate shared access, cached object reuse, or role-scoped visibility rather than broken authorization.",
        },
        "impact": {
            "goal": "Tie the boundary break to data exposure, privileged actions, or broader tenant impact.",
            "preferred_evidence": ["One bounded higher-value object or action.", "Business impact statement tied to the boundary break."],
            "allowed_moves": ["Check one adjacent privileged or broader-scope workflow.", "Capture one clean report artifact."],
            "blocked_moves": ["Claims about bulk or tenant-wide exposure without matching proof.", "Irreversible actions."],
            "next_if_stalled": "Deprioritize the current IDOR branch and test the next strongest route family or privilege boundary on the same object class.",
        },
        "reporting": {
            "goal": "Assemble clean role-separated artifacts and bounded impact wording.",
            "preferred_evidence": ["Role-separated diff.", "Observed data or action boundary impact."],
            "allowed_moves": ["Finalize the strongest observed boundary claim.", "Package only the proven scope."],
            "blocked_moves": ["Tenant-wide wording without proof.", "New object families."],
            "next_if_stalled": "Step back to impact and capture one stronger role-separated artifact.",
        },
        "alternative_explanation": "The observed difference is a legitimate role-scoped view, shared ownership case, or cache artifact rather than a broken authorization boundary.",
        "alternative_class": "legitimate role scope or cache artifact",
        "rejection_markers": ("role diff", "role-separated", "cross-tenant", "unauthorized", "other user's", "other tenant"),
    },
    "ssrf": {
        "family": "server-side-fetch",
        "triage": {
            "goal": "Confirm the application, not the client, is controlling an outbound fetch path.",
            "preferred_evidence": ["One bounded fetch observation.", "Exact parameter or sink note."],
            "allowed_moves": ["Keep to approved benign targets.", "Confirm fetch behavior without internal reach claims."],
            "blocked_moves": ["Internal reach claims without fetch evidence.", "Infrastructure pivoting."],
            "next_if_stalled": "Deprioritize the current SSRF branch and test whether the behavior is only URL reflection, redirect handling, or client-side fetch noise.",
        },
        "confirmation": {
            "goal": "Capture one benign outbound callback or stronger backend fetch artifact.",
            "preferred_evidence": ["Collaborator or callback signal.", "Stable fetch-linked response change."],
            "allowed_moves": ["Tie the callback to one exact request variant.", "Differentiate fetch from reflection."],
            "blocked_moves": ["Internal network or metadata claims without explicit proof.", "Broad target enumeration."],
            "next_if_stalled": "Move to the strongest alternate explanation: open redirect, reflection, or client-side fetch behavior.",
        },
        "impact": {
            "goal": "Show the strongest allowed trust-boundary implication of the fetch path.",
            "preferred_evidence": ["Internal reachability or stronger backend-control signal.", "Reportable fetch-path impact statement."],
            "allowed_moves": ["Document the exact trust boundary crossed.", "Keep escalation bounded to policy."],
            "blocked_moves": ["Metadata or internal network claims without approval or proof.", "Pivot chains."],
            "next_if_stalled": "Deprioritize the fetch branch and compare alternative trust issues such as redirect handling or parser-side URL logic.",
        },
        "reporting": {
            "goal": "Package the bounded fetch proof and exact trust-boundary statement.",
            "preferred_evidence": ["Fetch artifact.", "Observed trust-boundary implication."],
            "allowed_moves": ["Use the narrowest defensible wording.", "Tie the claim to the exact sink."],
            "blocked_moves": ["Broader internal reach claims without proof.", "New fetch targets."],
            "next_if_stalled": "Step back to impact and capture one stronger fetch-boundary artifact.",
        },
        "alternative_explanation": "The input only affects URL reflection, redirect handling, or client-side fetch behavior rather than a server-side outbound request.",
        "alternative_class": "reflection or redirect handling",
        "rejection_markers": ("callback", "dns interaction", "http interaction", "server fetched", "backend fetch"),
    },
    "authentication": {
        "family": "auth-boundary",
        "triage": {
            "goal": "Pin the exact auth boundary and expected baseline denial.",
            "preferred_evidence": ["Unauthenticated baseline.", "Expected auth boundary note."],
            "allowed_moves": ["Compare one authenticated and one unauthenticated state.", "Keep to one route family."],
            "blocked_moves": ["Privilege claims without a protected route artifact.", "Credential spraying or session churn."],
            "next_if_stalled": "Deprioritize the bypass branch and test whether the issue is just low-value route exposure or stale session noise.",
        },
        "confirmation": {
            "goal": "Show one stable protected route or workflow is reachable without the intended auth control.",
            "preferred_evidence": ["Protected route artifact.", "Role or session boundary note."],
            "allowed_moves": ["Confirm one protected action or data path.", "Keep the same route family."],
            "blocked_moves": ["Admin impact claims without a protected admin artifact.", "Broader account workflows."],
            "next_if_stalled": "Move to the strongest alternate explanation: stale session state, route misclassification, or weak caching rather than auth bypass.",
        },
        "impact": {
            "goal": "Tie the bypass to privileged actions, cross-user data, or stronger auth-boundary impact.",
            "preferred_evidence": ["Privileged route or workflow artifact.", "Business effect tied to the bypass."],
            "allowed_moves": ["Document one higher-value protected surface.", "Prepare bounded report wording."],
            "blocked_moves": ["Broader privilege narratives without matching proof.", "Destructive actions."],
            "next_if_stalled": "Deprioritize the current auth path and test whether the boundary issue is actually access-control or session-state drift on the same workflow.",
        },
        "reporting": {
            "goal": "Package the protected route proof and exact auth-boundary claim.",
            "preferred_evidence": ["Baseline denial vs bypassed access artifact.", "Observed privileged consequence."],
            "allowed_moves": ["Keep the report scoped to the proven route family.", "Limit the claim to the observed privilege boundary."],
            "blocked_moves": ["Critical wording without protected-route proof.", "New workflow families."],
            "next_if_stalled": "Step back to impact and capture one stronger protected-route artifact.",
        },
        "alternative_explanation": "The route is misclassified, cached, or weakly protected in a low-value way, but it does not demonstrate a real authentication boundary bypass.",
        "alternative_class": "route misclassification or session artifact",
        "rejection_markers": ("protected route", "admin", "privileged", "login required", "unauthenticated access"),
    },
    "race-condition": {
        "family": "concurrency-boundary",
        "triage": {
            "goal": "Confirm the behavior is concurrency-dependent rather than cache or eventual-consistency noise.",
            "preferred_evidence": ["Two bounded timing artifacts.", "One reversible affected workflow."],
            "allowed_moves": ["Keep the proof reversible and low-noise.", "Compare the same workflow under bounded concurrency."],
            "blocked_moves": ["Impact claims without repeatability.", "Destructive or high-volume races."],
            "next_if_stalled": "Deprioritize the race branch and test whether the signal is actually cache, retry, or state-propagation noise.",
        },
        "confirmation": {
            "goal": "Show one repeatable concurrency window on the same workflow.",
            "preferred_evidence": ["Timeline pair.", "Inconsistent but repeatable state artifact."],
            "allowed_moves": ["Repeat the same bounded concurrency test.", "Document the exact state assumption."],
            "blocked_moves": ["Financial or privilege claims without repeatability.", "Wider concurrency bursts."],
            "next_if_stalled": "Move to the strongest alternate explanation: cache inconsistency, async propagation delay, or retry noise.",
        },
        "impact": {
            "goal": "Tie the repeatable race to a meaningful business or privilege outcome.",
            "preferred_evidence": ["Observed business effect.", "Bounded repeatable race artifact."],
            "allowed_moves": ["Keep to one reversible workflow.", "Prepare the narrowest impact statement."],
            "blocked_moves": ["System-wide race claims.", "Irreversible financial or state damage."],
            "next_if_stalled": "Deprioritize the race branch and compare business-logic or cache-trust alternatives on the same flow.",
        },
        "reporting": {
            "goal": "Package the repeatable timing artifact and workflow effect cleanly.",
            "preferred_evidence": ["Timeline artifact.", "Observed state effect."],
            "allowed_moves": ["Describe the minimal concurrency needed.", "Limit the claim to the proven workflow."],
            "blocked_moves": ["Generalized race narratives without repeatability.", "Broader concurrency speculation."],
            "next_if_stalled": "Step back to impact and capture one clearer repeatability artifact.",
        },
        "alternative_explanation": "The observed inconsistency comes from cache behavior, async propagation, or retry noise rather than a true concurrency flaw.",
        "alternative_class": "cache or eventual-consistency noise",
        "rejection_markers": ("race", "concurrency", "simultaneous", "repeatable timing", "double-submit"),
    },
    "template-injection": {
        "family": "template-evaluation",
        "triage": {
            "goal": "Confirm template evaluation rather than plain reflection or stored text.",
            "preferred_evidence": ["One benign evaluation marker.", "Template sink note."],
            "allowed_moves": ["Keep evaluation markers benign.", "Confirm the exact rendering surface."],
            "blocked_moves": ["Execution claims.", "Server-control narratives without evaluation proof."],
            "next_if_stalled": "Deprioritize the template branch and test whether the signal is only reflection or preview rendering.",
        },
        "confirmation": {
            "goal": "Show one stable evaluation delta on the same template surface.",
            "preferred_evidence": ["Evaluation artifact.", "Template surface identity."],
            "allowed_moves": ["Keep to one surface.", "Differentiate evaluation from reflection."],
            "blocked_moves": ["Execution or file-access claims.", "Multiple template surfaces at once."],
            "next_if_stalled": "Move to the strongest alternate explanation: reflection-only or client-side rendering.",
        },
        "impact": {
            "goal": "Tie the evaluation sink to a privileged or higher-value rendering workflow.",
            "preferred_evidence": ["Privileged render path note.", "Bounded reportable template impact statement."],
            "allowed_moves": ["Document the trust boundary of the render path.", "Prepare bounded wording only."],
            "blocked_moves": ["Execution narratives.", "Backend-control claims without proof."],
            "next_if_stalled": "Deprioritize the template branch and compare XSS or rendering-trust alternatives on the same surface.",
        },
        "reporting": {
            "goal": "Package the benign evaluation proof and exact rendering boundary cleanly.",
            "preferred_evidence": ["Evaluation artifact.", "Observed privileged render path if any."],
            "allowed_moves": ["Keep the claim to evaluation and observed trust boundary.", "Avoid speculative backend control wording."],
            "blocked_moves": ["RCE framing.", "Broader server-control claims."],
            "next_if_stalled": "Step back to impact and capture one clearer evaluation artifact.",
        },
        "alternative_explanation": "The content is only reflected or rendered client-side and does not demonstrate server-side template evaluation.",
        "alternative_class": "reflection-only rendering",
        "rejection_markers": ("template evaluation", "evaluated", "server-side template", "expression resolved"),
    },
    "injection": {
        "family": "backend-injection",
        "triage": {
            "goal": "Confirm interpretation rather than reflection, validation noise, or parser quirks.",
            "preferred_evidence": ["One benign behavior-changing variant.", "Sink parameter note."],
            "allowed_moves": ["Change one variable at a time.", "Keep the test non-destructive."],
            "blocked_moves": ["Exploit chains.", "Destructive backend effects."],
            "next_if_stalled": "Deprioritize the current injection branch and compare access-control, parser, or rendering alternatives on the same route.",
        },
        "confirmation": {
            "goal": "Capture one stable interpreted-behavior delta on the same sink.",
            "preferred_evidence": ["Consistent response delta.", "Sink or parser behavior note."],
            "allowed_moves": ["Repeat the same bounded variant family.", "Differentiate interpretation from generic errors."],
            "blocked_moves": ["Data exfiltration or destructive payloads.", "Broader sink families at once."],
            "next_if_stalled": "Move to the strongest alternate explanation: generic validation error, parser noise, or reflection rather than backend interpretation.",
        },
        "impact": {
            "goal": "Tie the interpreted sink to a reportable data, auth, or workflow consequence.",
            "preferred_evidence": ["Observed trust-boundary consequence.", "Bounded impact statement."],
            "allowed_moves": ["Keep to the exact proven sink.", "Package one bounded impact path only."],
            "blocked_moves": ["Exploit framing.", "RCE or destructive narratives without explicit evidence."],
            "next_if_stalled": "Deprioritize the current injection path and compare authorization or parser-trust alternatives on the same endpoint.",
        },
        "reporting": {
            "goal": "Package the interpreted sink proof and exact bounded impact wording.",
            "preferred_evidence": ["Stable sink delta.", "Observed trust-boundary consequence."],
            "allowed_moves": ["Limit the wording to the proven sink and consequence.", "Avoid exploit-oriented framing."],
            "blocked_moves": ["Speculative database or execution claims.", "Broader chaining."],
            "next_if_stalled": "Step back to impact and capture one clearer interpreted-behavior artifact.",
        },
        "alternative_explanation": "The observed difference is a generic validation, parser, or reflection artifact rather than true backend interpretation.",
        "alternative_class": "parser or validation noise",
        "rejection_markers": ("query influence", "backend interpreted", "boolean diff", "time-based", "stable parser shift"),
    },
}


def build_investigation_intelligence(
        payload,
        *,
        rule_context: dict,
        prompt_sections: dict,
        provider_candidate: dict | None = None,
) -> dict[str, Any]:
    context_text = _combined_context_text(payload, prompt_sections)
    observed_signals = _observed_evidence_signals(payload, prompt_sections)
    evidence_score = round(sum(_EVIDENCE_WEIGHTS.get(item, 0.25) for item in observed_signals), 2)

    phase_state = build_investigation_phase_state(
        payload,
        rule_context=rule_context,
        prompt_sections=prompt_sections,
        provider_candidate=provider_candidate or {},
        context_text=context_text,
        observed_signals=observed_signals,
        evidence_score=evidence_score,
    )
    contradiction_assessment = detect_investigation_contradictions(
        payload,
        rule_context=rule_context,
        prompt_sections=prompt_sections,
        provider_candidate=provider_candidate or {},
        phase_state=phase_state,
        context_text=context_text,
        observed_signals=observed_signals,
        evidence_score=evidence_score,
    )
    evidence_sufficiency = assess_evidence_sufficiency(
        payload,
        rule_context=rule_context,
        prompt_sections=prompt_sections,
        provider_candidate=provider_candidate or {},
        phase_state=phase_state,
        contradiction_assessment=contradiction_assessment,
        observed_signals=observed_signals,
        evidence_score=evidence_score,
    )
    vulnerability_state_machine = build_vulnerability_state_machine(
        payload,
        rule_context=rule_context,
        prompt_sections=prompt_sections,
        provider_candidate=provider_candidate or {},
        phase_state=phase_state,
        contradiction_assessment=contradiction_assessment,
        evidence_sufficiency=evidence_sufficiency,
        observed_signals=observed_signals,
        context_text=context_text,
    )
    response_diff_semantics = build_response_diff_semantics(
        payload,
        rule_context=rule_context,
        prompt_sections=prompt_sections,
        vulnerability_state_machine=vulnerability_state_machine,
        context_text=context_text,
        observed_signals=observed_signals,
    )
    counter_hypothesis = build_counter_hypothesis(
        payload,
        rule_context=rule_context,
        prompt_sections=prompt_sections,
        provider_candidate=provider_candidate or {},
        phase_state=phase_state,
        contradiction_assessment=contradiction_assessment,
        evidence_sufficiency=evidence_sufficiency,
        vulnerability_state_machine=vulnerability_state_machine,
        context_text=context_text,
        observed_signals=observed_signals,
        evidence_score=evidence_score,
    )
    branch_guard = build_branch_guard(
        payload,
        rule_context=rule_context,
        prompt_sections=prompt_sections,
        provider_candidate=provider_candidate or {},
        phase_state=phase_state,
        contradiction_assessment=contradiction_assessment,
        evidence_sufficiency=evidence_sufficiency,
        vulnerability_state_machine=vulnerability_state_machine,
        counter_hypothesis=counter_hypothesis,
        context_text=context_text,
        observed_signals=observed_signals,
        evidence_score=evidence_score,
    )
    confidence_calibration = build_confidence_calibration(
        payload,
        rule_context=rule_context,
        provider_candidate=provider_candidate or {},
        phase_state=phase_state,
        evidence_sufficiency=evidence_sufficiency,
        vulnerability_state_machine=vulnerability_state_machine,
    )
    cross_issue_cluster = build_cross_issue_cluster(
        payload,
        vulnerability_state_machine=vulnerability_state_machine,
        response_diff_semantics=response_diff_semantics,
    )
    impact_path_ranking = build_impact_path_ranking(
        payload,
        rule_context=rule_context,
        phase_state=phase_state,
        evidence_sufficiency=evidence_sufficiency,
        vulnerability_state_machine=vulnerability_state_machine,
        response_diff_semantics=response_diff_semantics,
        confidence_calibration=confidence_calibration,
        cross_issue_cluster=cross_issue_cluster,
    )
    report_bundle = build_report_bundle(
        payload,
        phase_state=phase_state,
        evidence_sufficiency=evidence_sufficiency,
        branch_guard=branch_guard,
        vulnerability_state_machine=vulnerability_state_machine,
        counter_hypothesis=counter_hypothesis,
        response_diff_semantics=response_diff_semantics,
        confidence_calibration=confidence_calibration,
        cross_issue_cluster=cross_issue_cluster,
        impact_path_ranking=impact_path_ranking,
    )
    return {
        "phase_state": phase_state,
        "contradiction_assessment": contradiction_assessment,
        "evidence_sufficiency": evidence_sufficiency,
        "branch_guard": branch_guard,
        "vulnerability_state_machine": vulnerability_state_machine,
        "counter_hypothesis": counter_hypothesis,
        "confidence_calibration": confidence_calibration,
        "cross_issue_cluster": cross_issue_cluster,
        "response_diff_semantics": response_diff_semantics,
        "impact_path_ranking": impact_path_ranking,
        "report_bundle": report_bundle,
    }


def build_investigation_phase_state(
        payload,
        *,
        rule_context: dict,
        prompt_sections: dict,
        provider_candidate: dict,
        context_text: str,
        observed_signals: list[str],
        evidence_score: float,
) -> dict[str, Any]:
    desired_phase = _desired_phase(context_text)
    supported_phase = _max_supported_phase(payload, observed_signals, evidence_score, context_text)
    phase = _lower_phase(desired_phase, supported_phase)
    desired_rank = _PHASE_ORDER[desired_phase]
    supported_rank = _PHASE_ORDER[supported_phase]

    signals = _phase_signals(context_text, observed_signals)
    blockers: list[str] = []
    if desired_rank > supported_rank:
        blockers.append(
            f"The investigation intent points to `{desired_phase}`, but the current evidence only supports `{supported_phase}`."
        )
    if phase == "triage":
        blockers.append("No bounded observed signal is attached yet.")
    elif phase == "confirmation" and evidence_score < 1.6:
        blockers.append("A stronger observed artifact is still missing before impact-focused escalation.")
    elif phase == "impact" and evidence_score < 3.0:
        blockers.append("A cleaner report artifact is still missing before report-ready wording.")

    rationale = _phase_rationale(
        phase,
        desired_phase=desired_phase,
        supported_phase=supported_phase,
        signals=signals,
    )
    next_gate = _next_gate_for_phase(
        phase,
        vuln_class=_infer_vuln_class(provider_candidate, rule_context, payload=payload, prompt_sections=prompt_sections),
        supported_phase=supported_phase,
    )
    confidence = round(
        min(0.96, 0.42 + (0.08 * len(signals)) + (0.12 * min(3.0, evidence_score) / 3.0)),
        2,
    )
    return {
        "phase": phase,
        "desired_phase": desired_phase,
        "max_supported_phase": supported_phase,
        "confidence": confidence,
        "rationale": rationale,
        "signals": signals[:8],
        "blockers": blockers[:4],
        "next_gate": next_gate,
    }


def detect_investigation_contradictions(
        payload,
        *,
        rule_context: dict,
        prompt_sections: dict,
        provider_candidate: dict,
        phase_state: dict,
        context_text: str,
        observed_signals: list[str],
        evidence_score: float,
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    desired_phase = phase_state.get("desired_phase", "triage")
    supported_phase = phase_state.get("max_supported_phase", "triage")
    if _PHASE_ORDER[desired_phase] > _PHASE_ORDER[supported_phase]:
        items.append(
            {
                "code": "phase-ahead-of-evidence",
                "severity": "high" if desired_phase == "reporting" else "medium",
                "summary": (
                    f"The current follow-up is pushing toward `{desired_phase}`, but the attached evidence only supports `{supported_phase}`."
                ),
                "evidence": [phase_state.get("rationale", "")],
                "recommended_adjustment": phase_state.get("next_gate", ""),
            }
        )

    negative_present = _contains_any(context_text, _NEGATIVE_MARKERS)
    positive_present = _contains_any(context_text, _POSITIVE_MARKERS)
    strong_new_signal = any(
        signal in observed_signals
        for signal in ("response-delta", "logger-evidence", "collaborator-evidence", "evidence-timeline")
    )
    if negative_present and not strong_new_signal:
        items.append(
            {
                "code": "dead-end-without-new-signal",
                "severity": "medium",
                "summary": "Prior notes suggest a dead end or no signal, but no new observed artifact is attached to justify continuing the same branch.",
                "evidence": ["The workflow history includes dead-end markers and no fresh observed signal is present."],
                "recommended_adjustment": "Change one bounded variable and capture a new delta before continuing this escalation branch.",
            }
        )

    if negative_present and positive_present:
        items.append(
            {
                "code": "mixed-history-signal",
                "severity": "medium",
                "summary": "The investigation history contains both positive and negative resolution markers for the same branch.",
                "evidence": ["The saved notes include both confirmation-style and dead-end-style markers."],
                "recommended_adjustment": "Ask for one narrow clarification or capture one cleaner comparison before escalating the claim.",
            }
        )

    planner = provider_candidate.get("planner") if isinstance(provider_candidate, dict) else {}
    planner_confidence = _planner_confidence(planner)
    if planner_confidence >= 0.85 and evidence_score < 1.6:
        items.append(
            {
                "code": "confidence-outpaces-evidence",
                "severity": "medium",
                "summary": "Model confidence is high relative to the currently attached observed evidence.",
                "evidence": [
                    f"Planner confidence is {planner_confidence:.2f}, while the evidence score is only {evidence_score:.2f}.",
                ],
                "recommended_adjustment": "Keep the next step in confirmation mode until one cleaner observed artifact is attached.",
            }
        )

    highest = _highest_severity(items)
    count = len(items)

    # ORIGINAL SAFETY NET: Contradiction Status Flags
    # status = "clear"
    # if count:
    #     status = "watch" if highest == "low" else "contradictions-present"
    # summary = "No material contradictions were detected."
    # if items:
    #     summary = items[0]["summary"] if len(items) == 1 else f"{count} contradiction signals were detected."

    raw_status = "clear"
    if count:
        raw_status = "watch" if highest == "low" else "contradictions-present"
    effective_status = "clear"
    override_applied = raw_status != effective_status
    override_reason = ""
    if override_applied:
        override_reason = "Permissive contradiction override keeps escalation unblocked while preserving the raw contradiction signals."
    summary = "No material contradictions were detected."
    if items:
        summary = items[0]["summary"] if len(items) == 1 else f"{count} contradiction signals were detected."

    return {
        "status": raw_status,
        "raw_status": raw_status,
        "effective_status": effective_status,
        "override_applied": override_applied,
        "override_reason": override_reason,
        "highest_severity": highest,
        "count": count,
        "summary": summary,
        "items": items[:4],
    }


def assess_evidence_sufficiency(
        payload,
        *,
        rule_context: dict,
        prompt_sections: dict,
        provider_candidate: dict,
        phase_state: dict,
        contradiction_assessment: dict,
        observed_signals: list[str],
        evidence_score: float,
) -> dict[str, Any]:
    vuln_class = _infer_vuln_class(provider_candidate, rule_context, payload=payload, prompt_sections=prompt_sections)
    contradiction_count = int(contradiction_assessment.get("count", 0) or 0)
    contradiction_items = list(contradiction_assessment.get("items") or [])
    contradiction_block = contradiction_assessment.get("highest_severity") == "high" or any(
        str(item.get("code") or "").strip() == "dead-end-without-new-signal"
        for item in contradiction_items
    )
    supported_phase = phase_state.get("max_supported_phase", "triage")

    validation_status = "confirmed" if _PHASE_ORDER[supported_phase] >= _PHASE_ORDER["impact"] else "needs-confirmation"
    planner = build_impact_upgrade_planner(
        vuln_class,
        validation={"validation_status": validation_status},
        impact={
            "reportable": _PHASE_ORDER[supported_phase] >= _PHASE_ORDER["reporting"],
            "reportability": "high" if _PHASE_ORDER[supported_phase] >= _PHASE_ORDER["reporting"] else "medium",
            "confirmation_state": validation_status,
        },
    )

    missing_evidence: list[str] = []
    if "response-delta" not in observed_signals and "logger-evidence" not in observed_signals:
        missing_evidence.append("Capture one clean baseline-vs-variant response delta.")
    if not any(signal in observed_signals for signal in ("logger-evidence", "collaborator-evidence", "evidence-timeline")):
        missing_evidence.append("Add one second corroborating evidence source such as Logger++, Collaborator, or a short evidence timeline.")
    if contradiction_count:
        missing_evidence.append("Resolve the current contradiction signals before making a stronger claim.")

    missing_artifacts: list[str] = []
    planner_missing = str(planner.get("missing_artifact_for_upgrade") or "").strip()
    if planner_missing and _PHASE_ORDER[supported_phase] < _PHASE_ORDER["reporting"]:
        missing_artifacts.append(planner_missing)

    # ORIGINAL SAFETY NET: Contradiction Blocking
    # if contradiction_block:
    #     status = "blocked"
    # elif evidence_score >= 3.0 and contradiction_count == 0:
    #     status = "report-ready"
    # elif evidence_score >= 2.0 and contradiction_count <= 1:
    #     status = "impact-ready"
    # elif evidence_score >= 0.9:
    #     status = "confirmation-ready"
    # elif evidence_score > 0.0:
    #     status = "partial"
    # else:
    #     status = "insufficient"

    raw_status = "insufficient"
    if contradiction_block:
        raw_status = "blocked"
    elif evidence_score >= 3.0 and contradiction_count == 0:
        raw_status = "report-ready"
    elif evidence_score >= 2.0 and contradiction_count <= 1:
        raw_status = "impact-ready"
    elif evidence_score >= 0.9:
        raw_status = "confirmation-ready"
    elif evidence_score > 0.0:
        raw_status = "partial"

    effective_status = "insufficient"
    if evidence_score >= 2.0:
        effective_status = "report-ready"
    elif evidence_score >= 1.0:
        effective_status = "impact-ready"
    elif evidence_score >= 0.5:
        effective_status = "confirmation-ready"
    elif evidence_score > 0.0:
        effective_status = "partial"

    raw_ready_for_phase = {
        "blocked": phase_state.get("phase", "confirmation"),
        "report-ready": "reporting",
        "impact-ready": "impact",
        "confirmation-ready": "confirmation",
        "partial": "confirmation",
        "insufficient": "triage",
    }[raw_status]
    effective_ready_for_phase = {
        "blocked": phase_state.get("phase", "confirmation"),
        "report-ready": "reporting",
        "impact-ready": "impact",
        "confirmation-ready": "confirmation",
        "partial": "confirmation",
        "insufficient": "triage",
    }[effective_status]
    score = round(min(1.0, evidence_score / 3.5), 3)
    next_best_gate = phase_state.get("next_gate", "")
    if effective_status in {"impact-ready", "report-ready"}:
        next_best_gate = str(planner.get("next_strongest_allowed_step") or next_best_gate)
    rationale = _sufficiency_rationale(raw_status, raw_ready_for_phase, evidence_score, contradiction_assessment)
    override_applied = raw_status != effective_status or raw_ready_for_phase != effective_ready_for_phase
    override_reason = ""
    if override_applied:
        override_reason = "Permissive evidence override keeps escalation moving even when the raw sufficiency state is weaker or blocked."
    return {
        "status": raw_status,
        "raw_status": raw_status,
        "effective_status": effective_status,
        "ready_for_phase": raw_ready_for_phase,
        "raw_ready_for_phase": raw_ready_for_phase,
        "effective_ready_for_phase": effective_ready_for_phase,
        "override_applied": override_applied,
        "override_reason": override_reason,
        "score": score,
        "evidence_score": evidence_score,
        "confirmed_signals": [_signal_label(item) for item in observed_signals[:6]],
        "missing_evidence": missing_evidence[:4],
        "missing_artifacts": missing_artifacts[:3],
        "next_best_gate": next_best_gate,
        "rationale": rationale,
    }


def build_confidence_calibration(
        payload,
        *,
        rule_context: dict,
        provider_candidate: dict,
        phase_state: dict,
        evidence_sufficiency: dict,
        vulnerability_state_machine: dict,
) -> dict[str, Any]:
    vuln_class = _normalize_vuln_class(str(vulnerability_state_machine.get("vuln_class") or _infer_vuln_class(provider_candidate, rule_context)))
    partition_key = partition_from_payload(payload)
    review_examples = query_review_examples(vuln_classes=[vuln_class], partition_key=partition_key, limit=5)
    negative_reasoning = summarize_negative_reasoning(payload_like=payload, vuln_classes=[vuln_class], limit=5)
    repeater_learning = summarize_repeater_learning(payload_like=payload, vuln_classes=[vuln_class], limit=5)

    outcome_counts = {"positive": 0, "review_only": 0, "fallback": 0}
    for item in list(review_examples.get("items") or []):
        label = str(item.get("outcome_label") or "").strip().lower()
        if label in _POSITIVE_OUTCOME_LABELS:
            outcome_counts["positive"] += 1
        elif label == "fallback-review":
            outcome_counts["fallback"] += 1
        else:
            outcome_counts["review_only"] += 1

    base_confidence = _planner_confidence(provider_candidate.get("planner") if isinstance(provider_candidate, dict) else {})
    if not base_confidence:
        try:
            base_confidence = float(phase_state.get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            base_confidence = 0.0

    adjustment = 0.0
    adjustment += min(0.18, outcome_counts["positive"] * 0.06)
    adjustment -= min(0.15, int(negative_reasoning.get("count", 0) or 0) * 0.05)
    adjustment -= min(0.09, outcome_counts["fallback"] * 0.03)
    if _effective_status(evidence_sufficiency) == "blocked":
        adjustment -= 0.06

    preferred_families = list(repeater_learning.get("preferred_families") or [])
    deprioritized_families = list(repeater_learning.get("deprioritized_families") or [])
    success_rates = dict(repeater_learning.get("success_rates") or {})
    if preferred_families:
        adjustment += 0.04
    if deprioritized_families:
        adjustment -= 0.03

    calibrated_confidence = round(max(0.05, min(0.99, base_confidence + adjustment)), 2)
    if calibrated_confidence > base_confidence + 0.05:
        status = "boosted"
    elif calibrated_confidence < base_confidence - 0.05:
        status = "dampened"
    else:
        status = "neutral"

    step_ordering_bias = "No strong historical ordering bias was derived."
    if preferred_families and deprioritized_families:
        step_ordering_bias = (
            f"Prioritize `{preferred_families[0]}`-style follow-ups first and deprioritize `{deprioritized_families[0]}` because prior local outcomes were weaker."
        )
    elif preferred_families:
        step_ordering_bias = f"Prioritize `{preferred_families[0]}`-style follow-ups first because that family produced stronger prior local outcomes."
    elif deprioritized_families:
        step_ordering_bias = f"Deprioritize `{deprioritized_families[0]}`-style follow-ups because prior local outcomes were weak or low-value."

    summary = (
        f"Historical calibration for `{vuln_class}` moved confidence from {base_confidence:.2f} to {calibrated_confidence:.2f}."
    )
    return {
        "status": status,
        "base_confidence": round(base_confidence, 2),
        "calibrated_confidence": calibrated_confidence,
        "adjustment": round(adjustment, 2),
        "positive_history_count": outcome_counts["positive"],
        "review_history_count": outcome_counts["review_only"],
        "fallback_history_count": outcome_counts["fallback"],
        "negative_history_count": int(negative_reasoning.get("count", 0) or 0),
        "preferred_mutation_families": preferred_families[:4],
        "deprioritized_mutation_families": deprioritized_families[:4],
        "family_success_rates": {key: value for key, value in list(success_rates.items())[:4]},
        "step_ordering_bias": step_ordering_bias,
        "summary": summary,
    }


def build_cross_issue_cluster(
        payload,
        *,
        vulnerability_state_machine: dict,
        response_diff_semantics: dict,
) -> dict[str, Any]:
    dashboard_issue = get_dashboard_issue_context(payload)
    related_issues = get_related_dashboard_issue_contexts(payload, limit=5)
    anchor_hint = _normalize_vuln_class(
        str(
            dashboard_issue.get("vuln_hint")
            or vulnerability_state_machine.get("vuln_class")
            or ""
        ).strip().lower()
    )
    anchor_path_family = _path_family(
        str((dashboard_issue or {}).get("path") or urlparse(str(getattr(payload, "target_url", "") or "")).path or "/")
    )
    if anchor_hint != "general":
        compatible_classes = _compatible_cluster_classes(anchor_hint)
        same_family_related = [
            item for item in related_issues
            if _normalize_vuln_class(str(item.get("vuln_hint") or "").strip().lower()) in compatible_classes
        ]
        if same_family_related:
            related_issues = same_family_related
    same_path_related = [
        item for item in related_issues
        if _path_family(str(item.get("path") or urlparse(str(item.get("target_url") or "")).path or "/")) == anchor_path_family
    ]
    if same_path_related:
        related_issues = same_path_related
    issues = [item for item in [dashboard_issue, *related_issues] if item.get("found")]
    if len(issues) <= 1:
        host = str((dashboard_issue or {}).get("host") or _parsed_target_host(payload))
        return {
            "status": "isolated",
            "cluster_id": f"{host}|isolated",
            "host": host,
            "shared_path_family": _path_family(str((dashboard_issue or {}).get("path") or urlparse(str(getattr(payload, 'target_url', '') or '')).path or "/")),
            "shared_parameter_family": "",
            "issue_count": len(issues),
            "issue_names": [str((dashboard_issue or {}).get("issue_name") or "").strip()] if dashboard_issue.get("found") else [],
            "merged_vuln_classes": [str(vulnerability_state_machine.get("vuln_class") or "general")],
            "supporting_issue_names": [],
            "joined_impact_hints": [],
            "strategy": "No scanner-issue cluster is active; keep the investigation anchored to the primary finding.",
            "summary": "No related Burp scanner issue cluster was derived.",
        }

    host = str(dashboard_issue.get("host") or _parsed_target_host(payload))
    path_families = [_path_family(str(item.get("path") or urlparse(str(item.get("target_url") or "")).path or "/")) for item in issues]
    shared_path_family = _most_common_nonempty(path_families)
    param_candidates = []
    for item in issues:
        candidate_urls = [str(item.get("target_url") or "").strip(), *[str(url).strip() for url in list(item.get("affected_urls") or [])[:3]]]
        for url in candidate_urls:
            if not url:
                continue
            param_candidates.extend(_query_param_names(url))
    shared_parameter_family = _most_common_nonempty(param_candidates)
    merged_vuln_classes = list(dict.fromkeys(
        str(item.get("vuln_hint") or "").strip().lower()
        for item in issues
        if str(item.get("vuln_hint") or "").strip()
    )) or [str(vulnerability_state_machine.get("vuln_class") or "general")]
    issue_names = [str(item.get("issue_name") or "").strip() for item in issues if str(item.get("issue_name") or "").strip()]
    supporting_issue_names = issue_names[1:]

    same_path_cluster = sum(1 for family in path_families if family and family == shared_path_family) >= 2
    same_param_cluster = bool(shared_parameter_family) and param_candidates.count(shared_parameter_family) >= 2
    if same_path_cluster:
        status = "clustered"
        cluster_basis = "path-family"
    elif same_param_cluster:
        status = "clustered"
        cluster_basis = "parameter-family"
    else:
        status = "related"
        cluster_basis = "host-family"

    strategy = "Treat the primary scanner finding and the sibling scanner issues as one evolving case model."
    if same_path_cluster:
        strategy += " Keep confirmation anchored to the shared request family, then use the sibling issues as escalation rails."
    elif same_param_cluster:
        strategy += " Keep one parameter family fixed while the sibling findings supply alternate hypotheses."
    else:
        strategy += " Use the siblings as supporting context, but keep one request family active at a time."
    if "auth-boundary" in list(response_diff_semantics.get("semantics") or []):
        strategy += " The current response delta already looks like a boundary shift, so prioritize sibling issues on the same path family first."
    joined_impact_hints = _joined_impact_hints(
        anchor_class=anchor_hint or str(vulnerability_state_machine.get("vuln_class") or "general"),
        merged_classes=merged_vuln_classes,
        same_path_cluster=same_path_cluster,
        same_param_cluster=same_param_cluster,
        primary_semantic=str(response_diff_semantics.get("primary_semantic") or ""),
    )

    cluster_anchor = shared_path_family or shared_parameter_family or "mixed"
    return {
        "status": status,
        "cluster_id": f"{host}|{cluster_basis}|{cluster_anchor}",
        "host": host,
        "shared_path_family": shared_path_family,
        "shared_parameter_family": shared_parameter_family,
        "issue_count": len(issues),
        "issue_names": issue_names[:6],
        "merged_vuln_classes": merged_vuln_classes[:6],
        "supporting_issue_names": supporting_issue_names[:5],
        "joined_impact_hints": joined_impact_hints[:4],
        "strategy": strategy,
        "summary": f"Burp surfaced {len(issues)} related scanner issue(s) on `{host}` with a shared {cluster_basis.replace('-', ' ')}.",
    }


def build_response_diff_semantics(
        payload,
        *,
        rule_context: dict,
        prompt_sections: dict,
        vulnerability_state_machine: dict,
        context_text: str,
        observed_signals: list[str],
) -> dict[str, Any]:
    delta_text = " ".join(
        item for item in [
            str(getattr(payload, "response_delta_text", "") or "").strip(),
            str(getattr(payload, "logger_evidence_text", "") or "").strip(),
            str(prompt_sections.get("response_delta_summary", "") or "").strip(),
            str(prompt_sections.get("logger_evidence_summary", "") or "").strip(),
            str(prompt_sections.get("evidence_timeline_summary", "") or "").strip(),
        ]
        if item
    ).lower()
    status_transitions = re.findall(r"(\d{3})\s*(?:->|to)\s*(\d{3})", delta_text)
    scores = {name: 0.0 for name in _RESPONSE_SEMANTIC_KEYWORDS}

    for name, markers in _RESPONSE_SEMANTIC_KEYWORDS.items():
        for marker in markers:
            if marker in delta_text:
                scores[name] += 0.55

    if any({left, right} & {"401", "403"} and right.startswith("2") for left, right in status_transitions):
        scores["auth-boundary"] += 1.85
    if vulnerability_state_machine.get("vuln_class") in {"authorization", "authentication"} and status_transitions:
        scores["auth-boundary"] += 0.2
    if any(token in delta_text for token in ("attribute context", "script context", "encoded", "rendered")):
        scores["sink-context-shift"] += 1.1
    if any(token in delta_text for token in ("full object", "fields visible", "data visible", "exposed profile", "invoice fields")):
        scores["data-exposure"] += 1.0
    if any(token in delta_text for token in ("saved", "updated", "deleted", "created", "state change")):
        scores["state-change"] += 1.0
    if any(token in delta_text for token in ("parser", "doctype", "entity", "deserial", "parse error")):
        scores["parser-behavior"] += 1.0
    if any(token in delta_text for token in ("backend fetch", "outbound fetch", "callback", "collaborator", "oast", "server fetched")):
        scores["backend-fetch"] += 1.1
    if any(token in delta_text for token in ("cache", "etag", "vary", "stale", "cached")):
        scores["cache-variance"] += 1.0

    if ("response-delta" in observed_signals or "logger-evidence" in observed_signals) and not any(value > 0.0 for value in scores.values()):
        scores["generic-structural"] = 0.75
    elif any(token in delta_text for token in ("length changed", "bytes", "header change", "response length")):
        scores["generic-structural"] = max(scores.get("generic-structural", 0.0), 0.7)

    ranked = [name for name, score in sorted(scores.items(), key=lambda item: item[1], reverse=True) if score >= 0.7]
    primary_semantic = ranked[0] if ranked else ("generic-structural" if delta_text else "not-classified")
    if (
            vulnerability_state_machine.get("vuln_class") in {"authorization", "authentication"}
            and any({left, right} & {"401", "403"} and right.startswith("2") for left, right in status_transitions)
    ):
        primary_semantic = "auth-boundary"
        ranked = ["auth-boundary", *[item for item in ranked if item != "auth-boundary"]]
    recommended_focus = {
        "auth-boundary": "Capture the exact role-, tenant-, or session-separated baseline and variant with the same route and object.",
        "sink-context-shift": "Capture the exact render context and the viewer workflow that can reach it.",
        "data-exposure": "Record which fields or objects became visible and whether the exposure crosses a user, tenant, or trust boundary.",
        "state-change": "Capture the before/after workflow state and one reversible business effect.",
        "parser-behavior": "Keep the same input family and compare one structural parser variation at a time.",
        "backend-fetch": "Capture the exact callback or fetch artifact and keep the next proof on the same bounded fetch path.",
        "cache-variance": "Keep the route fixed and compare cache-control, vary, etag, age, and authenticated visibility.",
        "redirect-flow": "Capture the redirect target, trust boundary, and whether the flow affects tokens or privileged navigation.",
        "timing-variance": "Repeat the same bounded request and capture timing consistency before escalating.",
        "generic-structural": "Capture one cleaner baseline-vs-variant diff so the next step is driven by a specific semantic change rather than a generic delta.",
        "not-classified": "No response-diff semantics were derived yet; attach one concrete baseline-vs-variant note first.",
    }[primary_semantic]
    evidence_markers = [f"{left}->{right}" for left, right in status_transitions[:3]]
    if "length changed" in delta_text or "response length" in delta_text:
        evidence_markers.append("body-length-delta")
    if any(token in delta_text for token in ("attribute context", "script context")):
        evidence_markers.append("sink-context-shift")
    if any(token in delta_text for token in ("backend fetch", "callback", "collaborator", "oast")):
        evidence_markers.append("backend-fetch")
    if any(token in delta_text for token in ("cache", "etag", "vary")):
        evidence_markers.append("cache-behavior")
    if any(token in delta_text for token in ("parser", "doctype", "entity")):
        evidence_markers.append("parser-behavior")

    if not ranked and vulnerability_state_machine.get("vuln_class") in {"authorization", "authentication"} and status_transitions:
        ranked = ["auth-boundary"]
        primary_semantic = "auth-boundary"

    summary = (
        f"Primary response-diff semantic: `{primary_semantic}`."
        if primary_semantic != "not-classified"
        else "No specific response-diff semantic was derived from the attached notes."
    )
    return {
        "primary_semantic": primary_semantic,
        "semantics": ranked[:5],
        "status_transitions": [f"{left}->{right}" for left, right in status_transitions[:3]],
        "evidence_markers": list(dict.fromkeys(evidence_markers))[:5],
        "recommended_comparison_focus": recommended_focus,
        "summary": summary,
    }


def build_impact_path_ranking(
        payload,
        *,
        rule_context: dict,
        phase_state: dict,
        evidence_sufficiency: dict,
        vulnerability_state_machine: dict,
        response_diff_semantics: dict,
        confidence_calibration: dict,
        cross_issue_cluster: dict,
) -> dict[str, Any]:
    vuln_class = _normalize_vuln_class(str(vulnerability_state_machine.get("vuln_class") or "general"))
    cluster_paths = list((cross_issue_cluster.get("joined_impact_hints") or [])[:4])
    raw_paths = list((((rule_context or {}).get("aggregate") or {}).get("impact_paths") or []))
    planner = build_impact_upgrade_planner(
        vuln_class,
        validation={"validation_status": "confirmed" if phase_state.get("phase") in {"impact", "reporting"} else "needs-confirmation"},
        impact={"reportable": _effective_status(evidence_sufficiency) == "report-ready"},
    )
    planner_paths = list(planner.get("impact_ladder") or [])
    matching_paths = [path for path in raw_paths if _impact_path_matches_vuln_class(path, vuln_class)]
    if raw_paths and matching_paths:
        raw_paths = list(dict.fromkeys(matching_paths))
    elif raw_paths and vuln_class != "general":
        raw_paths = planner_paths or raw_paths
    elif not raw_paths:
        raw_paths = planner_paths
    raw_paths = list(dict.fromkeys([*raw_paths, *cluster_paths]))

    target_type = _infer_target_type(payload, vulnerability_state_machine, response_diff_semantics)
    policy_context = build_program_policy_context(payload)
    policy_gate = assess_high_risk_escalation_policy(payload, requested_classes=[vuln_class])
    calibrated_confidence = float(confidence_calibration.get("calibrated_confidence", 0.0) or 0.0)
    current_phase = str(phase_state.get("phase") or "confirmation")
    primary_semantic = str(response_diff_semantics.get("primary_semantic") or "")

    ranked_paths = []
    for path in raw_paths[:8]:
        lowered = str(path or "").strip().lower()
        if not lowered:
            continue
        score = 0.42
        reasons: list[str] = []

        # ORIGINAL SAFETY NET: Program Policy Gating
        # if policy_gate.get("applies") and not policy_gate.get("allowed") and _policy_sensitive_path(lowered, vuln_class):
        #     score -= 0.3
        #     gated = True
        #     reasons.append(policy_gate.get("reason") or "Program policy currently gates the strongest high-risk escalation path.")

        raw_gated = (
            bool(policy_gate.get("applies"))
            and not bool(policy_gate.get("allowed", True))
            and _policy_sensitive_path(lowered, vuln_class)
        )
        gated = False
        override_applied = raw_gated != gated
        override_reason = ""
        if override_applied:
            override_reason = "Permissive policy override keeps the path available while preserving the raw gate metadata."
        if raw_gated:
            reasons.append(policy_gate.get("reason") or "Program policy currently gates the strongest high-risk escalation path.")

        reward_alignment = _impact_path_reward_alignment(lowered, vuln_class, target_type, primary_semantic)
        score += reward_alignment
        if reward_alignment > 0.18:
            reasons.append("The path aligns with the issue family, target type, and current response semantics.")

        if cross_issue_cluster.get("status") == "clustered":
            score += 0.08
            reasons.append("Sibling Burp scanner issues suggest the same request family has a broader evolving case model.")
        if str(path).strip() in cluster_paths:
            score += 0.03
            reasons.append("This path is reinforced by compatible sibling Burp findings on the same evolving case.")

        if current_phase in {"triage", "confirmation"} and _is_bold_impact_path(lowered):
            score -= 0.12
            reasons.append("The current investigation phase is still below strong impact proof, so this path stays slightly deprioritized.")

        if calibrated_confidence < 0.55 and _is_bold_impact_path(lowered):
            score -= 0.08
            reasons.append("Historical confidence calibration is still conservative, so weaker high-impact branches stay lower in the order.")

        platform = str(policy_context.get("name") or "generic")
        if platform == "bugcrowd" and any(token in lowered for token in ("cross-tenant", "privilege", "state change", "secret")):
            score += 0.08
            reasons.append("The path lines up with reward-relevant, triage-friendly impact language.")
        elif platform == "intigriti" and any(token in lowered for token in ("privilege", "cross-user", "sensitive data", "workflow")):
            score += 0.06
            reasons.append("The path matches concise business-impact framing.")
        elif platform == "hackerone" and any(token in lowered for token in ("boundary", "unauthorized", "admin", "workflow")):
            score += 0.06
            reasons.append("The path fits explicit boundary-breach reporting language.")

        ranked_paths.append({
            "path": str(path).strip(),
            "score": round(max(0.0, min(1.0, score)), 3),
            "gated": gated,
            "raw_gated": raw_gated,
            "effective_gated": gated,
            "override_applied": override_applied,
            "override_reason": override_reason,
            "reasons": reasons[:4],
        })

    ranked_paths.sort(key=lambda item: (item["gated"], -item["score"], item["path"]))
    top_path = next((item["path"] for item in ranked_paths if not item.get("gated")), "") or (ranked_paths[0]["path"] if ranked_paths else "")
    effective_sufficiency_status = _effective_status(evidence_sufficiency)
    impact = {
        "reportable": effective_sufficiency_status == "report-ready",
        "reportability": "high" if effective_sufficiency_status in {"impact-ready", "report-ready"} else "medium",
        "business_impact_class": "high-impact" if _is_bold_impact_path(str(top_path).lower()) else "security-impact",
        "confirmation_state": "confirmed" if phase_state.get("phase") in {"impact", "reporting"} else "needs-confirmation",
    }
    submission_value = build_submission_value_score(
        validation={
            "validation_status": impact["confirmation_state"],
            "evidence_score": evidence_sufficiency.get("evidence_score", 0.0),
        },
        impact=impact,
        severity={"severity": "high" if _is_bold_impact_path(str(top_path).lower()) else "medium"},
        policy_gate=policy_gate,
        platform=str(policy_context.get("name") or "generic"),
    )
    summary = (
        f"Program-aware ranking selected `{top_path}` as the top reward-relevant path."
        if top_path
        else "No program-aware impact path ranking was derived."
    )
    return {
        "status": "ranked" if ranked_paths else "none",
        "platform": str(policy_context.get("name") or "generic"),
        "target_type": target_type,
        "top_path": top_path,
        "ranked_paths": ranked_paths[:6],
        "ranked_path_texts": [item["path"] for item in ranked_paths[:6]],
        "gated_paths": [item["path"] for item in ranked_paths if item.get("raw_gated")][:4],
        "submission_value_score": float(submission_value.get("score", 0.0) or 0.0),
        "summary": summary,
    }


def build_report_bundle(
        payload,
        *,
        phase_state: dict,
        evidence_sufficiency: dict,
        branch_guard: dict,
        vulnerability_state_machine: dict,
        counter_hypothesis: dict,
        response_diff_semantics: dict,
        confidence_calibration: dict,
        cross_issue_cluster: dict,
        impact_path_ranking: dict,
) -> dict[str, Any]:
    dashboard_issue = get_dashboard_issue_context(payload)
    platform = str((build_program_policy_context(payload) or {}).get("name") or "generic")
    vuln_class = _normalize_vuln_class(str(vulnerability_state_machine.get("vuln_class") or "general"))
    joined_paths = {
        str(item).strip()
        for item in (cross_issue_cluster.get("joined_impact_hints") or [])
        if str(item).strip()
    }
    ranked_paths = [
        str(item).strip()
        for item in (impact_path_ranking.get("ranked_path_texts") or [])
        if str(item).strip()
    ]
    top_path = next((item for item in ranked_paths if item not in joined_paths), "") or str(
        impact_path_ranking.get("top_path") or branch_guard.get("next_best_step") or ""
    ).strip()
    business_impact_class = "high-impact" if _is_bold_impact_path(top_path.lower()) else "security-impact"
    planner = build_impact_upgrade_planner(
        vuln_class,
        validation={
            "validation_status": "confirmed" if phase_state.get("phase") in {"impact", "reporting"} else "needs-confirmation",
            "evidence_score": evidence_sufficiency.get("evidence_score", 0.0),
        },
        impact={
            "reportable": _effective_status(evidence_sufficiency) == "report-ready",
            "reportability": "high" if _effective_status(evidence_sufficiency) in {"impact-ready", "report-ready"} else "medium",
            "business_impact_class": business_impact_class,
            "confirmation_state": "confirmed" if phase_state.get("phase") in {"impact", "reporting"} else "needs-confirmation",
        },
        severity={"severity": _planner_severity(top_path, vuln_class)},
    )
    wording = build_program_specific_impact_wording(
        platform,
        vuln_class,
        {"business_impact_class": business_impact_class},
    )
    target_path = str(
        dashboard_issue.get("path")
        or urlparse(str(getattr(payload, "target_url", "") or "")).path
        or "/"
    ).strip()
    title = f"{str(dashboard_issue.get('issue_name') or vuln_class or 'finding').strip()} on {target_path}"
    proof_bundle = _dedupe_nonempty([
        "Baseline request from the same Burp-originated request family.",
        "Changed request showing the one bounded confirmation or escalation variant.",
        _bundle_delta_artifact(response_diff_semantics),
        "One report artifact tying the observed effect to the same trust boundary or workflow.",
    ])[:6]
    missing_evidence = _dedupe_nonempty([
        *list(evidence_sufficiency.get("missing_artifacts") or []),
        *list(counter_hypothesis.get("missing_rejection_evidence") or []),
        str(planner.get("missing_artifact_for_upgrade") or "").strip(),
    ])[:6]
    burp_workflow = _dedupe_nonempty([
        "Keep one untouched baseline Repeater tab for the anchor request family.",
        branch_guard.get("next_best_step") or planner.get("next_strongest_allowed_step") or top_path,
        _cluster_workflow_hint(cross_issue_cluster),
        "Capture the baseline request, changed request, and strongest observed delta as separate report artifacts.",
        ])[:5]
    related_case_support = _dedupe_nonempty([
        str(cross_issue_cluster.get("summary") or "").strip(),
        *list(cross_issue_cluster.get("joined_impact_hints") or []),
    ])[:5]
    summary = (
        f"Phase `{phase_state.get('phase', 'confirmation')}` on `{vuln_class}`. "
        f"Top bounded impact path: {top_path or 'not derived yet'}. "
        f"Reportability is `{_effective_status(evidence_sufficiency, 'blocked')}`."
    )
    return {
        "status": "active" if _is_burp_originated_request(payload) or dashboard_issue.get("found") else "available",
        "title": title,
        "summary": summary,
        "phase": str(phase_state.get("phase") or "confirmation"),
        "reportability": _effective_status(evidence_sufficiency, "blocked"),
        "top_path": top_path,
        "impact_statement": str(planner.get("report_ready_impact_sentence") or "").strip(),
        "platform_focus": str(wording.get("focus") or "").strip(),
        "platform_wording": str(wording.get("wording") or "").strip(),
        "submission_value_score": float(impact_path_ranking.get("submission_value_score", 0.0) or 0.0),
        "confidence": float(confidence_calibration.get("calibrated_confidence", 0.0) or 0.0),
        "proof_bundle": proof_bundle,
        "missing_evidence": missing_evidence,
        "burp_workflow": burp_workflow,
        "related_case_support": related_case_support,
        "claim_boundaries": _dedupe_nonempty([
            "Keep the report scoped to the observed request family, trust boundary, and evidence artifacts only.",
            *list((counter_hypothesis.get("missing_rejection_evidence") or [])[:2]),
        ])[:4],
    }


def build_branch_guard(
        payload,
        *,
        rule_context: dict,
        prompt_sections: dict,
        provider_candidate: dict,
        phase_state: dict,
        contradiction_assessment: dict,
        evidence_sufficiency: dict,
        vulnerability_state_machine: dict,
        counter_hypothesis: dict,
        context_text: str,
        observed_signals: list[str],
        evidence_score: float,
) -> dict[str, Any]:
    contradiction_items = list(contradiction_assessment.get("items") or [])
    contradiction_codes = {str(item.get("code") or "").strip() for item in contradiction_items}
    repeat_requested = _contains_any(context_text, ("retry", "repeat", "same branch", "again", "same payload", "same request"))
    strong_new_signal = any(
        signal in observed_signals
        for signal in ("response-delta", "logger-evidence", "collaborator-evidence", "evidence-timeline")
    )
    dead_end_block = "dead-end-without-new-signal" in contradiction_codes and not strong_new_signal
    mixed_signal = "mixed-history-signal" in contradiction_codes
    vuln_class = str(
        vulnerability_state_machine.get("vuln_class")
        or _infer_vuln_class(provider_candidate, rule_context, payload=payload, prompt_sections=prompt_sections)
    )
    current_state = str(vulnerability_state_machine.get("current_state") or phase_state.get("phase") or "confirmation")
    active_branch = f"{vuln_class}:{current_state}"

    deprioritized_branches: list[str] = []
    if dead_end_block or repeat_requested:
        deprioritized_branches.append(active_branch)

    next_best_hypothesis = str(counter_hypothesis.get("alternative_class") or "").strip()
    next_best_step = str(vulnerability_state_machine.get("next_if_stalled") or phase_state.get("next_gate") or "").strip()
    if counter_hypothesis.get("status") == "rejected":
        next_best_hypothesis = str(vulnerability_state_machine.get("family") or vuln_class).strip()

    # ORIGINAL SAFETY NET: Dead End & Mixed Signal Blocks
    # if dead_end_block:
    #     status = "repeat-branch-blocked"
    #     blocking_reason = "The current branch already produced no signal and no fresh observed artifact is attached."
    #     summary = f"Deprioritize `{active_branch}` until a new observed signal is attached. Move to `{next_best_hypothesis or 'the next bounded hypothesis'}` instead."
    # elif mixed_signal or repeat_requested:
    #     status = "watch"
    #     blocking_reason = "The branch history looks noisy or repetitive, so the next step should change the hypothesis rather than replay the same variant."
    #     summary = "Avoid replaying the same branch without a clearer differentiator."
    # else:
    #     status = "clear"
    #     blocking_reason = ""
    #     summary = "No repeat-branch block is active."

    raw_status = "clear"
    if dead_end_block:
        raw_status = "repeat-branch-blocked"
        blocking_reason = "The current branch already produced no signal and no fresh observed artifact is attached."
        summary = f"Deprioritize `{active_branch}` until a new observed signal is attached. Move to `{next_best_hypothesis or 'the next bounded hypothesis'}` instead."
    elif mixed_signal or repeat_requested:
        raw_status = "watch"
        blocking_reason = "The branch history looks noisy or repetitive, so the next step should change the hypothesis rather than replay the same variant."
        summary = "Avoid replaying the same branch without a clearer differentiator."
    else:
        blocking_reason = ""
        summary = "No repeat-branch block is active."
    effective_status = "clear"
    effective_blocking_reason = ""
    effective_summary = "Permissive branch override keeps the current branch available."
    override_applied = raw_status != effective_status
    override_reason = ""
    if override_applied:
        override_reason = "Permissive branch override keeps repeated or dead-end branches available for continued escalation."

    resume_condition = "Resume this branch only after one new observed delta or corroborating artifact is attached."
    if _effective_status(evidence_sufficiency) in {"impact-ready", "report-ready"} and not dead_end_block:
        resume_condition = "The branch can continue because the current evidence is strong enough for bounded escalation."
    confidence = round(
        min(0.97, 0.38 + (0.18 if strong_new_signal else 0.0) + (0.16 if dead_end_block else 0.0) + min(0.25, evidence_score / 10.0)),
        2,
    )
    return {
        "status": raw_status,
        "raw_status": raw_status,
        "effective_status": effective_status,
        "override_applied": override_applied,
        "override_reason": override_reason,
        "active_branch": active_branch,
        "deprioritized_branches": deprioritized_branches[:3],
        "blocking_reason": blocking_reason,
        "effective_blocking_reason": effective_blocking_reason,
        "next_best_hypothesis": next_best_hypothesis,
        "next_best_step": next_best_step,
        "resume_condition": resume_condition,
        "confidence": confidence,
        "summary": summary,
        "effective_summary": effective_summary,
    }


def build_vulnerability_state_machine(
        payload,
        *,
        rule_context: dict,
        prompt_sections: dict,
        provider_candidate: dict,
        phase_state: dict,
        contradiction_assessment: dict,
        evidence_sufficiency: dict,
        observed_signals: list[str],
        context_text: str,
) -> dict[str, Any]:
    vuln_class = _normalize_vuln_class(
        _infer_vuln_class(provider_candidate, rule_context, payload=payload, prompt_sections=prompt_sections)
    )
    machine = _state_machine_profile(vuln_class)
    current_state = str(phase_state.get("phase") or "confirmation")
    state_profile = dict(machine.get(current_state) or {})
    raw_ready_for_phase = str(evidence_sufficiency.get("ready_for_phase") or current_state)
    effective_ready_for_phase = str(
        evidence_sufficiency.get("effective_ready_for_phase")
        or evidence_sufficiency.get("ready_for_phase")
        or current_state
    )
    raw_contradiction_block = (
        evidence_sufficiency.get("status") == "blocked"
        or contradiction_assessment.get("status") == "contradictions-present"
    )

    # ORIGINAL SAFETY NET: State Machine Holds
    # if contradiction_block:
    #     next_state = current_state
    # elif _PHASE_ORDER.get(ready_for_phase, 0) > _PHASE_ORDER.get(current_state, 0):
    #     next_state = ready_for_phase
    # else:
    #     next_state = current_state

    raw_next_state = current_state
    if raw_contradiction_block:
        raw_next_state = current_state
    elif _PHASE_ORDER.get(raw_ready_for_phase, 0) > _PHASE_ORDER.get(current_state, 0):
        raw_next_state = raw_ready_for_phase

    if _PHASE_ORDER.get(effective_ready_for_phase, 0) > _PHASE_ORDER.get(current_state, 0):
        effective_next_state = effective_ready_for_phase
    else:
        effective_next_state = current_state

    allowed_moves = list(state_profile.get("allowed_moves") or [])
    blocked_moves = list(state_profile.get("blocked_moves") or [])
    preferred_evidence = list(state_profile.get("preferred_evidence") or [])
    next_if_stalled = str(state_profile.get("next_if_stalled") or phase_state.get("next_gate") or "").strip()
    if raw_contradiction_block and preferred_evidence:
        next_if_stalled = preferred_evidence[0]

    # ORIGINAL SAFETY NET: Status Holding
    # if contradiction_block:
    #     status = "hold"
    #     transition_reason = "Contradictions or dead-end signals are stronger than the current escalation evidence, so the state should not advance."
    # elif next_state != current_state:
    #     status = "advance-allowed"
    #     transition_reason = (
    #         f"The evidence sufficiency state supports moving from `{current_state}` to `{next_state}` for `{vuln_class}`."
    #     )
    # else:
    #     status = "stay-bounded"
    #     transition_reason = f"Stay in `{current_state}` until the preferred evidence for `{vuln_class}` is attached."

    if raw_contradiction_block:
        raw_status = "hold"
        raw_transition_reason = "Contradictions or dead-end signals are stronger than the current escalation evidence, so the state should not advance."
    elif raw_next_state != current_state:
        raw_status = "advance-allowed"
        raw_transition_reason = (
            f"The evidence sufficiency state supports moving from `{current_state}` to `{raw_next_state}` for `{vuln_class}`."
        )
    else:
        raw_status = "stay-bounded"
        raw_transition_reason = f"Stay in `{current_state}` until the preferred evidence for `{vuln_class}` is attached."

    if effective_next_state != current_state:
        effective_status = "advance-allowed"
        effective_transition_reason = (
            f"The effective evidence sufficiency state supports moving from `{current_state}` to `{effective_next_state}` for `{vuln_class}`."
        )
    else:
        effective_status = "stay-bounded"
        effective_transition_reason = f"Stay in `{current_state}` until the effective evidence state supports a later phase for `{vuln_class}`."
    override_applied = raw_status != effective_status or raw_next_state != effective_next_state
    override_reason = ""
    if override_applied:
        override_reason = "Permissive state-machine override advances or keeps the branch active based on the effective evidence state."

    return {
        "vuln_class": vuln_class,
        "family": str(machine.get("family") or "general"),
        "status": raw_status,
        "raw_status": raw_status,
        "effective_status": effective_status,
        "override_applied": override_applied,
        "override_reason": override_reason,
        "current_state": current_state,
        "next_state": raw_next_state,
        "raw_next_state": raw_next_state,
        "effective_next_state": effective_next_state,
        "goal": str(state_profile.get("goal") or _PHASE_REASONING.get(current_state, "")),
        "preferred_evidence": preferred_evidence[:4],
        "allowed_moves": allowed_moves[:4],
        "blocked_moves": blocked_moves[:4],
        "next_if_stalled": next_if_stalled,
        "alternative_class": str(machine.get("alternative_class") or "alternate explanation"),
        "alternative_explanation": str(machine.get("alternative_explanation") or "The strongest alternate explanation has not been ruled out yet."),
        "transition_reason": raw_transition_reason,
        "effective_transition_reason": effective_transition_reason,
    }


def build_counter_hypothesis(
        payload,
        *,
        rule_context: dict,
        prompt_sections: dict,
        provider_candidate: dict,
        phase_state: dict,
        contradiction_assessment: dict,
        evidence_sufficiency: dict,
        vulnerability_state_machine: dict,
        context_text: str,
        observed_signals: list[str],
        evidence_score: float,
) -> dict[str, Any]:
    machine = _state_machine_profile(str(vulnerability_state_machine.get("vuln_class") or "general"))
    markers = tuple(machine.get("rejection_markers") or ())
    matched_markers = _matched_markers(context_text, markers)
    contradiction_count = int(contradiction_assessment.get("count", 0) or 0)
    strong_new_signal = any(
        signal in observed_signals
        for signal in ("response-delta", "logger-evidence", "collaborator-evidence", "evidence-timeline")
    )

    if matched_markers and contradiction_count == 0 and evidence_score >= 1.8 and strong_new_signal:
        status = "rejected"
    elif matched_markers or (strong_new_signal and evidence_score >= 1.0):
        status = "partially-rejected"
    else:
        status = "not-rejected"

    rejection_evidence = [
        f"Observed marker: `{item}`."
        for item in matched_markers[:4]
    ]
    if strong_new_signal:
        rejection_evidence.append(f"Observed evidence types: {', '.join(_signal_label(item) for item in observed_signals[:4])}.")
    rejection_evidence = rejection_evidence[:4]

    missing_rejection_evidence = []
    if status != "rejected":
        if markers:
            missing_rejection_evidence.append(
                "Add one artifact that specifically rules out the alternative explanation, such as "
                + ", ".join(f"`{item}`" for item in markers[:3])
                + "."
            )
        preferred = list(vulnerability_state_machine.get("preferred_evidence") or [])
        if preferred:
            missing_rejection_evidence.append(preferred[0])
        if contradiction_count:
            missing_rejection_evidence.append("Resolve the current contradiction signals before rejecting the alternative explanation.")

    rejection_confidence = round(
        min(
            0.97,
            0.24
            + (0.18 * len(matched_markers))
            + (0.16 if strong_new_signal else 0.0)
            + min(0.24, evidence_score / 10.0)
            - (0.1 * min(2, contradiction_count)),
            ),
        2,
    )
    summary = (
        f"The strongest alternative explanation is `{vulnerability_state_machine.get('alternative_class', 'alternate explanation')}`."
    )
    if status == "rejected":
        summary += " The currently attached evidence is strong enough to reject it."
    elif status == "partially-rejected":
        summary += " The attached evidence weakens it, but does not close it out yet."
    else:
        summary += " The attached evidence is not yet strong enough to reject it."

    return {
        "lead_hypothesis": str(
            vulnerability_state_machine.get("vuln_class")
            or _infer_vuln_class(provider_candidate, rule_context, payload=payload, prompt_sections=prompt_sections)
        ),
        "alternative_class": str(vulnerability_state_machine.get("alternative_class") or "alternate explanation"),
        "alternative_explanation": str(vulnerability_state_machine.get("alternative_explanation") or ""),
        "status": status,
        "rejection_confidence": rejection_confidence,
        "rejection_evidence": rejection_evidence,
        "missing_rejection_evidence": missing_rejection_evidence[:4],
        "summary": summary,
    }


def summarize_phase_state(phase_state: dict) -> str:
    if not phase_state:
        return "No explicit investigation phase state was derived."
    lines = [
        f"Phase: {phase_state.get('phase', 'triage')}",
        f"Desired phase: {phase_state.get('desired_phase', 'triage')}",
        f"Max supported phase: {phase_state.get('max_supported_phase', 'triage')}",
        f"Rationale: {phase_state.get('rationale', '')}",
    ]
    blockers = list(phase_state.get("blockers") or [])
    if blockers:
        lines.append("Blockers: " + "; ".join(blockers[:3]))
    next_gate = str(phase_state.get("next_gate") or "").strip()
    if next_gate:
        lines.append("Next gate: " + next_gate)
    return "\n".join(lines).strip()


def summarize_contradiction_assessment(assessment: dict) -> str:
    if not assessment:
        return "No contradiction assessment was derived."
    if not int(assessment.get("count", 0) or 0):
        return "Contradictions: none detected."
    lines = [
        f"Status: {assessment.get('status', 'watch')}",
        f"Effective status: {_effective_status(assessment, assessment.get('status', 'watch'))}",
        f"Highest severity: {assessment.get('highest_severity', 'low')}",
        f"Summary: {assessment.get('summary', '')}",
    ]
    if assessment.get("override_applied"):
        lines.append("Override: " + str(assessment.get("override_reason") or "").strip())
    for item in list(assessment.get("items") or [])[:3]:
        lines.append("- " + str(item.get("summary") or "").strip())
    return "\n".join(lines).strip()


def summarize_evidence_sufficiency(sufficiency: dict) -> str:
    if not sufficiency:
        return "No evidence sufficiency state was derived."
    lines = [
        f"Status: {sufficiency.get('status', 'insufficient')}",
        f"Effective status: {_effective_status(sufficiency, sufficiency.get('status', 'insufficient'))}",
        f"Ready for phase: {sufficiency.get('ready_for_phase', 'triage')}",
        f"Effective phase: {_effective_ready_for_phase(sufficiency, sufficiency.get('ready_for_phase', 'triage'))}",
        f"Evidence score: {sufficiency.get('evidence_score', 0.0)}",
        f"Rationale: {sufficiency.get('rationale', '')}",
    ]
    if sufficiency.get("override_applied"):
        lines.append("Override: " + str(sufficiency.get("override_reason") or "").strip())
    missing = list(sufficiency.get("missing_evidence") or [])
    if missing:
        lines.append("Missing evidence: " + "; ".join(missing[:3]))
    artifacts = list(sufficiency.get("missing_artifacts") or [])
    if artifacts:
        lines.append("Missing artifact for upgrade: " + "; ".join(artifacts[:2]))
    next_gate = str(sufficiency.get("next_best_gate") or "").strip()
    if next_gate:
        lines.append("Next gate: " + next_gate)
    return "\n".join(lines).strip()


def summarize_branch_guard(branch_guard: dict) -> str:
    if not branch_guard:
        return "No no-repeat guard state was derived."
    lines = [
        f"Status: {branch_guard.get('status', 'clear')}",
        f"Effective status: {_effective_status(branch_guard, branch_guard.get('status', 'clear'))}",
        f"Active branch: {branch_guard.get('active_branch', '')}",
        f"Summary: {branch_guard.get('summary', '')}",
    ]
    if branch_guard.get("override_applied"):
        lines.append("Override: " + str(branch_guard.get("override_reason") or "").strip())
    effective_summary = str(branch_guard.get("effective_summary") or "").strip()
    if effective_summary:
        lines.append("Effective summary: " + effective_summary)
    blocking_reason = str(branch_guard.get("blocking_reason") or "").strip()
    if blocking_reason:
        lines.append("Blocking reason: " + blocking_reason)
    next_hypothesis = str(branch_guard.get("next_best_hypothesis") or "").strip()
    if next_hypothesis:
        lines.append("Next best hypothesis: " + next_hypothesis)
    next_step = str(branch_guard.get("next_best_step") or "").strip()
    if next_step:
        lines.append("Next best step: " + next_step)
    return "\n".join(lines).strip()


def summarize_vulnerability_state_machine(state_machine: dict) -> str:
    if not state_machine:
        return "No per-vulnerability state machine was derived."
    lines = [
        f"Vulnerability class: {state_machine.get('vuln_class', 'general')}",
        f"Current state: {state_machine.get('current_state', 'confirmation')}",
        f"Next state: {state_machine.get('next_state', 'confirmation')}",
        f"Effective next state: {_effective_next_state(state_machine, state_machine.get('next_state', 'confirmation'))}",
        f"Goal: {state_machine.get('goal', '')}",
        f"Transition reason: {state_machine.get('transition_reason', '')}",
    ]
    if state_machine.get("override_applied"):
        lines.append("Override: " + str(state_machine.get("override_reason") or "").strip())
    effective_transition_reason = str(state_machine.get("effective_transition_reason") or "").strip()
    if effective_transition_reason:
        lines.append("Effective transition reason: " + effective_transition_reason)
    allowed_moves = list(state_machine.get("allowed_moves") or [])
    if allowed_moves:
        lines.append("Allowed moves: " + "; ".join(allowed_moves[:3]))
    blocked_moves = list(state_machine.get("blocked_moves") or [])
    if blocked_moves:
        lines.append("Blocked moves: " + "; ".join(blocked_moves[:3]))
    next_if_stalled = str(state_machine.get("next_if_stalled") or "").strip()
    if next_if_stalled:
        lines.append("Next if stalled: " + next_if_stalled)
    return "\n".join(lines).strip()


def summarize_counter_hypothesis(counter_hypothesis: dict) -> str:
    if not counter_hypothesis:
        return "No counter-hypothesis state was derived."
    lines = [
        f"Lead hypothesis: {counter_hypothesis.get('lead_hypothesis', '')}",
        f"Alternative: {counter_hypothesis.get('alternative_class', '')}",
        f"Status: {counter_hypothesis.get('status', 'not-rejected')}",
        f"Summary: {counter_hypothesis.get('summary', '')}",
    ]
    rejection_evidence = list(counter_hypothesis.get("rejection_evidence") or [])
    if rejection_evidence:
        lines.append("Rejection evidence: " + "; ".join(rejection_evidence[:3]))
    missing = list(counter_hypothesis.get("missing_rejection_evidence") or [])
    if missing:
        lines.append("Missing rejection evidence: " + "; ".join(missing[:3]))
    return "\n".join(lines).strip()


def summarize_confidence_calibration(confidence_calibration: dict) -> str:
    if not confidence_calibration:
        return "No historical confidence calibration was derived."
    lines = [
        f"Status: {confidence_calibration.get('status', 'neutral')}",
        f"Base confidence: {confidence_calibration.get('base_confidence', 0.0)}",
        f"Calibrated confidence: {confidence_calibration.get('calibrated_confidence', 0.0)}",
        f"Summary: {confidence_calibration.get('summary', '')}",
    ]
    ordering = str(confidence_calibration.get("step_ordering_bias") or "").strip()
    if ordering:
        lines.append("Step ordering bias: " + ordering)
    return "\n".join(lines).strip()


def summarize_cross_issue_cluster(cluster: dict) -> str:
    if not cluster:
        return "No cross-issue cluster was derived."
    lines = [
        f"Status: {cluster.get('status', 'isolated')}",
        f"Issue count: {cluster.get('issue_count', 0)}",
        f"Summary: {cluster.get('summary', '')}",
    ]
    strategy = str(cluster.get("strategy") or "").strip()
    if strategy:
        lines.append("Strategy: " + strategy)
    supporting = list(cluster.get("supporting_issue_names") or [])
    if supporting:
        lines.append("Supporting issues: " + ", ".join(supporting[:3]))
    joined_hints = list(cluster.get("joined_impact_hints") or [])
    if joined_hints:
        lines.append("Joined impact hints: " + "; ".join(joined_hints[:2]))
    return "\n".join(lines).strip()


def summarize_response_diff_semantics(semantics: dict) -> str:
    if not semantics:
        return "No response-diff semantics were derived."
    lines = [
        f"Primary semantic: {semantics.get('primary_semantic', 'not-classified')}",
        f"Summary: {semantics.get('summary', '')}",
    ]
    focus = str(semantics.get("recommended_comparison_focus") or "").strip()
    if focus:
        lines.append("Comparison focus: " + focus)
    return "\n".join(lines).strip()


def summarize_impact_path_ranking(ranking: dict) -> str:
    if not ranking:
        return "No program-aware impact path ranking was derived."
    lines = [
        f"Platform: {ranking.get('platform', 'generic')}",
        f"Target type: {ranking.get('target_type', 'general-web')}",
        f"Top path: {ranking.get('top_path', '')}",
        f"Summary: {ranking.get('summary', '')}",
    ]
    gated = list(ranking.get("gated_paths") or [])
    if gated:
        lines.append("Gated paths: " + "; ".join(gated[:3]))
    return "\n".join(lines).strip()


def summarize_report_bundle(bundle: dict) -> str:
    if not bundle:
        return "No live report bundle was derived."
    lines = [
        f"Title: {bundle.get('title', '')}",
        f"Phase: {bundle.get('phase', 'confirmation')}",
        f"Reportability: {bundle.get('reportability', 'blocked')}",
        f"Top path: {bundle.get('top_path', '')}",
        f"Summary: {bundle.get('summary', '')}",
    ]
    proof_bundle = list(bundle.get("proof_bundle") or [])
    if proof_bundle:
        lines.append("Proof bundle: " + "; ".join(proof_bundle[:3]))
    missing = list(bundle.get("missing_evidence") or [])
    if missing:
        lines.append("Missing evidence: " + "; ".join(missing[:2]))
    return "\n".join(lines).strip()


def _combined_context_text(payload, prompt_sections: dict) -> str:
    chunks = [
        prompt_sections.get("follow_up_request", ""),
        prompt_sections.get("issue_workflow_notes_summary", ""),
        prompt_sections.get("investigation_notebook_summary", ""),
        prompt_sections.get("scanner_issue_context", ""),
        prompt_sections.get("response_delta_summary", ""),
        prompt_sections.get("tool_results_summary", ""),
        getattr(payload, "tool_results_text", "") or "",
        ]
    return " ".join(str(item).strip().lower() for item in chunks if str(item).strip())


def _observed_evidence_signals(payload, prompt_sections: dict) -> list[str]:
    signals = []
    if _has_signal_text(getattr(payload, "response_delta_text", "") or prompt_sections.get("response_delta_summary", "")):
        signals.append("response-delta")
    if _has_signal_text(getattr(payload, "logger_evidence_text", "") or prompt_sections.get("logger_evidence_summary", "")):
        signals.append("logger-evidence")
    if _has_signal_text(getattr(payload, "collaborator_evidence_text", "") or prompt_sections.get("collaborator_evidence_summary", "")):
        signals.append("collaborator-evidence")
    if getattr(payload, "evidence_timeline_entries", None) or _has_signal_text(prompt_sections.get("evidence_timeline_summary", "")):
        signals.append("evidence-timeline")
    if _has_signal_text(prompt_sections.get("scanner_issue_context", "")):
        signals.append("scanner-baseline")
    if getattr(payload, "issue_workflow_notes", None) or _has_signal_text(prompt_sections.get("investigation_notebook_summary", "")):
        signals.append("workflow-memory")
    if _has_signal_text(getattr(payload, "bapp_findings_text", "") or prompt_sections.get("bapp_findings_summary", "")):
        signals.append("bapp-findings")
    return signals


def _desired_phase(context_text: str) -> str:
    if _contains_any(context_text, _REPORTING_MARKERS):
        return "reporting"
    if _contains_any(context_text, _IMPACT_MARKERS):
        return "impact"
    if _contains_any(context_text, _CONFIRMATION_MARKERS) or context_text.strip():
        return "confirmation"
    return "triage"


def _max_supported_phase(payload, observed_signals: list[str], evidence_score: float, context_text: str) -> str:
    strong_signals = {
        signal
        for signal in observed_signals
        if signal in {"response-delta", "logger-evidence", "collaborator-evidence", "evidence-timeline"}
    }
    if (
            evidence_score >= 3.2
            and len(strong_signals) >= 3
            and _contains_any(context_text, _REPORTING_MARKERS)
            and not _contains_any(context_text, _NEGATIVE_MARKERS)
    ):
        return "reporting"
    if evidence_score >= 2.0 and strong_signals:
        return "impact"
    if evidence_score >= 0.8 or observed_signals or _has_signal_text(getattr(payload, "target_url", "")):
        return "confirmation"
    return "triage"


def _phase_signals(context_text: str, observed_signals: list[str]) -> list[str]:
    signals = [_signal_label(item) for item in observed_signals]
    if _contains_any(context_text, _CONFIRMATION_MARKERS):
        signals.append("confirmation-intent")
    if _contains_any(context_text, _IMPACT_MARKERS):
        signals.append("impact-intent")
    if _contains_any(context_text, _REPORTING_MARKERS):
        signals.append("reporting-intent")
    return list(dict.fromkeys(signals))


def _phase_rationale(phase: str, *, desired_phase: str, supported_phase: str, signals: list[str]) -> str:
    if desired_phase != supported_phase and _PHASE_ORDER[desired_phase] > _PHASE_ORDER[supported_phase]:
        return (
            f"{desired_phase.capitalize()} intent was detected, but the current observed evidence only supports {supported_phase}."
        )
    signal_text = ", ".join(signals[:4]) or "no explicit signals"
    return f"The current follow-up intent and attached evidence align with {phase}; key signals: {signal_text}."


def _next_gate_for_phase(phase: str, *, vuln_class: str, supported_phase: str) -> str:
    planner = build_impact_upgrade_planner(
        vuln_class,
        validation={"validation_status": "confirmed" if supported_phase in {"impact", "reporting"} else "needs-confirmation"},
        impact={"reportable": supported_phase == "reporting", "confirmation_state": "confirmed" if supported_phase in {"impact", "reporting"} else "needs-confirmation"},
    )
    if phase == "triage":
        return _PHASE_REASONING["triage"]
    if phase == "confirmation":
        return _PHASE_REASONING["confirmation"]
    if phase in {"impact", "reporting"}:
        return str(planner.get("next_strongest_allowed_step") or _PHASE_REASONING[phase])
    return _PHASE_REASONING["confirmation"]


def _sufficiency_rationale(status: str, ready_for_phase: str, evidence_score: float, contradiction_assessment: dict) -> str:
    contradiction_count = int(contradiction_assessment.get("count", 0) or 0)
    if status == "blocked":
        return "Contradictions are currently stronger than the attached evidence, so the case should not escalate yet."
    if status == "report-ready":
        return f"The evidence score is {evidence_score:.2f} with no material contradiction gates, so report assembly is justified."
    if status == "impact-ready":
        return f"The evidence score is {evidence_score:.2f}, which is strong enough to explore bounded impact without claiming report-ready proof."
    if status == "confirmation-ready":
        return f"The evidence score is {evidence_score:.2f}; stay in confirmation until one cleaner artifact is attached."
    if contradiction_count:
        return "The evidence is still incomplete and contradictions are present, so the next step should narrow the branch."
    return f"The current evidence only supports `{ready_for_phase}` at this stage."


def _scanner_anchor_vuln_class(payload, prompt_sections: dict | None = None) -> str:
    dashboard_issue = get_dashboard_issue_context(payload)
    dashboard_hint = _normalize_vuln_class(str(dashboard_issue.get("vuln_hint") or "").strip().lower())
    if dashboard_issue.get("found") and dashboard_hint != "general":
        return dashboard_hint

    scanner_text = str((prompt_sections or {}).get("scanner_issue_context") or "").strip().lower()
    for tokens, mapped in (
            (("cross-site scripting", " xss", "stored xss", "reflected xss"), "xss"),
            (("direct object reference", "idor", "access control"), "authorization"),
            (("server-side request forgery", "ssrf"), "ssrf"),
            (("sql injection", " sqli"), "injection"),
            (("template injection", "ssti"), "template-injection"),
            (("authentication", "session"), "authentication"),
            (("race condition", "race-condition"), "race-condition"),
    ):
        if any(token in scanner_text for token in tokens):
            return mapped
    return ""


def _infer_vuln_class(
        provider_candidate: dict,
        rule_context: dict,
        *,
        payload=None,
        prompt_sections: dict | None = None,
) -> str:
    anchor_class = _scanner_anchor_vuln_class(payload, prompt_sections)
    if anchor_class:
        return _normalize_vuln_class(anchor_class)
    planner = provider_candidate.get("planner") if isinstance(provider_candidate, dict) else {}
    if isinstance(planner, dict) and str(planner.get("vuln_type") or "").strip():
        return _normalize_vuln_class(str(planner.get("vuln_type") or "").strip().lower())
    matched = list((rule_context or {}).get("matched_recipes", []) or [])
    if matched:
        value = str(matched[0].get("vuln_class") or "").strip().lower()
        if value:
            return _normalize_vuln_class(value)
    return "general"


def _normalize_vuln_class(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return "general"
    return _CLASS_ALIASES.get(normalized, normalized)


def _effective_status(container: dict | None, default: str = "") -> str:
    if not isinstance(container, dict):
        return default
    return str(container.get("effective_status") or container.get("status") or default)


def _effective_ready_for_phase(container: dict | None, default: str = "") -> str:
    if not isinstance(container, dict):
        return default
    return str(container.get("effective_ready_for_phase") or container.get("ready_for_phase") or default)


def _effective_next_state(container: dict | None, default: str = "") -> str:
    if not isinstance(container, dict):
        return default
    return str(container.get("effective_next_state") or container.get("next_state") or default)


def _state_machine_profile(vuln_class: str) -> dict[str, Any]:
    normalized = _normalize_vuln_class(vuln_class)
    profile = _STATE_MACHINES.get(normalized)
    if profile:
        return profile
    return {
        "family": "general-assessment",
        "triage": {
            "goal": _PHASE_REASONING["triage"],
            "preferred_evidence": ["One bounded baseline artifact.", "One explicit route or parameter anchor."],
            "allowed_moves": ["Keep one variable fixed.", "Capture one baseline before widening the branch."],
            "blocked_moves": ["Impact claims without confirmation.", "Multiple new branches at once."],
            "next_if_stalled": "Move to the next strongest bounded hypothesis instead of replaying the same branch.",
        },
        "confirmation": {
            "goal": _PHASE_REASONING["confirmation"],
            "preferred_evidence": ["One reproducible response or workflow delta.", "One corroborating evidence source."],
            "allowed_moves": ["Confirm one bounded delta.", "Keep the hypothesis stable."],
            "blocked_moves": ["Report-ready wording without confirmation.", "Broader exploit narratives."],
            "next_if_stalled": "Ask whether the strongest alternative explanation better fits the current evidence.",
        },
        "impact": {
            "goal": _PHASE_REASONING["impact"],
            "preferred_evidence": ["One bounded business impact artifact.", "One clear trust-boundary consequence."],
            "allowed_moves": ["Document one reportable consequence.", "Stay within the same trust boundary."],
            "blocked_moves": ["Broader claims without proof.", "New branch families."],
            "next_if_stalled": "Step back to confirmation and capture one stronger artifact.",
        },
        "reporting": {
            "goal": _PHASE_REASONING["reporting"],
            "preferred_evidence": ["One report-ready artifact bundle.", "One bounded claim statement."],
            "allowed_moves": ["Assemble the report-ready evidence.", "Limit the wording to observed facts."],
            "blocked_moves": ["New escalation branches.", "Broader scope wording."],
            "next_if_stalled": "Return to impact and collect one cleaner artifact.",
        },
        "alternative_class": "generic alternate explanation",
        "alternative_explanation": "The current evidence may still fit a lower-signal or non-security explanation.",
        "rejection_markers": ("confirmed", "role diff", "response delta", "collaborator"),
    }


def _planner_confidence(planner: dict) -> float:
    if not isinstance(planner, dict):
        return 0.0
    try:
        value = float(planner.get("confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0
    if value > 1.0 and value <= 100.0:
        value = value / 100.0
    return max(0.0, min(1.0, round(value, 2)))


def _lower_phase(left: str, right: str) -> str:
    return left if _PHASE_ORDER[left] <= _PHASE_ORDER[right] else right


def _highest_severity(items: list[dict[str, Any]]) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    highest = "low"
    for item in items:
        severity = str(item.get("severity") or "low").strip().lower()
        if order.get(severity, 0) > order[highest]:
            highest = severity
    return highest


def _signal_label(signal: str) -> str:
    mapping = {
        "response-delta": "response delta",
        "logger-evidence": "Logger++ evidence",
        "collaborator-evidence": "Collaborator evidence",
        "evidence-timeline": "evidence timeline",
        "scanner-baseline": "scanner baseline",
        "workflow-memory": "workflow memory",
        "bapp-findings": "BApp findings",
    }
    return mapping.get(signal, signal.replace("-", " "))


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text for marker in markers)


def _matched_markers(text: str, markers: tuple[str, ...]) -> list[str]:
    matched = []
    for marker in markers:
        if marker not in text:
            continue
        negated_forms = (
            f"no {marker}",
            f"not {marker}",
            f"without {marker}",
            f"missing {marker}",
            f"still no {marker}",
        )
        if any(form in text for form in negated_forms):
            continue
        matched.append(marker)
    return matched


def _parsed_target_host(payload) -> str:
    target_url = str(getattr(payload, "target_url", "") or "").strip()
    return urlparse(target_url).hostname or urlparse(target_url).netloc or "unknown-host"


def _path_family(path: str) -> str:
    parts = []
    for item in str(path or "/").split("/"):
        lowered = item.strip().lower()
        if not lowered:
            continue
        parts.append("{id}" if lowered.isdigit() else lowered)
    if not parts:
        return "/"
    return "/" + "/".join(parts[:3])


def _query_param_names(target_url: str) -> list[str]:
    return [
        str(key).strip().lower()
        for key, _ in parse_qsl(urlparse(target_url).query, keep_blank_values=True)
        if str(key).strip()
    ]


def _most_common_nonempty(values: list[str]) -> str:
    counts: dict[str, int] = {}
    for value in values:
        normalized = str(value or "").strip().lower()
        if not normalized:
            continue
        counts[normalized] = counts.get(normalized, 0) + 1
    if not counts:
        return ""
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def _infer_target_type(payload, vulnerability_state_machine: dict, response_diff_semantics: dict) -> str:
    target_url = str(getattr(payload, "target_url", "") or "").lower()
    path = urlparse(target_url).path or "/"
    semantics = set(response_diff_semantics.get("semantics") or [])
    vuln_class = str(vulnerability_state_machine.get("vuln_class") or "general")
    if "/api/" in path or any(token in path for token in ("/graphql", "/rest", "/v1/", "/v2/")):
        return "api"
    if vuln_class in {"xss", "template-injection"} or "sink-context-shift" in semantics:
        return "browser-workflow"
    if any(token in path for token in ("/admin", "/settings", "/account", "/profile")):
        return "account-workflow"
    return "general-web"


def _impact_path_reward_alignment(path_text: str, vuln_class: str, target_type: str, primary_semantic: str) -> float:
    score = 0.0
    lowered = str(path_text or "").lower()
    if vuln_class in {"authorization", "authentication"} and any(token in lowered for token in ("unauthorized", "cross-tenant", "privilege", "admin", "other user", "sensitive data")):
        score += 0.24
    if vuln_class in {"xss", "template-injection"} and any(token in lowered for token in ("viewer", "shared", "admin", "privileged render", "workflow")):
        score += 0.24
    if vuln_class in {"ssrf", "xxe"} and any(token in lowered for token in ("backend", "fetch", "callback", "internal", "metadata", "file")):
        score += 0.2
    if vuln_class in {"race-condition", "csrf", "business-logic"} and any(token in lowered for token in ("state change", "approval", "quota", "balance", "workflow", "inventory")):
        score += 0.22
    if target_type == "api" and any(token in lowered for token in ("data", "object", "tenant", "admin", "workflow")):
        score += 0.12
    if target_type == "browser-workflow" and any(token in lowered for token in ("viewer", "render", "browser", "admin")):
        score += 0.12
    if primary_semantic == "auth-boundary" and any(token in lowered for token in ("unauthorized", "cross-tenant", "privilege", "admin")):
        score += 0.1
    if primary_semantic == "data-exposure" and any(token in lowered for token in ("data", "exposure", "fields", "secret", "pii")):
        score += 0.1
    if primary_semantic == "state-change" and "state change" in lowered:
        score += 0.1
    if primary_semantic == "sink-context-shift" and any(token in lowered for token in ("viewer", "render", "workflow")):
        score += 0.08
    return score


def _impact_path_matches_vuln_class(path_text: str, vuln_class: str) -> bool:
    lowered = str(path_text or "").lower()
    if not lowered or vuln_class == "general":
        return True
    token_map = {
        "xss": ("viewer", "render", "shared", "admin", "workflow", "script"),
        "template-injection": ("template", "render", "server-side"),
        "authorization": ("unauthorized", "cross-tenant", "cross-user", "object", "other user", "other tenant", "field"),
        "authentication": ("auth", "session", "login", "privilege", "protected route"),
        "ssrf": ("backend", "fetch", "callback", "metadata", "internal", "service reachability"),
        "xxe": ("xml", "entity", "parser", "file", "backend fetch"),
        "injection": ("query", "database", "sql", "sensitive data", "protected data"),
        "race-condition": ("concurrent", "double", "workflow", "timing", "state change"),
    }
    return any(token in lowered for token in token_map.get(vuln_class, (vuln_class,)))


def _is_bold_impact_path(path_text: str) -> bool:
    lowered = str(path_text or "").lower()
    return any(token in lowered for token in ("cross-tenant", "privilege", "admin", "internal", "metadata", "state change", "secret", "bulk", "financial"))


def _policy_sensitive_path(path_text: str, vuln_class: str) -> bool:
    lowered = str(path_text or "").lower()
    if vuln_class in {"ssrf", "xxe", "deserialization", "http-request-smuggling", "race-condition"}:
        return any(token in lowered for token in ("internal", "metadata", "queue", "concurrency", "file", "pivot", "desync", "smuggling"))
    return False


def _compatible_cluster_classes(anchor_class: str) -> set[str]:
    normalized = _normalize_vuln_class(anchor_class)
    return set(_CLUSTER_JOIN_COMPATIBILITY.get(normalized, {normalized})) | {"general"}


def _joined_impact_hints(
        *,
        anchor_class: str,
        merged_classes: list[str],
        same_path_cluster: bool,
        same_param_cluster: bool,
        primary_semantic: str,
) -> list[str]:
    normalized_anchor = _normalize_vuln_class(anchor_class)
    merged = {_normalize_vuln_class(item) for item in merged_classes if item}
    hints: list[str] = []

    if normalized_anchor == "authorization":
        hints.append("Prioritize unauthorized object fields, adjacent export views, or privileged records on the same object family.")
        if {"information-disclosure", "secret-exposure"} & merged:
            hints.append("Use the sibling data-exposure findings to strengthen the same unauthorized object-boundary report, not as a separate case.")
    elif normalized_anchor == "authentication":
        hints.append("Prioritize protected routes or workflows that stay reachable across login, logout, recovery, or token-state transitions.")
    elif normalized_anchor == "xss":
        hints.append("Prioritize the highest-value shared, moderator, or admin viewer workflow that can reach the same render sink.")
        if "template-injection" in merged:
            hints.append("Use the sibling evaluation-style finding only if it reinforces the same render surface and viewer workflow.")
    elif normalized_anchor == "ssrf":
        hints.append("Prioritize the strongest bounded backend fetch implication on the same URL-handling sink before switching routes.")
        if {"xxe", "open-redirect"} & merged:
            hints.append("Use the sibling parser or redirect finding to narrow the same backend URL-handling trust boundary.")
    elif normalized_anchor == "injection":
        hints.append("Prioritize the strongest bounded data, auth, or workflow consequence on the same interpreted sink.")
    elif normalized_anchor == "race-condition":
        hints.append("Prioritize the same reversible workflow effect across the strongest related approval, quota, or state-change surface.")

    if same_path_cluster:
        hints.append("Keep the same path family anchored while the sibling issues raise the strongest reportable impact path.")
    elif same_param_cluster:
        hints.append("Keep the same parameter family fixed and use the sibling finding only to choose the next bounded comparison.")
    elif primary_semantic == "auth-boundary":
        hints.append("The current response delta already looks like a boundary shift, so keep the next proof on the same trust boundary.")

    return _dedupe_nonempty(hints)[:4]


def _bundle_delta_artifact(response_diff_semantics: dict) -> str:
    semantic = str(response_diff_semantics.get("primary_semantic") or "").strip()
    focus = str(response_diff_semantics.get("recommended_comparison_focus") or "").strip()
    if semantic and focus:
        return f"Key delta artifact: `{semantic}`. {focus}"
    if semantic:
        return f"Key delta artifact: `{semantic}`."
    return "One clear response or workflow delta explaining what actually changed."


def _cluster_workflow_hint(cross_issue_cluster: dict) -> str:
    joined = list(cross_issue_cluster.get("joined_impact_hints") or [])
    if joined:
        return joined[0]
    strategy = str(cross_issue_cluster.get("strategy") or "").strip()
    if strategy:
        return strategy
    return "Keep related Burp findings as supporting context only while one bounded request family stays active."


def _planner_severity(top_path: str, vuln_class: str) -> str:
    lowered = str(top_path or "").lower()
    if _is_bold_impact_path(lowered):
        return "high"
    if vuln_class in {"authentication", "authorization", "ssrf", "injection", "template-injection", "file-read"}:
        return "high"
    return "medium"


def _dedupe_nonempty(items: list[str]) -> list[str]:
    deduped: list[str] = []
    for item in items:
        normalized = str(item or "").strip()
        if normalized and normalized not in deduped:
            deduped.append(normalized)
    return deduped


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
        or bool(get_dashboard_issue_context(payload).get("found"))
    )


def _has_signal_text(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(
        text
        and text != "<none>"
        and text != "No context found."
        and not text.startswith("No ")
        and text.lower() != "unavailable"
    )
