from __future__ import annotations

from typing import Any


def build_next_try_matrix(
    *,
    vuln_class: str = "",
    title: str = "",
    primary_next_action: str = "",
    request_plan: list[str] | None = None,
    payload_recommendations: list[str] | None = None,
    impact_paths: list[str] | None = None,
    escalation_profile: str = "",
    required_evidence_for_upgrade: list[str] | None = None,
    business_impact_expansion_paths: list[str] | None = None,
) -> list[dict[str, str]]:
    normalized_class = (vuln_class or "general").strip().lower() or "general"
    title_text = (title or normalized_class or "finding").strip()
    plan = list(request_plan or [])
    payloads = list(payload_recommendations or [])
    impacts = list(impact_paths or [])
    required = list(required_evidence_for_upgrade or [])
    expansions = list(business_impact_expansion_paths or [])

    target = _plan_value(plan, "Target parameter")
    mode = _plan_value(plan, "Primary mode")
    tool = _plan_value(plan, "Best Burp helper") or mode or "Burp Repeater"
    starter_payload = payloads[0] if payloads else "Use one bounded variant tied to the scanner-marked sink or object boundary."

    items = [
        {
            "phase": "baseline-confirmation",
            "what_to_try": primary_next_action or f"Capture one clean baseline confirmation for {title_text}.",
            "how_it_helps": f"This proves the current {normalized_class} signal is real before you widen into impact or chaining.",
            "evidence_to_capture": "Baseline request, changed request, and one clear response delta.",
            "impact_signal": "A repeatable control failure on the scanner-marked input, sink, or object boundary.",
        },
        {
            "phase": "bounded-variant",
            "what_to_try": f"Use {tool} on {target or 'the marked request component'} with one bounded variant: {starter_payload}",
            "how_it_helps": "This turns a generic scanner finding into a controlled comparison you can explain in a report.",
            "evidence_to_capture": "Status, headers, body-length/body-content delta, and any reflected or parser-side marker change.",
            "impact_signal": "A stable diff that shows the server changed authorization, rendering, parsing, or workflow behavior.",
        },
        {
            "phase": "impact-branch",
            "what_to_try": impacts[0] if impacts else (expansions[0] if expansions else f"Choose the safest next {normalized_class} impact branch after the baseline holds."),
            "how_it_helps": "This moves the finding from confirmation toward a business-impact statement that bug bounty programs care about.",
            "evidence_to_capture": required[0] if required else "One artifact that ties the confirmed bug to a stronger impact claim.",
            "impact_signal": "Cross-tenant access, privileged render, state change, backend fetch, or another bounded impact effect.",
        },
    ]

    if required or expansions or escalation_profile:
        items.append(
            {
                "phase": "report-upgrade",
                "what_to_try": expansions[0] if expansions else f"Use the {escalation_profile or normalized_class} escalation path only after the baseline evidence is clean.",
                "how_it_helps": "This gives you the missing proof needed to justify a stronger severity and cleaner bounty report.",
                "evidence_to_capture": required[0] if required else "The exact missing artifact needed for a severity upgrade.",
                "impact_signal": "The point where the report can move from technical finding to business impact.",
            }
        )

    return items[:4]


def build_reporting_impact_notes(
    *,
    vuln_class: str = "",
    required_evidence_for_upgrade: list[str] | None = None,
    business_impact_expansion_paths: list[str] | None = None,
) -> list[str]:
    normalized_class = (vuln_class or "general").strip().lower() or "general"
    required = list(required_evidence_for_upgrade or [])
    expansions = list(business_impact_expansion_paths or [])
    notes = [
        f"Keep the report anchored to the confirmed {normalized_class} behavior, not only the scanner label.",
    ]
    if required:
        notes.append("Do not claim a stronger severity until you capture: " + required[0])
    if expansions:
        notes.append("Best business-impact branch to test next: " + expansions[0])
    else:
        notes.append("Keep the next step bounded and evidence-first before broadening the impact claim.")
    return notes[:3]


def _plan_value(request_plan: list[str], prefix: str) -> str:
    for item in request_plan:
        if str(item).startswith(prefix + ":"):
            return str(item).split(":", 1)[1].strip()
    return ""
