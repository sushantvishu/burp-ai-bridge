from __future__ import annotations

from typing import Any


_IMPACT_TEMPLATES = {
    "idor": {
        "proof_level": "object-boundary confirmation",
        "next_step": "Confirm one cross-tenant or cross-user object access with the same endpoint and a clean role-separated diff.",
        "missing": "A stable two-account or two-tenant object comparison showing unauthorized access to a non-owned resource.",
        "severity_if_confirmed": "high",
        "report_sentence": "The issue crosses an authorization boundary by exposing another user's object data through the same endpoint without the intended ownership check.",
        "impact_ladder": [
            "Show a stable 403/200 or redacted/full-object delta for a second account.",
            "Capture the exact object fields exposed and whether the object is cross-tenant, privileged, or financially sensitive.",
            "Tie the object to a business function such as invoices, admin data, PII, balances, or workflow state.",
        ],
    },
    "bola": {
        "proof_level": "object-boundary confirmation",
        "next_step": "Confirm one API-level object access across tenants or user roles with the same token and a clean diff.",
        "missing": "A stable API role or tenant comparison that proves another actor's object is accessible.",
        "severity_if_confirmed": "high",
        "report_sentence": "The API permits access to another actor's object through the same operation, creating a broken object-level authorization condition.",
        "impact_ladder": [
            "Show the unauthorized object fetch or modification with a second actor.",
            "Map the object to a sensitive workflow, state change, or data exposure path.",
        ],
    },
    "xss": {
        "proof_level": "render-path confirmation",
        "next_step": "Confirm the payload reaches a meaningful viewer or privileged render path rather than only the submitter's preview flow.",
        "missing": "A reproducible render in a shared, privileged, or administrative viewer context.",
        "severity_if_confirmed": "high",
        "report_sentence": "The stored client-side execution reaches a higher-value viewer context, which turns a basic injection into a cross-user or privileged-session impact path.",
        "impact_ladder": [
            "Prove storage and render separately.",
            "Show the viewer role or workflow where execution occurs.",
            "Capture one bounded impact such as admin review, ticket queue, or cross-user content rendering.",
        ],
    },
    "stored-xss": {
        "proof_level": "render-path confirmation",
        "next_step": "Confirm render in a moderator, admin, or shared viewer workflow.",
        "missing": "A shared-view or privileged-view render artifact.",
        "severity_if_confirmed": "high",
        "report_sentence": "The stored payload executes in a privileged or shared-view workflow, converting basic storage into a stronger cross-user impact path.",
        "impact_ladder": [
            "Keep one clean storage proof.",
            "Capture the privileged or shared viewer render separately.",
            "Tie the viewer role to business impact or admin action exposure.",
        ],
    },
    "ssrf": {
        "proof_level": "backend fetch confirmation",
        "next_step": "Confirm one bounded internal reachability or callback artifact tied to the exact request variant.",
        "missing": "A callback, internal service fingerprint, or controlled internal target reachability signal.",
        "severity_if_confirmed": "high",
        "report_sentence": "The server can be induced to make backend-controlled requests, and the confirmed target reachability raises the issue from a URL handling flaw to an SSRF impact path.",
        "impact_ladder": [
            "Keep the baseline fetch proof.",
            "Tie the callback or internal reachability to one exact request variant.",
            "Show whether the reachable target is internal, metadata-related, or trust-boundary significant.",
        ],
    },
    "xxe": {
        "proof_level": "parser-controlled entity confirmation",
        "next_step": "Confirm one benign parser-controlled entity or outbound-resolution artifact tied to the same XML sink before claiming stronger backend impact.",
        "missing": "A bounded parser artifact showing external entity resolution, backend fetch, or controlled file-handling behavior on the same request family.",
        "severity_if_confirmed": "high",
        "report_sentence": "The XML parser behavior crosses the expected trust boundary by resolving or processing attacker-influenced XML structures in a way that supports a stronger backend impact path.",
        "impact_ladder": [
            "Separate plain XML handling from parser-controlled entity behavior.",
            "Capture the exact parser-controlled artifact on the same XML sink.",
            "Tie the parser behavior to one bounded backend fetch, file-handling, or privileged processing implication.",
        ],
    },
    "authentication": {
        "proof_level": "access-control bypass confirmation",
        "next_step": "Show one privileged endpoint or workflow action is reachable without the intended authentication or session control.",
        "missing": "A bounded privileged action or admin-only data access without the intended auth check.",
        "severity_if_confirmed": "critical",
        "report_sentence": "The issue bypasses an authentication or session boundary and exposes functionality that should require a stronger identity check.",
        "impact_ladder": [
            "Separate baseline access denial from bypassed access.",
            "Capture the exact privileged route or state change reached after bypass.",
            "Avoid broad privilege chaining unless the same control failure supports it.",
        ],
    },
    "session-management": {
        "proof_level": "session-boundary confirmation",
        "next_step": "Show one durable session or token-state failure that crosses the intended login, logout, or privilege boundary.",
        "missing": "A clean session-state artifact showing reuse, fixation, invalidation failure, or privilege confusion on the same workflow.",
        "severity_if_confirmed": "high",
        "report_sentence": "The session handling permits a stronger identity-boundary failure than a cosmetic cookie weakness by preserving or confusing session state across a protected workflow.",
        "impact_ladder": [
            "Separate the baseline session transition from the broken one.",
            "Capture the exact token, cookie, or logout boundary that fails.",
            "Tie the session flaw to one bounded protected route, user boundary, or privileged workflow.",
        ],
    },
    "auth-bypass": {
        "proof_level": "access-control bypass confirmation",
        "next_step": "Show one admin or otherwise restricted function is reachable after the bypass with a stable diff.",
        "missing": "A clean privileged-route or privileged-state artifact tied to the same bypass condition.",
        "severity_if_confirmed": "critical",
        "report_sentence": "The issue bypasses the intended access boundary and reaches functionality that should remain restricted to a higher-privilege actor.",
        "impact_ladder": [
            "Capture the restricted baseline denial.",
            "Capture the bypassed access or action with the same route.",
            "Describe the privileged workflow reached, not just the status-code change.",
        ],
    },
    "csrf": {
        "proof_level": "state-change confirmation",
        "next_step": "Show one meaningful state-changing action completes without a valid anti-CSRF control under the allowed victim context.",
        "missing": "A sensitive state change that occurs without a valid anti-CSRF protection signal.",
        "severity_if_confirmed": "medium",
        "report_sentence": "The issue permits a sensitive state-changing workflow to complete without the anti-CSRF protection the user would reasonably rely on.",
        "impact_ladder": [
            "Prove the action changes state.",
            "Show the absence or ineffectiveness of the anti-CSRF control.",
            "Tie the action to account, billing, recovery, or workflow significance.",
        ],
    },
    "mass-assignment": {
        "proof_level": "field-control confirmation",
        "next_step": "Show one unauthorized privileged or workflow-significant field can be accepted and persisted by the same endpoint.",
        "missing": "A field persistence artifact for a privileged, authorization-relevant, or workflow-sensitive attribute.",
        "severity_if_confirmed": "high",
        "report_sentence": "The endpoint accepts and persists fields outside the intended client-controlled set, creating a privilege or workflow manipulation condition.",
        "impact_ladder": [
            "Show the extra field is accepted.",
            "Show the field persists or changes behavior.",
            "Tie the field to role, trust, billing, approval, or account-control impact.",
        ],
    },
    "injection": {
        "proof_level": "interpreted sink confirmation",
        "next_step": "Show one stable interpreted backend effect tied to the same sink, then connect it to the strongest bounded data, auth, or workflow consequence.",
        "missing": "A reproducible interpreted-behavior artifact that proves the backend, query layer, or evaluator is influenced in a meaningful way.",
        "severity_if_confirmed": "high",
        "report_sentence": "The backend interprets attacker-controlled input in a way that creates a stronger trust-boundary consequence than a generic validation error or parser quirk.",
        "impact_ladder": [
            "Keep one clean baseline-vs-variant diff on the same sink.",
            "Prove the sink is interpreted rather than merely reflected or rejected.",
            "Tie the interpreted behavior to one bounded data exposure, authorization effect, or workflow consequence.",
        ],
    },
    "template-injection": {
        "proof_level": "template evaluation confirmation",
        "next_step": "Show one benign evaluation artifact on the same render surface, then tie it to the strongest bounded viewer or processing workflow.",
        "missing": "A stable evaluation artifact proving server-side template handling rather than reflection-only behavior.",
        "severity_if_confirmed": "high",
        "report_sentence": "The template surface evaluates attacker-controlled content in a way that reaches a stronger rendering or processing boundary than plain reflection alone.",
        "impact_ladder": [
            "Separate reflection from evaluation on the same template surface.",
            "Capture the exact benign evaluation artifact.",
            "Tie the evaluation sink to one bounded shared-view, privileged render, or processing consequence.",
        ],
    },
    "file-upload": {
        "proof_level": "file-handling confirmation",
        "next_step": "Show one meaningful post-upload effect such as parser execution, privileged retrieval, or storage in a sensitive path.",
        "missing": "A bounded post-upload impact artifact beyond simple file acceptance.",
        "severity_if_confirmed": "high",
        "report_sentence": "The upload control permits a file state or processing path that creates a stronger trust-boundary impact than simple upload acceptance alone.",
        "impact_ladder": [
            "Show acceptance separately from post-upload behavior.",
            "Capture the retrieval, parsing, or execution path clearly.",
            "Tie the path to trust-boundary impact, not only file type mismatch.",
        ],
    },
    "file-read": {
        "proof_level": "file-boundary confirmation",
        "next_step": "Show one bounded read or traversal effect on the same path family, then tie it to sensitive content or trust-boundary exposure.",
        "missing": "A controlled file-read or traversal artifact that proves access outside the intended path boundary.",
        "severity_if_confirmed": "high",
        "report_sentence": "The path handling crosses the intended file boundary and exposes content or processing paths that should remain inaccessible from the same request family.",
        "impact_ladder": [
            "Confirm the path boundary break with one bounded read effect.",
            "Capture the exact file or resource class exposed.",
            "Tie the exposure to sensitive content, configuration, or privileged workflow significance.",
        ],
    },
    "business-logic": {
        "proof_level": "workflow-control confirmation",
        "next_step": "Show one bounded business rule bypass that changes pricing, quota, approval, balance, or another meaningful workflow outcome.",
        "missing": "A stable before/after workflow artifact that proves the rule bypass changes the intended business outcome.",
        "severity_if_confirmed": "high",
        "report_sentence": "The issue bypasses an intended business control and changes a workflow outcome the application is supposed to enforce.",
        "impact_ladder": [
            "Define the intended workflow rule.",
            "Show the bypass and resulting changed outcome.",
            "Tie the changed outcome to financial, approval, quota, or trust impact.",
        ],
    },
    "deserialization": {
        "proof_level": "object-handling confirmation",
        "next_step": "Show one bounded object-handling or workflow effect tied to the same serialized sink before claiming broader backend impact.",
        "missing": "A reproducible object-handling artifact proving attacker-controlled data is reaching a privileged or stateful deserialization path.",
        "severity_if_confirmed": "high",
        "report_sentence": "The serialized object handling crosses an expected trust boundary and reaches a stronger backend or workflow consequence than simple input parsing alone.",
        "impact_ladder": [
            "Separate decoding or parsing from object rehydration or workflow handling.",
            "Capture one bounded object-handling artifact.",
            "Tie the sink to a privileged processing, data, or workflow consequence.",
        ],
    },
    "cors": {
        "proof_level": "cross-origin trust confirmation",
        "next_step": "Show one bounded origin-trust failure on a sensitive route or response, then tie it to readable data or state-changing reach.",
        "missing": "A clean origin-handling artifact that proves an untrusted origin can read sensitive data or drive a stronger protected workflow.",
        "severity_if_confirmed": "medium",
        "report_sentence": "The origin policy trusts a broader origin set than intended, exposing sensitive response data or protected workflows to a cross-origin caller.",
        "impact_ladder": [
            "Confirm the origin policy decision on the same sensitive route.",
            "Capture whether credentials, readable data, or protected actions are exposed.",
            "Tie the trust decision to one bounded cross-origin impact that matters to triage.",
        ],
    },
    "open-redirect": {
        "proof_level": "redirect-boundary confirmation",
        "next_step": "Show one redirect or forward crosses a meaningful trust boundary such as login, OAuth, or post-auth navigation rather than only an arbitrary URL change.",
        "missing": "A clean redirect artifact tied to a sensitive auth, token, or trust workflow on the same route family.",
        "severity_if_confirmed": "medium",
        "report_sentence": "The redirect handling crosses a stronger trust boundary than a cosmetic navigation issue by influencing an authentication, token, or trusted navigation workflow.",
        "impact_ladder": [
            "Separate open navigation from a trusted workflow boundary.",
            "Capture the exact redirect target and trust decision.",
            "Tie the redirect to one bounded authentication, token, or privileged navigation consequence.",
        ],
    },
    "secret-exposure": {
        "proof_level": "sensitive-data exposure confirmation",
        "next_step": "Show one stable exposure of a credential, token, configuration secret, or privileged internal value tied to the same request family.",
        "missing": "A reproducible artifact proving the exposed material is sensitive and reachable through the same workflow.",
        "severity_if_confirmed": "high",
        "report_sentence": "The response or resource handling exposes sensitive material that crosses an expected confidentiality boundary and supports a stronger reportable impact claim.",
        "impact_ladder": [
            "Confirm the exact secret or sensitive field exposure.",
            "Show why the exposed material is privileged, reusable, or confidentiality-significant.",
            "Tie the exposure to one bounded account, tenant, or infrastructure impact statement.",
        ],
    },
    "security-misconfiguration": {
        "proof_level": "misconfiguration confirmation",
        "next_step": "Tie the configuration weakness to one stronger trust-boundary or sensitive-data consequence on the same route or service.",
        "missing": "A reproducible artifact showing the misconfiguration enables a meaningful exposure or control failure rather than a checklist-only issue.",
        "severity_if_confirmed": "medium",
        "report_sentence": "The misconfiguration matters because it enables a clearer trust-boundary, exposure, or control-failure consequence than a low-value hardening gap alone.",
        "impact_ladder": [
            "Separate the configuration symptom from the actual security consequence.",
            "Capture one bounded exposure or trust-boundary artifact enabled by the misconfiguration.",
            "Keep the report focused on the resulting impact, not only the missing header or setting.",
        ],
    },
    "race-condition": {
        "proof_level": "concurrency-effect confirmation",
        "next_step": "Show one repeatable bounded workflow effect under minimal concurrency, then tie it to the strongest reversible business or privilege consequence.",
        "missing": "A stable timing or double-submit artifact showing the same workflow can be influenced by concurrency.",
        "severity_if_confirmed": "high",
        "report_sentence": "The workflow permits a repeatable concurrency window that changes the intended business or trust outcome under the same request family.",
        "impact_ladder": [
            "Capture the minimal concurrency window needed.",
            "Show the repeatable before/after workflow effect.",
            "Tie the effect to one bounded financial, approval, quota, or privilege consequence.",
        ],
    },
    "jwt-token": {
        "proof_level": "token-trust confirmation",
        "next_step": "Show one bounded token-verification or claims-trust failure tied to a protected route or workflow.",
        "missing": "A clean artifact proving token validation, signature handling, or trusted claims allow stronger access than intended.",
        "severity_if_confirmed": "high",
        "report_sentence": "The token handling trusts a broader identity boundary than intended, exposing protected routes, claims, or workflows to a stronger impact path.",
        "impact_ladder": [
            "Separate token parsing from trusted-claims use.",
            "Capture the exact protected route or role effect influenced by the token flaw.",
            "Tie the token-trust failure to one bounded privilege, data, or workflow impact.",
        ],
    },
    "graphql": {
        "proof_level": "schema or resolver boundary confirmation",
        "next_step": "Show one resolver, field, or operation crosses an auth, data, or workflow boundary more strongly than the baseline request.",
        "missing": "A reproducible GraphQL resolver or field artifact proving stronger unauthorized data, introspection, or workflow reach.",
        "severity_if_confirmed": "high",
        "report_sentence": "The GraphQL surface exposes a stronger resolver or schema-boundary consequence than a generic query issue by crossing an auth, data, or workflow control.",
        "impact_ladder": [
            "Keep the same operation or field family anchored.",
            "Capture the exact resolver or field boundary that fails.",
            "Tie the GraphQL behavior to one bounded data, privilege, or workflow impact.",
        ],
    },
    "cache": {
        "proof_level": "cache-boundary confirmation",
        "next_step": "Show one cache decision exposes cross-user data, stale protected content, or a stronger trust-boundary confusion on the same route family.",
        "missing": "A stable cache artifact proving the route serves the wrong user, role, or state context.",
        "severity_if_confirmed": "high",
        "report_sentence": "The cache handling crosses a trust boundary by serving protected or wrong-context content beyond the intended requester scope.",
        "impact_ladder": [
            "Confirm the cache artifact with the same route and vary conditions.",
            "Capture the wrong-context content, headers, or stale protected response.",
            "Tie the cache flaw to one bounded cross-user, auth, or workflow consequence.",
        ],
    },
}


def build_impact_upgrade_planner(
    vuln_class: str,
    *,
    validation: dict | None = None,
    impact: dict | None = None,
    severity: dict | None = None,
) -> dict[str, Any]:
    normalized = _normalize_class(vuln_class)
    template = _IMPACT_TEMPLATES.get(normalized, _default_template(normalized))
    validation = validation or {}
    impact = impact or {}
    severity = severity or {}
    current_proof = _current_proof_level(validation, impact, template)
    return {
        "vuln_class": normalized,
        "current_proof_level": current_proof,
        "next_strongest_allowed_step": template["next_step"],
        "missing_artifact_for_upgrade": template["missing"],
        "likely_severity_if_confirmed": severity.get("severity") or template["severity_if_confirmed"],
        "report_ready_impact_sentence": _program_tailored_sentence(
            template["report_sentence"],
            normalized,
            platform="",
        ),
        "impact_ladder": list(template["impact_ladder"])[:5],
    }


def build_reportability_gate(
    vuln_class: str,
    *,
    validation: dict | None = None,
    impact: dict | None = None,
) -> dict[str, Any]:
    normalized = _normalize_class(vuln_class)
    validation = validation or {}
    impact = impact or {}
    proven = []
    inferred = []
    unsafe = []

    hypothesis = validation.get("hypothesis") or {}
    if (validation.get("validation_status") or "").strip().lower() in {"confirmed", "high-signal"}:
        proven.append(hypothesis.get("summary") or f"The {normalized} condition is confirmed with bounded evidence.")
    else:
        inferred.append(hypothesis.get("summary") or f"The {normalized} condition is still partly inferred.")

    for item in (impact.get("business_impact_expansion_paths") or [])[:2]:
        inferred.append(item)
    for item in (impact.get("required_evidence_for_upgrade") or [])[:2]:
        unsafe.append(f"Do not claim this yet without: {item}")

    if not impact.get("reportable"):
        unsafe.append("Do not claim a stronger business-impact statement until the current reportability gate is met.")
    if (impact.get("confirmation_state") or "").strip().lower() == "needs-confirmation":
        unsafe.append("Do not present the impact path as proven while confirmation is still incomplete.")

    if not proven:
        proven.append("The baseline observation and deterministic context are captured, but the stronger impact claim is not fully proven yet.")

    return {
        "already_proven": proven[:4],
        "still_inferred": inferred[:4],
        "unsafe_to_claim_yet": unsafe[:4],
    }


def build_submission_value_score(
    *,
    validation: dict | None = None,
    impact: dict | None = None,
    severity: dict | None = None,
    policy_gate: dict | None = None,
    platform: str = "",
) -> dict[str, Any]:
    validation = validation or {}
    impact = impact or {}
    severity = severity or {}
    policy_gate = policy_gate or {}

    reproducibility = 0.85 if (validation.get("validation_status") or "").strip().lower() in {"confirmed", "high-signal"} else 0.55
    impact_clarity = 0.85 if (impact.get("business_impact_class") or "").strip().lower() == "high-impact" else 0.68 if impact.get("reportable") else 0.45
    evidence_score = float(validation.get("evidence_score", 0.0) or 0.0)
    evidence_completeness = min(1.0, evidence_score / 3.5)
    policy_safety = 0.95 if not policy_gate.get("effective_applies", policy_gate.get("applies")) or policy_gate.get("effective_allowed", policy_gate.get("allowed", True)) else 0.4
    triage_acceptance = 0.82 if severity.get("severity") in {"high", "critical"} and impact.get("reportable") else 0.64 if impact.get("reportability") in {"medium", "high"} else 0.45
    platform_details = _platform_submission_adjustment((platform or "generic").strip().lower(), impact, severity)
    total = round(
        (
            reproducibility
            + impact_clarity
            + evidence_completeness
            + policy_safety
            + triage_acceptance
        ) / 5.0,
        3,
    )
    total = max(0.0, min(1.0, round(total + platform_details["adjustment"], 3)))
    return {
        "score": total,
        "platform": (platform or "generic").strip().lower() or "generic",
        "components": {
            "reproducibility": round(reproducibility, 3),
            "impact_clarity": round(impact_clarity, 3),
            "evidence_completeness": round(evidence_completeness, 3),
            "policy_safety": round(policy_safety, 3),
            "likely_triage_acceptance": round(triage_acceptance, 3),
        },
        "platform_adjustment": platform_details["adjustment"],
        "platform_notes": platform_details["notes"],
        "summary": _submission_value_summary(total),
    }


def build_program_specific_impact_wording(platform: str, vuln_class: str, impact: dict | None = None) -> dict[str, str]:
    normalized_platform = (platform or "generic").strip().lower()
    normalized_class = _normalize_class(vuln_class)
    emphasis = _platform_emphasis(normalized_platform, normalized_class, impact or {})
    return {
        "platform": normalized_platform,
        "focus": emphasis["focus"],
        "wording": emphasis["wording"],
    }


def build_finding_to_impact_template(vuln_class: str) -> dict[str, Any]:
    normalized = _normalize_class(vuln_class)
    template = _IMPACT_TEMPLATES.get(normalized, _default_template(normalized))
    return {
        "vuln_class": normalized,
        "proof_level": template["proof_level"],
        "impact_ladder": list(template["impact_ladder"])[:5],
        "report_ready_impact_sentence": template["report_sentence"],
    }


def _normalize_class(vuln_class: str) -> str:
    normalized = (vuln_class or "general").strip().lower()
    aliases = {
        "authorization": "idor",
        "access-control": "idor",
        "broken-access-control": "idor",
        "bola": "idor",
        "stored xss": "stored-xss",
        "stored_xss": "stored-xss",
        "auth bypass": "auth-bypass",
        "auth_bypass": "auth-bypass",
        "auth": "authentication",
        "session": "session-management",
        "session management": "session-management",
        "file upload": "file-upload",
        "path-traversal": "file-read",
        "path traversal": "file-read",
        "lfi": "file-read",
        "rfi": "file-read",
        "sqli": "injection",
        "sql-injection": "injection",
        "sql injection": "injection",
        "ssti": "template-injection",
        "server-side-template-injection": "template-injection",
        "server side template injection": "template-injection",
        "business logic": "business-logic",
        "xxe injection": "xxe",
        "open redirect": "open-redirect",
        "secret exposure": "secret-exposure",
        "security misconfiguration": "security-misconfiguration",
        "jwt": "jwt-token",
        "web cache poisoning": "cache",
        "web-cache-poisoning": "cache",
        "cache-poisoning": "cache",
        "cache-deception": "cache",
    }
    return aliases.get(normalized, normalized or "general")


def _default_template(vuln_class: str) -> dict[str, Any]:
    return {
        "proof_level": "bounded confirmation",
        "next_step": f"Capture one bounded, reproducible impact artifact that raises the {vuln_class} finding above a baseline confirmation.",
        "missing": "A cleaner impact artifact tied to the same request family.",
        "severity_if_confirmed": "medium",
        "report_sentence": f"The confirmed {vuln_class} behavior should be tied to a reproducible business-impact effect before stronger severity wording is used.",
        "impact_ladder": [
            "Keep one baseline proof.",
            "Add one higher-value impact artifact.",
            "Tie the effect to a business workflow or trust boundary.",
        ],
    }


def _current_proof_level(validation: dict, impact: dict, template: dict[str, Any]) -> str:
    status = (validation.get("validation_status") or "").strip().lower()
    if status in {"confirmed", "high-signal"} and impact.get("reportable"):
        return f"{template['proof_level']} with a reportable impact path"
    if status in {"confirmed", "high-signal"}:
        return template["proof_level"]
    return "baseline confirmation only"


def _program_tailored_sentence(sentence: str, vuln_class: str, platform: str) -> str:
    wording = build_program_specific_impact_wording(platform, vuln_class)
    return f"{sentence} Focus the report on {wording['focus']}."


def _platform_emphasis(platform: str, vuln_class: str, impact: dict[str, Any]) -> dict[str, str]:
    impact_class = (impact.get("business_impact_class") or "").strip().lower()
    if vuln_class in {"idor", "bola"}:
        focus = "cross-tenant data exposure and privilege boundary break"
    elif vuln_class in {"stored-xss", "xss"}:
        focus = "privileged viewer impact or shared-workflow execution"
    elif vuln_class == "csrf":
        focus = "meaningful state change without user intent"
    elif vuln_class == "mass-assignment":
        focus = "privilege or workflow-significant field control"
    elif vuln_class == "ssrf":
        focus = "backend trust-boundary reachability"
    elif vuln_class in {"authentication", "auth-bypass"}:
        focus = "privileged access without the intended identity control"
    elif vuln_class == "file-upload":
        focus = "post-upload trust-boundary impact"
    elif vuln_class == "business-logic":
        focus = "changed business outcome rather than raw input manipulation"
    elif vuln_class == "template-injection":
        focus = "server-side evaluation on a privileged render or processing path"
    elif vuln_class == "injection":
        focus = "interpreted backend behavior tied to data, auth, or workflow impact"
    elif vuln_class == "xxe":
        focus = "parser-driven backend trust-boundary crossing"
    elif vuln_class == "file-read":
        focus = "sensitive content reachable beyond the intended path boundary"
    elif vuln_class == "deserialization":
        focus = "privileged object handling or workflow control"
    elif vuln_class == "cors":
        focus = "cross-origin trust applied to sensitive data or protected workflows"
    elif vuln_class == "open-redirect":
        focus = "trusted navigation or auth-flow boundary misuse"
    elif vuln_class == "secret-exposure":
        focus = "sensitive material that meaningfully crosses a confidentiality boundary"
    elif vuln_class == "security-misconfiguration":
        focus = "the concrete security consequence enabled by the misconfiguration"
    elif vuln_class == "race-condition":
        focus = "repeatable workflow impact under bounded concurrency"
    elif vuln_class == "jwt-token":
        focus = "trusted identity or claims boundary failure"
    elif vuln_class == "graphql":
        focus = "resolver- or field-level boundary failure"
    elif vuln_class == "cache":
        focus = "protected content served across the wrong trust boundary"
    else:
        focus = "the clearest bounded business impact"

    if platform == "hackerone":
        wording = f"Frame the impact as {focus}, with a short reproducible proof and one explicit boundary broken."
    elif platform == "bugcrowd":
        wording = f"Emphasize {focus} and the exact artifact that makes the issue reproducible and triage-friendly."
    elif platform == "intigriti":
        wording = f"Keep the wording concise around {focus}, with clear severity support and minimal speculative language."
    else:
        wording = f"Describe {focus} with one direct proof artifact and avoid generic severity phrasing."

    if impact_class == "high-impact":
        wording += " The current impact class already supports stronger business framing if the evidence bundle stays clean."
    return {"focus": focus, "wording": wording}


def _submission_value_summary(score: float) -> str:
    if score >= 0.8:
        return "Strong submission candidate with good triage value."
    if score >= 0.65:
        return "Promising submission, but one stronger artifact or cleaner wording would improve value."
    return "Keep the finding in evidence-building mode before prioritizing it for submission."


def _platform_submission_adjustment(platform: str, impact: dict[str, Any], severity: dict[str, Any]) -> dict[str, Any]:
    normalized_platform = (platform or "generic").strip().lower()
    adjustment = 0.0
    notes: list[str] = []
    if normalized_platform == "bugcrowd":
        if impact.get("reportable"):
            adjustment += 0.03
        notes.append("Bugcrowd favors clean reproducibility and direct proof artifacts.")
    elif normalized_platform == "hackerone":
        if severity.get("severity") in {"high", "critical"}:
            adjustment += 0.03
        notes.append("HackerOne triage benefits from concise boundary-break wording and a stable proof path.")
    elif normalized_platform == "intigriti":
        if (impact.get("business_impact_class") or "").strip().lower() == "high-impact":
            adjustment += 0.02
        notes.append("Intigriti reports benefit from concise impact framing with limited speculation.")
    else:
        notes.append("Generic scoring keeps the emphasis on reproducibility, evidence completeness, and policy safety.")
    return {"adjustment": round(adjustment, 3), "notes": notes[:2]}
