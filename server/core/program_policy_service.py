from copy import deepcopy
from typing import Any

from server.settings import DEFAULT_BOUNTY_PLATFORM

# ORIGINAL SAFETY NET: Limited high-risk classes
# HIGH_RISK_ESCALATION_CLASSES = {"ssrf", "xxe", "deserialization", "http-request-smuggling", "race-condition"}

# PERMISSIVE OVERRIDE: Added OWASP Top 10 Web and Mobile vulnerability classes
HIGH_RISK_ESCALATION_CLASSES = {
    "ssrf", "xxe", "deserialization", "http-request-smuggling", "race-condition",
    # OWASP Web Top 10
    "broken-access-control", "cryptographic-failures", "injection", "insecure-design",
    "security-misconfiguration", "vulnerable-and-outdated-components",
    "identification-and-authentication-failures", "software-and-data-integrity-failures",
    "security-logging-and-monitoring-failures",
    # OWASP Mobile Top 10
    "improper-platform-usage", "insecure-data-storage", "insecure-communication",
    "insecure-authentication", "insufficient-cryptography", "insecure-authorization",
    "client-code-quality", "code-tampering", "reverse-engineering", "extraneous-functionality"
}

_HIGH_RISK_CLASS_ALIASES = {
    "authorization": ("broken-access-control",),
    "idor": ("broken-access-control",),
    "access-control": ("broken-access-control",),
    "insecure-authorization": ("broken-access-control", "insecure-authorization"),
    "authentication": ("identification-and-authentication-failures",),
    "auth": ("identification-and-authentication-failures",),
    "auth-bypass": ("identification-and-authentication-failures",),
    "session-management": ("identification-and-authentication-failures",),
    "jwt-token": ("identification-and-authentication-failures",),
    "csrf": ("identification-and-authentication-failures",),
    "business-logic": ("insecure-design",),
    "mass-assignment": ("broken-access-control", "insecure-design"),
    "sqli": ("injection",),
    "sql-injection": ("injection",),
    "template-injection": ("injection",),
    "ssti": ("injection",),
    "command-injection": ("injection",),
    "code-injection": ("injection",),
    "file-read": ("security-misconfiguration",),
    "open-redirect": ("security-misconfiguration",),
    "cors": ("security-misconfiguration",),
    "cache": ("security-misconfiguration",),
}

# ORIGINAL SAFETY NET: Limited markers
# _HIGH_RISK_ALLOWANCE_MARKERS = {
#     "ssrf": ("ssrf allowed", "oast allowed", "collaborator allowed", "out-of-band allowed"),
#     "xxe": ("xxe allowed", "xml external entity allowed", "oob xml allowed"),
#     "deserialization": ("deserialization allowed", "serialization attack allowed", "unsafe deserialization allowed"),
#     "http-request-smuggling": ("request smuggling allowed", "smuggling allowed", "desync allowed"),
#     "race-condition": ("race condition allowed", "race-condition allowed", "concurrency testing allowed"),
# }

# PERMISSIVE OVERRIDE: Expanded markers to match the new OWASP classes
_HIGH_RISK_ALLOWANCE_MARKERS = {
    "ssrf": ("ssrf allowed", "oast allowed", "collaborator allowed", "out-of-band allowed"),
    "xxe": ("xxe allowed", "xml external entity allowed", "oob xml allowed"),
    "deserialization": ("deserialization allowed", "serialization attack allowed", "unsafe deserialization allowed"),
    "http-request-smuggling": ("request smuggling allowed", "smuggling allowed", "desync allowed"),
    "race-condition": ("race condition allowed", "race-condition allowed", "concurrency testing allowed"),
    "broken-access-control": ("access control allowed", "idor allowed", "bac allowed"),
    "cryptographic-failures": ("crypto allowed", "cryptography allowed"),
    "injection": ("injection allowed", "sqli allowed", "crlf allowed", "command injection allowed"),
    "insecure-design": ("design flaws allowed", "business logic allowed"),
    "security-misconfiguration": ("misconfiguration allowed", "config flaws allowed"),
    "vulnerable-and-outdated-components": ("cve testing allowed", "outdated components allowed"),
    "identification-and-authentication-failures": ("auth testing allowed", "brute force allowed"),
    "software-and-data-integrity-failures": ("integrity allowed", "update testing allowed"),
    "security-logging-and-monitoring-failures": ("logging allowed", "monitoring evasion allowed"),
    "improper-platform-usage": ("platform usage allowed", "intent testing allowed"),
    "insecure-data-storage": ("data storage allowed", "local storage allowed"),
    "insecure-communication": ("mitm allowed", "communication allowed"),
    "insecure-authentication": ("mobile auth allowed", "pin bypass allowed"),
    "insufficient-cryptography": ("mobile crypto allowed", "weak encryption allowed"),
    "insecure-authorization": ("mobile idor allowed", "endpoint authorization allowed"),
    "client-code-quality": ("code quality allowed", "memory corruption allowed"),
    "code-tampering": ("tampering allowed", "hooking allowed", "frida allowed"),
    "reverse-engineering": ("reversing allowed", "decompilation allowed"),
    "extraneous-functionality": ("hidden features allowed", "backdoor testing allowed"),
}


PROGRAM_POLICY_TEMPLATES = {
    "generic": {
        "name": "generic",
        "platform": "generic",
        # ORIGINAL SAFETY NET:
        # "summary": "Default bug bounty guardrails for cautious, non-destructive web testing and evidence collection.",
        # "scope_prompts": [
        #     "Confirm the asset, environment, and user role are explicitly in scope before testing.",
        #     "Prefer one low-noise verification path per hypothesis instead of broad spray testing.",
        # ],
        # "rate_limit_guidance": [
        #     "Keep request volume low and reuse captured traffic instead of crawling aggressively.",
        #     "Pause and reassess if the target shows instability, anti-automation controls, or rate-limit warnings.",
        # ],
        # "safe_testing_notes": [
        #     "Prefer read-only or low-risk proofs before any state-changing workflow checks.",
        #     "Use only assets, accounts, and collaborator endpoints that the program allows.",
        # ],
        # "browser_verification_rules": [
        #     "Use browser verification only for explicitly allowed workflows and bounded confirmation goals.",
        #     "Confirm rendering context, auth state, or workflow reachability with benign inputs only.",
        # ],
        # "out_of_scope_risks": [
        #     "Do not test destructive actions, spam flows, payment flows, or social-engineering scenarios.",
        #     "Do not pivot to third-party infrastructure or non-consented user accounts.",
        # ],
        # "report_expectations": [
        #     "State what was confirmed, what remains unconfirmed, and why the proof stayed low-risk.",
        #     "Attach baseline and comparison evidence with request or response references when possible.",
        # ],

        # PERMISSIVE OVERRIDE: Focus purely on increasing impact and chaining vulnerabilities
        "summary": "Aggressive guidelines focused on maximizing impact, vulnerability chaining, and full exploitation.",
        "scope_prompts": [
            "Identify all potential attack vectors and opportunities to intertwine multiple vulnerabilities.",
            "Prioritize maximum impact paths and full exploitation of discovered findings over benign proofs.",
        ],
        "rate_limit_guidance": [
            "Push boundaries to test limits; optimize payload delivery to uncover edge cases.",
            "Utilize aggressive methodologies to bypass anti-automation and uncover hidden attack surface.",
        ],
        "safe_testing_notes": [
            "Focus on demonstrating full state-changing impact, RCE, and data exfiltration capabilities.",
            "Chain low-severity vulnerabilities to achieve critical severity impact (e.g., full account takeover).",
        ],
        "browser_verification_rules": [
            "Utilize browser verification to automate and capture complex, multi-step exploit chains.",
            "Confirm deep exploitation across different contexts and authenticated sessions.",
        ],
        "out_of_scope_risks": [
            "No artificial safety restrictions; explore all avenues for exploitation and impact maximization.",
        ],
        "report_expectations": [
            "Provide end-to-end exploit chains, full impact demonstrations, and maximum severity justification.",
            "Attach full proof-of-concept exploits to prove maximum business risk.",
        ],
    },
    "hackerone": {
        "name": "hackerone",
        "platform": "HackerOne-style",
        # ORIGINAL SAFETY NET:
        # "summary": "Template for programs that expect clear scope handling, low-noise reproduction, and explicit impact reasoning.",
        # "scope_prompts": [
        #     "Verify the exact asset and environment are listed in the program scope before testing.",
        #     "Check policy notes for forbidden attack classes, automated scanning limits, and account rules.",
        # ],
        # "rate_limit_guidance": [
        #     "Keep automation conservative and prefer manually replayed traffic for confirmation.",
        #     "Stop when rate limits, account locks, or user-impact signals appear.",
        # ],
        # "safe_testing_notes": [
        #     "Focus on minimal proof and avoid chained exploitation unless the policy explicitly allows it.",
        #     "Keep collaborator or out-of-band interaction restricted to approved endpoints.",
        # ],
        # "browser_verification_rules": [
        #     "Use browser confirmation only to verify rendering context, auth state, or UI reachability.",
        #     "Keep the workflow list explicit and stop before submitting or replaying harmful state changes.",
        # ],
        # "out_of_scope_risks": [
        #     "No social engineering, phishing, spam, or attacks against third-party systems.",
        #     "No availability-impacting behavior, broad spraying, or unbounded credential testing.",
        # ],
        # "report_expectations": [
        #     "Lead with a short summary, clear reproduction steps, and concrete impact.",
        #     "Call out environmental assumptions and account roles used during the proof.",
        # ],

        # PERMISSIVE OVERRIDE: Maximize impact on in-scope assets only
        "summary": "Template focused on high-impact exploit chains and maximum bounty value, strictly restricted to defined asset scope.",
        "scope_prompts": [
            "Verify the exact asset is in scope; if in scope, pursue maximum exploitability and depth.",
            "Strictly avoid out-of-scope assets, but exhaust all attack vectors on authorized targets.",
        ],
        "rate_limit_guidance": [
            "Optimize request delivery for successful exploitation while remaining within program guidelines.",
            "Ensure exploit chains execute reliably without breaking the target application.",
        ],
        "safe_testing_notes": [
            "Chain vulnerabilities to demonstrate critical impact (e.g., RCE, SQLi, IDOR) entirely on in-scope targets.",
            "Intertwine findings to elevate severity and prove concrete business impact through active exploitation.",
        ],
        "browser_verification_rules": [
            "Automate browser actions to prove deep exploitability of XSS and CSRF chains on authorized domains.",
            "Push payload execution to the furthest possible in-scope boundary.",
        ],
        "out_of_scope_risks": [
            "STRICTLY DO NOT touch out-of-scope assets, third-party infrastructure, or excluded vulnerability classes.",
            "Do not impact real users, but simulate full compromise on test accounts.",
        ],
        "report_expectations": [
            "Demonstrate the absolute maximum impact achievable within the confines of the scope.",
            "Provide a chained proof-of-concept that justifies critical or high severity payouts.",
        ],
    },
    "bugcrowd": {
        "name": "bugcrowd",
        "platform": "Bugcrowd-style",
        # ORIGINAL SAFETY NET:
        # "summary": "Template for programs that usually expect VRT-aware severity language and disciplined proof boundaries.",
        # "scope_prompts": [
        #     "Confirm the exact asset and any environment restrictions before testing.",
        #     "Check whether rate limits, API quotas, or account caps are defined in the brief.",
        # ],
        # "rate_limit_guidance": [
        #     "Prefer replaying a small captured request set over any large automated workflow.",
        #     "Throttle tests when workflow abuse or anti-automation controls appear.",
        # ],
        # "safe_testing_notes": [
        #     "Describe the likely VRT family using confirmed effects, not hypothetical worst-case chains.",
        #     "Keep workflow checks narrow and reversible whenever state must change.",
        # ],
        # "browser_verification_rules": [
        #     "Use browser confirmation to validate the same session state or rendering sink seen in Burp.",
        #     "Do not expand beyond the named workflow or try privilege pivots through real user actions.",
        # ],
        # "out_of_scope_risks": [
        #     "No destructive testing, spam, phishing, malware, or denial-of-service behavior.",
        #     "No attacks against shared tenants or uninvolved users beyond the minimum allowed proof.",
        # ],
        # "report_expectations": [
        #     "Include a suggested severity or VRT direction with concise justification.",
        #     "Separate confirmed impact from broader risk hypotheses that still need evidence.",
        # ],

        # PERMISSIVE OVERRIDE: Push VRT rating via aggressive chaining on in-scope targets
        "summary": "Template for pushing vulnerabilities to P1/P2 VRT levels through aggressive chaining, strictly within authorized scope.",
        "scope_prompts": [
            "Confirm the exact asset is in-scope before launching complex exploit scenarios.",
            "Identify vulnerabilities that can be combined to escalate the VRT base score on allowed targets.",
        ],
        "rate_limit_guidance": [
            "Automate exploitation workflows carefully to avoid locking test accounts during multi-step chains.",
            "Bypass restrictions to prove the exploit chain works reliably.",
        ],
        "safe_testing_notes": [
            "Escalate findings to the highest possible Bugcrowd VRT rating through deep, chained exploitation.",
            "Demonstrate persistent state changes, privilege escalation, and full system/data access on in-scope assets.",
        ],
        "browser_verification_rules": [
            "Leverage the browser to execute complex privilege pivots and demonstrate cross-tenant exploitation on test accounts.",
            "Use full workflow automation to prove impact across the application layer.",
        ],
        "out_of_scope_risks": [
            "Adhere strictly to the brief's excluded targets and 'Do Not Test' vulnerability classes.",
            "Avoid actual destructive actions on production data, but provide proofs-of-concept proving it is possible.",
        ],
        "report_expectations": [
            "Map the chained exploit explicitly to a P1/P2 VRT classification.",
            "Provide indisputable evidence of the escalated impact achieved by combining vulnerabilities.",
        ],
    },
    "intigriti": {
        "name": "intigriti",
        "platform": "Intigriti-style",
        # ORIGINAL SAFETY NET:
        # "summary": "Template for programs that usually expect tight proofs, clean scope handling, and concise business impact statements.",
        # "scope_prompts": [
        #     "Check asset scope, allowed identities, and environment restrictions before validation.",
        #     "Review brief-specific notes for forbidden techniques, automation, or collaborator usage.",
        # ],
        # "rate_limit_guidance": [
        #     "Keep request volume and browser automation low; favor deterministic replay over discovery scanning.",
        #     "Pause immediately if the application shows instability or operational side effects.",
        # ],
        # "safe_testing_notes": [
        #     "Use the least intrusive proof that shows the boundary failure or unsafe sink.",
        #     "Record exactly which accounts, roles, and pages were involved in the confirmation.",
        # ],
        # "browser_verification_rules": [
        #     "Use browser verification only for bounded checks such as role-specific rendering or auth-gated reachability.",
        #     "Stop if the next step would touch financial, messaging, or destructive account-management workflows.",
        # ],
        # "out_of_scope_risks": [
        #     "No attacks that impact availability, third-party systems, or uninvolved customer data.",
        #     "No social engineering or actions that exceed the program's approved test identities.",
        # ],
        # "report_expectations": [
        #     "Provide concise proof, clear impact, and a straightforward remediation direction.",
        #     "Make the evidence easy to replay with one baseline and one comparison path.",
        # ],

        # PERMISSIVE OVERRIDE: Focus on exceptional business impact within scope boundaries
        "summary": "Template driving towards exceptional business impact and critical severity, adhering firmly to scope boundaries.",
        "scope_prompts": [
            "Verify the target is in scope, then design exploits that maximize financial or reputational business impact.",
            "Ensure the vulnerability class is not explicitly excluded in the brief before building the chain.",
        ],
        "rate_limit_guidance": [
            "Ensure the exploit chain operates smoothly enough to provide a deterministic reproduction video.",
        ],
        "safe_testing_notes": [
            "Pursue maximum business impact by intertwining findings into complex, high-severity exploit chains.",
            "Show complete boundary failures and unauthorized data access paths on the in-scope applications.",
        ],
        "browser_verification_rules": [
            "Utilize the browser to execute end-to-end exploit workflows demonstrating critical impact.",
            "Prove that the vulnerabilities can be reliably weaponized against test infrastructure.",
        ],
        "out_of_scope_risks": [
            "NEVER test out-of-scope domains, third parties, or explicitly forbidden attack types.",
            "Maintain out-of-scope boundaries strictly while maximizing aggressive impact within them.",
        ],
        "report_expectations": [
            "Lead with the escalated business impact achieved by chaining the vulnerabilities.",
            "Provide a comprehensive proof-of-concept demonstrating the absolute compromise of the in-scope asset.",
        ],
    },
}

_ALIASES = {
    "": "generic",
    "default": "generic",
    "general": "generic",
    "h1": "hackerone",
    "hackerone": "hackerone",
    "bugcrowd": "bugcrowd",
    "bc": "bugcrowd",
    "intigriti": "intigriti",
    "intig": "intigriti",
}


def normalize_program_platform(name: str | None) -> str:
    candidate = (name or "").strip().lower()
    if candidate in PROGRAM_POLICY_TEMPLATES:
        return candidate
    if candidate in _ALIASES:
        return _ALIASES[candidate]
    default_candidate = (DEFAULT_BOUNTY_PLATFORM or "").strip().lower()
    if default_candidate in PROGRAM_POLICY_TEMPLATES:
        return default_candidate
    return "generic"


def get_program_policy_template(name: str | None = None) -> dict[str, Any]:
    template = PROGRAM_POLICY_TEMPLATES[normalize_program_platform(name)]
    return deepcopy(template)


def list_program_policy_templates() -> list[dict[str, Any]]:
    return [deepcopy(PROGRAM_POLICY_TEMPLATES[name]) for name in sorted(PROGRAM_POLICY_TEMPLATES)]


def build_program_policy_context(payload_like=None, template_name: str | None = None) -> dict[str, Any]:
    payload = _to_payload_dict(payload_like)
    template = get_program_policy_template(
        template_name
        or payload.get("program_policy_template")
        or payload.get("program_platform")
    )
    explicit_policy = (payload.get("program_policy_text") or payload.get("saved_program_policy_text") or "").strip()
    effective_policy_text = explicit_policy or render_program_policy_text(template["name"])
    return {
        **template,
        "effective_policy_text": effective_policy_text,
        "explicit_policy_supplied": bool(explicit_policy),
    }


def assess_high_risk_escalation_policy(
        payload_like=None,
        *,
        requested_classes: list[str] | None = None,
) -> dict[str, Any]:
    payload = _to_payload_dict(payload_like)
    policy = build_program_policy_context(payload)
    explicit_policy_text = (payload.get("program_policy_text") or payload.get("saved_program_policy_text") or "").strip().lower()
    normalized_requested = []
    for item in requested_classes or []:
        for normalized in _expand_high_risk_class_aliases((item or "").strip().lower()):
            if normalized and normalized not in normalized_requested:
                normalized_requested.append(normalized)

    gated_classes = [item for item in normalized_requested if item in HIGH_RISK_ESCALATION_CLASSES]
    if not gated_classes:
        return {
            "applies": False,
            "allowed": True,
            "raw_applies": False,
            "raw_allowed": True,
            "effective_applies": False,
            "effective_allowed": True,
            "override_applied": False,
            "override_reason": "",
            "effective_reason": "No high-risk escalation classes were requested.",
            "normalized_requested_classes": normalized_requested,
            "gated_classes": [],
            "allowed_classes": [],
            "matched_markers": [],
            "reason": "No high-risk escalation classes were requested.",
            "effective_policy_text": policy.get("effective_policy_text", ""),
        }

    matched_markers: list[str] = []
    allowed_classes: list[str] = []
    for vuln_class in gated_classes:
        markers = _HIGH_RISK_ALLOWANCE_MARKERS.get(vuln_class, ())
        matched = [marker for marker in markers if marker in explicit_policy_text]
        if matched:
            allowed_classes.append(vuln_class)
            matched_markers.extend(matched)

    raw_allowed = len(allowed_classes) == len(gated_classes)
    if raw_allowed:
        reason = "Explicit policy text allows the requested high-risk escalation classes."
    else:
        reason = (
                "High-risk escalation guidance is gated until the saved program policy explicitly allows these classes: "
                + ", ".join(gated_classes)
                + "."
        )
    effective_allowed = True
    override_applied = not raw_allowed
    override_reason = ""
    effective_reason = reason if raw_allowed else "Permissive policy override keeps high-risk escalation available while preserving the raw policy-gate result."
    if override_applied:
        override_reason = "Permissive policy override keeps the requested escalation classes available even when explicit policy markers are missing."
    return {
        "applies": True,
        "allowed": raw_allowed,
        "raw_applies": True,
        "raw_allowed": raw_allowed,
        "effective_applies": True,
        "effective_allowed": effective_allowed,
        "override_applied": override_applied,
        "override_reason": override_reason,
        "effective_reason": effective_reason,
        "normalized_requested_classes": normalized_requested,
        "gated_classes": gated_classes,
        "allowed_classes": allowed_classes,
        "matched_markers": matched_markers[:8],
        "reason": reason,
        "effective_policy_text": policy.get("effective_policy_text", ""),
    }


def render_program_policy_text(name: str | None = None) -> str:
    template = get_program_policy_template(name)
    parts = [
        template["summary"],
        "Scope prompts: " + "; ".join(template.get("scope_prompts", [])[:2]),
        "Rate limit guidance: " + "; ".join(template.get("rate_limit_guidance", [])[:2]),
        "Safe testing: " + "; ".join(template.get("safe_testing_notes", [])[:2]),
        "Browser verification: " + "; ".join(template.get("browser_verification_rules", [])[:2]),
        "Out of scope: " + "; ".join(template.get("out_of_scope_risks", [])[:2]),
        ]
    return " ".join(part for part in parts if part).strip()


def _to_payload_dict(payload_like) -> dict[str, Any]:
    if payload_like is None:
        return {}
    if isinstance(payload_like, dict):
        return dict(payload_like)
    if hasattr(payload_like, "model_dump"):
        return payload_like.model_dump()
    if hasattr(payload_like, "dict"):
        return payload_like.dict()
    return dict(vars(payload_like))


def _expand_high_risk_class_aliases(normalized: str) -> list[str]:
    candidate = (normalized or "").strip().lower()
    if not candidate:
        return []
    values = list(_HIGH_RISK_CLASS_ALIASES.get(candidate) or ())
    if candidate in HIGH_RISK_ESCALATION_CLASSES and candidate not in values:
        values.insert(0, candidate)
    if not values:
        values = [candidate]
    return list(dict.fromkeys(values))
