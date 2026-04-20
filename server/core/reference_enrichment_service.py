from typing import Any

from server.core.escalation_service import build_escalation_guidance, normalize_vuln_class
from server.settings import INTERNET_REFERENCE_ENRICHMENT_ENABLED, INTERNET_REFERENCE_MODE

_CURATED_REFERENCE_MAP = {
    "authorization": [
        "https://portswigger.net/web-security/access-control",
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    ],
    "idor": [
        "https://portswigger.net/web-security/access-control/idor",
        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    ],
    "authentication": [
        "https://portswigger.net/web-security/authentication",
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    ],
    "session-management": [
        "https://portswigger.net/web-security/authentication/session-management",
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    ],
    "xss": [
        "https://portswigger.net/web-security/cross-site-scripting",
        "https://owasp.org/Top10/A03_2021-Injection/",
    ],
    "csrf": [
        "https://portswigger.net/web-security/csrf",
        "https://owasp.org/www-community/attacks/csrf",
    ],
    "ssrf": [
        "https://portswigger.net/web-security/ssrf",
        "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    ],
    "injection": [
        "https://portswigger.net/web-security/sql-injection",
        "https://owasp.org/Top10/A03_2021-Injection/",
    ],
    "sqli": [
        "https://portswigger.net/web-security/sql-injection",
        "https://owasp.org/Top10/A03_2021-Injection/",
    ],
    "xxe": [
        "https://portswigger.net/web-security/xxe",
        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    ],
    "template-injection": [
        "https://portswigger.net/research/server-side-template-injection",
        "https://owasp.org/www-project-web-security-testing-guide/",
    ],
    "file-upload": [
        "https://portswigger.net/web-security/file-upload",
        "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
    ],
    "file-read": [
        "https://portswigger.net/web-security/file-path-traversal",
        "https://owasp.org/www-community/attacks/Path_Traversal",
    ],
    "open-redirect": [
        "https://portswigger.net/kb/issues/00500100_open-redirection-reflected",
        "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
    ],
    "cors": [
        "https://portswigger.net/web-security/cors",
        "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
    ],
    "mass-assignment": [
        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
    ],
    "host-header": [
        "https://portswigger.net/web-security/host-header",
        "https://owasp.org/www-project-web-security-testing-guide/",
    ],
    "web-cache-poisoning": [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "https://portswigger.net/web-security/web-cache-deception",
    ],
    "graphql": [
        "https://portswigger.net/web-security/graphql",
        "https://owasp.org/www-project-web-security-testing-guide/",
    ],
}

_GITHUB_REFERENCE_ROOTS = {
    "authorization": ["https://github.com/PortSwigger/BChecks"],
    "idor": ["https://github.com/PortSwigger/BChecks"],
    "authentication": ["https://github.com/PortSwigger/BChecks"],
    "session-management": ["https://github.com/PortSwigger/BChecks"],
    "xss": ["https://github.com/PortSwigger/BChecks"],
    "csrf": ["https://github.com/PortSwigger/BChecks"],
    "ssrf": ["https://github.com/PortSwigger/BChecks"],
    "injection": ["https://github.com/PortSwigger/BChecks"],
    "sqli": ["https://github.com/PortSwigger/BChecks"],
    "xxe": ["https://github.com/PortSwigger/BChecks"],
    "template-injection": ["https://github.com/PortSwigger/BChecks"],
    "file-upload": ["https://github.com/PortSwigger/BChecks"],
    "file-read": ["https://github.com/PortSwigger/BChecks"],
    "open-redirect": ["https://github.com/PortSwigger/BChecks"],
    "cors": ["https://github.com/PortSwigger/BChecks"],
    "mass-assignment": ["https://github.com/PortSwigger/BChecks"],
    "host-header": ["https://github.com/PortSwigger/BChecks"],
    "web-cache-poisoning": ["https://github.com/PortSwigger/BChecks"],
    "graphql": ["https://github.com/PortSwigger/BChecks"],
}


def enrich_advisory_with_references(payload, advisory: dict, rule_context: dict | None = None) -> dict[str, Any]:
    enriched = dict(advisory or {})
    potential_vulnerabilities = list(enriched.get("potential_vulnerabilities") or [])
    vuln_classes = _extract_vuln_classes(potential_vulnerabilities)
    local_resource_hints = list(enriched.get("local_resource_hints") or [])
    source_links = _dedupe_links(list(enriched.get("source_links") or []))

    reference_links: list[str] = []
    if INTERNET_REFERENCE_ENRICHMENT_ENABLED and _should_add_internet_candidates(source_links, local_resource_hints):
        for vuln_class in vuln_classes[:4]:
            for link in curated_references_for_class(vuln_class):
                if link not in reference_links:
                    reference_links.append(link)

    escalation = build_escalation_guidance(
        payload,
        advisory=enriched,
        selected={"vuln_class": vuln_classes[0] if vuln_classes else "general"},
        confirmed_count=0,
    )
    enriched["source_links"] = _dedupe_links(source_links + reference_links)[:10]
    enriched["escalation_profile"] = escalation.get("escalation_profile", "")
    enriched["baseline_confirmation"] = escalation.get("baseline_confirmation", "")
    enriched["safe_vapt_escalation_steps"] = list(escalation.get("safe_vapt_escalation_steps") or [])[:8]
    enriched["business_impact_expansion_paths"] = list(escalation.get("business_impact_expansion_paths") or [])[:6]
    enriched["required_evidence_for_upgrade"] = list(escalation.get("required_evidence_for_upgrade") or [])[:6]
    enriched["stop_conditions"] = list(escalation.get("stop_conditions") or [])[:6]
    enriched["likely_severity_promotions"] = list(escalation.get("likely_severity_promotions") or [])[:6]
    enriched["escalation_ladder"] = list(escalation.get("escalation_ladder") or [])[:8]
    enriched["internet_reference_candidates"] = reference_links[:6]
    enriched["internet_reference_policy"] = (
        f"{INTERNET_REFERENCE_MODE} with explicit bridge configuration"
        if INTERNET_REFERENCE_ENRICHMENT_ENABLED
        else "disabled"
    )
    enriched["policy_gate"] = escalation.get("policy_gate") or {}
    return enriched


def curated_references_for_class(vuln_class: str) -> list[str]:
    normalized = normalize_vuln_class(vuln_class or "general")
    links = []
    for link in _CURATED_REFERENCE_MAP.get(normalized, []):
        if link not in links:
            links.append(link)
    for link in _GITHUB_REFERENCE_ROOTS.get(normalized, []):
        if link not in links:
            links.append(link)
    return links[:4]


def _extract_vuln_classes(entries: list[str]) -> list[str]:
    classes: list[str] = []
    for entry in entries:
        text = (entry or "").strip()
        if text.startswith("[") and "]" in text:
            normalized = normalize_vuln_class(text[1:text.index("]")].strip())
        else:
            normalized = ""
        if normalized and normalized not in classes:
            classes.append(normalized)
    return classes or ["general"]


def _should_add_internet_candidates(source_links: list[str], local_resource_hints: list[str]) -> bool:
    return len(source_links) < 2 or len(local_resource_hints) < 1


def _dedupe_links(items: list[str]) -> list[str]:
    deduped: list[str] = []
    for item in items:
        normalized = (item or "").strip()
        if normalized and normalized not in deduped:
            deduped.append(normalized)
    return deduped
