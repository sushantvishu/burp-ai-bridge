from __future__ import annotations

import re

BAPP_PATTERNS = [
    {
        "tool": "Param Miner",
        "pattern": re.compile(r"\bparam\s*miner\b|\bhidden parameter\b|\bcache buster\b", re.IGNORECASE),
        "vuln_class": "input-validation",
        "summary": "Param Miner-style findings suggest hidden parameters, cache-key quirks, or input surface expansion worth passive review.",
        "source_links": [
            "https://portswigger.net/burp/documentation/desktop/testing-workflow/analyzing/hidden-inputs",
        ],
    },
    {
        "tool": "Autorize/AuthMatrix",
        "pattern": re.compile(r"\bautorize\b|\bauthmatrix\b|\bunauthori[sz]ed\b|\brole\b", re.IGNORECASE),
        "vuln_class": "access-control",
        "summary": "Authorization-matrix style findings point to role or object-level access-control inconsistencies.",
        "source_links": [
            "https://portswigger.net/web-security/access-control",
        ],
    },
    {
        "tool": "JWT Editor",
        "pattern": re.compile(r"\bjwt\b|\btoken\b|\bheader\.alg\b|\bkid\b", re.IGNORECASE),
        "vuln_class": "jwt-token",
        "summary": "JWT-oriented BApp notes suggest token structure, algorithm, or claim-handling review.",
        "source_links": [
            "https://portswigger.net/web-security/jwt",
        ],
    },
    {
        "tool": "Retire.js",
        "pattern": re.compile(r"\bretire\.js\b|\boutdated library\b|\bvulnerable component\b", re.IGNORECASE),
        "vuln_class": "security-misconfiguration",
        "summary": "Component-version findings suggest outdated client-side libraries or dependency exposure.",
        "source_links": [
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        ],
    },
    {
        "tool": "Logger++",
        "pattern": re.compile(
            r"\blogger\+\+\b|\binteresting response\b|\bheader diff\b|\bbaseline\b|\bconfirmed\b|\b\d{3}\s*(?:->|to)\s*\d{3}\b|\blength\s*(?:delta|change|changed)\b",
            re.IGNORECASE,
        ),
        "vuln_class": "information-disclosure",
        "summary": "Logger++-style notes indicate useful passive diffs across headers, status codes, or response bodies.",
        "source_links": [
            "https://portswigger.net/burp/documentation/desktop/tools/logger",
        ],
    },
    {
        "tool": "Burp Scanner",
        "pattern": re.compile(r"\bxml external entity injection\b|\bxxe\b", re.IGNORECASE),
        "vuln_class": "xxe",
        "summary": "Burp Scanner issue text indicates XML parser behavior that should be confirmed with safe XML structure comparisons.",
        "source_links": [
            "https://portswigger.net/web-security/xxe",
        ],
    },
    {
        "tool": "Burp Scanner",
        "pattern": re.compile(r"\bsql injection\b|\bsqli\b", re.IGNORECASE),
        "vuln_class": "sqli",
        "summary": "Burp Scanner issue text suggests SQL-style backend query handling that should be confirmed with controlled request comparisons.",
        "source_links": [
            "https://portswigger.net/web-security/sql-injection",
        ],
    },
    {
        "tool": "Burp Scanner",
        "pattern": re.compile(r"\bcross[- ]site scripting\b|\bxss\b", re.IGNORECASE),
        "vuln_class": "xss",
        "summary": "Burp Scanner issue text suggests reflected or stored client-side script execution risk that should be confirmed in the exact reflection context.",
        "source_links": [
            "https://portswigger.net/web-security/cross-site-scripting",
        ],
    },
    {
        "tool": "Burp Scanner",
        "pattern": re.compile(r"\bserver-side request forgery\b|\bssrf\b", re.IGNORECASE),
        "vuln_class": "ssrf",
        "summary": "Burp Scanner issue text suggests server-side outbound request handling that should be confirmed conservatively with approved URL-format comparisons.",
        "source_links": [
            "https://portswigger.net/web-security/ssrf",
        ],
    },
    {
        "tool": "Burp Scanner",
        "pattern": re.compile(r"\bopen redirect\b", re.IGNORECASE),
        "vuln_class": "open-redirect",
        "summary": "Burp Scanner issue text suggests redirect target validation weaknesses that should be confirmed with exact Location and allowlist comparisons.",
        "source_links": [
            "https://portswigger.net/web-security/open-redirect",
        ],
    },
    {
        "tool": "Burp Scanner",
        "pattern": re.compile(r"\bpath traversal\b|\bdirectory traversal\b", re.IGNORECASE),
        "vuln_class": "path-traversal",
        "summary": "Burp Scanner issue text suggests path normalization or file retrieval weaknesses that should be confirmed with one path variation at a time.",
        "source_links": [
            "https://portswigger.net/web-security/file-path-traversal",
        ],
    },
    {
        "tool": "Burp Scanner",
        "pattern": re.compile(r"\bserver-side template injection\b|\bssti\b", re.IGNORECASE),
        "vuln_class": "ssti",
        "summary": "Burp Scanner issue text suggests server-side template evaluation risk that should be confirmed with safe rendering-context comparisons.",
        "source_links": [
            "https://portswigger.net/web-security/server-side-template-injection",
        ],
    },
    {
        "tool": "Burp Scanner",
        "pattern": re.compile(r"\bcommand injection\b|\bos command injection\b", re.IGNORECASE),
        "vuln_class": "command-injection",
        "summary": "Burp Scanner issue text suggests command-processing behavior that should be confirmed with low-risk timing or formatting comparisons first.",
        "source_links": [
            "https://portswigger.net/web-security/os-command-injection",
        ],
    },
    {
        "tool": "Burp Scanner",
        "pattern": re.compile(r"\brequest smuggling\b", re.IGNORECASE),
        "vuln_class": "http-request-smuggling",
        "summary": "Burp Scanner issue text suggests front-end and back-end parsing differences that should be confirmed with exact framing comparisons.",
        "source_links": [
            "https://portswigger.net/web-security/request-smuggling",
        ],
    },
    {
        "tool": "Burp Scanner",
        "pattern": re.compile(r"\bcross-origin resource sharing\b|\bcors\b", re.IGNORECASE),
        "vuln_class": "cors",
        "summary": "Burp Scanner issue text suggests Origin trust-boundary review with explicit Access-Control-Allow-* comparisons.",
        "source_links": [
            "https://portswigger.net/web-security/cors",
        ],
    },
    {
        "tool": "Burp Scanner",
        "pattern": re.compile(r"\bcross-site request forgery\b|\bcsrf\b", re.IGNORECASE),
        "vuln_class": "csrf",
        "summary": "Burp Scanner issue text suggests browser-driven state-change handling that should be confirmed with token and origin comparisons.",
        "source_links": [
            "https://portswigger.net/web-security/csrf",
        ],
    },
    {
        "tool": "Burp Scanner",
        "pattern": re.compile(r"\baccess control\b|\bauthori[sz]ation\b|\binsecure direct object reference\b|\bidor\b", re.IGNORECASE),
        "vuln_class": "access-control",
        "summary": "Burp Scanner issue text suggests role, tenant, or object-level authorization differences that should be confirmed across approved sessions.",
        "source_links": [
            "https://portswigger.net/web-security/access-control",
        ],
    },
]

LOADED_BURP_TOOL_PATTERNS = [
    {
        "name": "Logger++",
        "pattern": re.compile(r"\blogger\s*\+\+\b|\blogger plus plus\b", re.IGNORECASE),
        "summary": "Use Logger++ to pin the baseline, confirming delta, and impact request with filters, comments, and exports.",
    },
    {
        "name": "Param Miner",
        "pattern": re.compile(r"\bparam\s*miner\b", re.IGNORECASE),
        "summary": "Use Param Miner before wider fuzzing when the hypothesis depends on hidden inputs, cache keys, or unlinked parameters.",
    },
    {
        "name": "Autorize/AuthMatrix",
        "pattern": re.compile(r"\bautorize\b|\bauthmatrix\b", re.IGNORECASE),
        "summary": "Use Autorize or AuthMatrix first for access-control and session-difference confirmation before broader scan noise.",
    },
    {
        "name": "JWT Editor",
        "pattern": re.compile(r"\bjwt\s*editor\b", re.IGNORECASE),
        "summary": "Use JWT Editor for token inspection, claim edits, and safe token-state comparisons.",
    },
    {
        "name": "Active Scan++",
        "pattern": re.compile(r"\bactive\s*scan\s*\+\+\b", re.IGNORECASE),
        "summary": "Use Active Scan++ only after you narrow to an in-scope insertion point that justifies extra scan depth.",
    },
    {
        "name": "Turbo Intruder",
        "pattern": re.compile(r"\bturbo\s*intruder\b", re.IGNORECASE),
        "summary": "Use Turbo Intruder only after a manual delta is proven and the program rules allow the request volume.",
    },
    {
        "name": "Collaborator Everywhere",
        "pattern": re.compile(r"\bcollaborator\s*everywhere\b", re.IGNORECASE),
        "summary": "Use Collaborator Everywhere to widen passive callback visibility only where the program permits outbound interaction testing.",
    },
    {
        "name": "Content Type Converter",
        "pattern": re.compile(r"\bcontent\s*type\s*converter\b", re.IGNORECASE),
        "summary": "Use Content Type Converter when you need the same request tested across JSON, XML, and form encodings without rebuilding it.",
    },
    {
        "name": "Repeater",
        "pattern": re.compile(r"\brepeater\b", re.IGNORECASE),
        "summary": "Keep Repeater as the primary tool for one-change-at-a-time confirmation before scan expansion.",
    },
    {
        "name": "Intruder",
        "pattern": re.compile(r"\bintruder\b", re.IGNORECASE),
        "summary": "Use Intruder only after Repeater identifies the exact field, payload family, and comparison markers worth expanding.",
    },
    {
        "name": "Comparer",
        "pattern": re.compile(r"\bcomparer\b", re.IGNORECASE),
        "summary": "Use Comparer when the baseline versus confirming response diff is noisy and you need clearer evidence.",
    },
]


def normalize_bapp_findings(text: str | None) -> dict:
    normalized_text = (text or "").strip()
    if not normalized_text:
        return {
            "detected_tools": [],
            "findings": [],
            "summary_lines": [],
            "suggested_vuln_classes": [],
            "source_links": [],
        }

    findings = []
    detected_tools = []
    suggested_vuln_classes = []
    source_links = []

    for entry in BAPP_PATTERNS:
        if not entry["pattern"].search(normalized_text):
            continue
        findings.append({
            "tool": entry["tool"],
            "vuln_class": entry["vuln_class"],
            "summary": entry["summary"],
            "evidence": f"Pasted BApp findings matched the {entry['tool']} heuristic.",
            "source_links": list(entry["source_links"]),
        })
        detected_tools.append(entry["tool"])
        if entry["vuln_class"] not in suggested_vuln_classes:
            suggested_vuln_classes.append(entry["vuln_class"])
        for link in entry["source_links"]:
            if link not in source_links:
                source_links.append(link)

    summary_lines = []
    if detected_tools:
        summary_lines.append("Detected Burp evidence sources: " + ", ".join(detected_tools))
    if suggested_vuln_classes:
        summary_lines.append("Burp scan or BApp evidence suggests: " + ", ".join(suggested_vuln_classes))

    compact = normalized_text[:1200] + ("..." if len(normalized_text) > 1200 else "")
    summary_lines.append("Burp evidence preview: " + compact.replace("\r\n", " ").replace("\n", " "))

    return {
        "detected_tools": detected_tools,
        "findings": findings,
        "summary_lines": summary_lines,
        "suggested_vuln_classes": suggested_vuln_classes,
        "source_links": source_links,
    }


def normalize_loaded_burp_tools(text: str | None) -> dict:
    normalized_text = (text or "").strip()
    if not normalized_text:
        return {
            "detected_tools": [],
            "summary_lines": [],
            "recommendation_lines": [],
        }

    detected_tools = []
    recommendation_lines = []
    for entry in LOADED_BURP_TOOL_PATTERNS:
        if not entry["pattern"].search(normalized_text):
            continue
        if entry["name"] not in detected_tools:
            detected_tools.append(entry["name"])
            recommendation_lines.append(f"{entry['name']}: {entry['summary']}")

    summary_lines = []
    if detected_tools:
        summary_lines.append("Loaded Burp tools or BApps: " + ", ".join(detected_tools))

    compact = normalized_text[:1200] + ("..." if len(normalized_text) > 1200 else "")
    summary_lines.append("Declared Burp tool inventory preview: " + compact.replace("\r\n", " ").replace("\n", " "))

    return {
        "detected_tools": detected_tools,
        "summary_lines": summary_lines,
        "recommendation_lines": recommendation_lines,
    }
