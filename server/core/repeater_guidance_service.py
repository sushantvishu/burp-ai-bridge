import json
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from server.capabilities.knowledge import search_local_knowledge
from server.capabilities.memory import (
    build_history_fingerprint,
    find_history_matches,
    summarize_history_matches,
)
from server.core.burp_context_service import (
    get_dashboard_issue_context,
    get_related_dashboard_issue_contexts,
    get_repeater_request,
)
from server.providers.deterministic_provider import build_deterministic_context


def build_repeater_escalation_plan(payload_like, *, advisory: dict | None = None, impact: dict | None = None) -> dict[str, Any]:
    payload = _to_payload_dict(payload_like)
    advisory = dict(advisory or {})
    impact = dict(impact or {})
    issue = payload.get("burp_dashboard_issue") or {}
    issue_context = get_dashboard_issue_context(payload)
    related_issue_contexts = get_related_dashboard_issue_contexts(payload)
    raw_request = (payload.get("raw_request") or "").strip()
    request_text = raw_request or _extract_repeater_request_text(payload)
    gated_classes = list((impact.get("policy_gate") or {}).get("gated_classes") or [])
    vuln_class = (
        (gated_classes[0] if gated_classes else None)
        or (impact.get("dashboard_issue") or {}).get("vuln_hint")
        or issue_context.get("vuln_hint")
        or _issue_vuln_class(issue)
        or "general"
    )
    highlights = _normalize_highlights(issue.get("highlights") or [])
    focus_targets = _focus_targets(highlights, request_text, payload.get("target_url") or "")
    mutation_plan = _build_mutation_plan(vuln_class, focus_targets, payload, issue_context, related_issue_contexts, advisory, impact)
    variant_requests = _build_variant_requests(request_text, mutation_plan)[:3]
    issue_chain_strategy = _build_issue_chain_strategy(vuln_class, issue_context, related_issue_contexts)
    kb_hints, memory_hints = _local_resource_hints(payload, issue_context, vuln_class)
    repeater_context = get_repeater_request(payload, limit=2)

    return {
        "scanner_focus": {
            "issue_id": issue_context.get("issue_id", ""),
            "issue_name": issue_context.get("issue_name", ""),
            "severity": issue_context.get("severity", ""),
            "confidence": issue_context.get("confidence", ""),
            "request_refs": list(issue_context.get("request_refs") or [])[:6],
            "response_refs": list(issue_context.get("response_refs") or [])[:6],
            "affected_urls": list(issue_context.get("affected_urls") or [])[:6],
            "highlights": highlights[:8],
            "focus_targets": focus_targets[:6],
            "related_issues": [
                {
                    "issue_name": item.get("issue_name", ""),
                    "severity": item.get("severity", ""),
                    "confidence": item.get("confidence", ""),
                    "vuln_hint": item.get("vuln_hint", ""),
                    "target_url": item.get("target_url", ""),
                }
                for item in related_issue_contexts[:4]
            ],
        },
        "repeater_mutation_plan": mutation_plan[:6],
        "repeater_variant_requests": variant_requests,
        "issue_chain_strategy": issue_chain_strategy[:5],
        "related_scanner_issues": related_issue_contexts[:4],
        "kb_hints": kb_hints[:4],
        "memory_hints": memory_hints[:4],
        "preferred_request_ref": ((repeater_context.get("primary_request") or {}).get("request_ref") or ((issue_context.get("request_refs") or [""])[0] or "inline-request")),
    }


def _build_mutation_plan(vuln_class: str, focus_targets: list[dict[str, Any]], payload: dict[str, Any], issue_context: dict[str, Any], related_issue_contexts: list[dict[str, Any]], advisory: dict, impact: dict) -> list[dict[str, Any]]:
    primary_target = focus_targets[0] if focus_targets else {"location": "request", "selector": "", "current_value": ""}
    current_value = primary_target.get("current_value") or ""
    selector = primary_target.get("selector") or ""
    location = primary_target.get("location") or "request"
    expected_signal = (impact.get("baseline_confirmation") or advisory.get("primary_next_action") or "").strip()

    profiles = {
        "authorization": [
            _change(location, selector, current_value, "<other-tenant-or-role-owned-value>", "Replace the scanner-marked object reference with a permitted alternate tenant or role value.", "A stable authorization delta such as 200/403, field change, or object swap."),
            _change(location, selector, current_value, "<list-or-export-scope-variant>", "Keep the same object family but test the matching list, export, or administrative view the scanner context points toward.", "The same boundary issue repeats beyond one object read."),
        ],
        "authentication": [
            _change("header", "Cookie/Authorization", "<current-session-or-auth-header>", "<omit-or-lower-privilege-session>", "Replay the scanner-marked request without the expected session or with a lower-privilege session.", "The same endpoint stays reachable across the missing authentication boundary."),
            _change(location, selector, current_value, "<same-target-under-auth-state-change>", "Keep the target fixed and compare authenticated vs unauthenticated or lower-privilege state.", "The response path is identical across auth states."),
        ],
        "session-management": [
            _change("header", "Cookie/Authorization", "<current-session-or-auth-header>", "<stale-or-reissued-session>", "Replay the same request with the session state the scanner issue references and one bounded session-state change.", "The same response path survives an unexpected session transition."),
        ],
        "xss": [
            _change(location, selector, current_value, "<bridge-benign-render-marker>", "Replace the scanner-marked input with one benign rendering marker so Repeater can confirm the exact sink context.", "The marker reaches the same reflected or stored sink the scanner highlighted."),
            _change(location, selector, current_value, "<shared-or-admin-view-marker>", "Use the same benign marker only on the workflow the scanner or MCP context ties to a shared or privileged view.", "The same sink is visible in a stronger trust boundary."),
        ],
        "csrf": [
            _change("header", "Origin/Referer", "<current-origin-or-referer>", "<remove-or-cross-origin-placeholder>", "Remove or vary the browser-side origin signal while keeping the state change low-risk.", "The request still succeeds without the expected anti-CSRF control."),
            _change(location, selector or "csrf_token", current_value or "<token>", "<omit-token-or-reuse-stale-token>", "Replay the scanner-marked action without the expected anti-CSRF token or with a stale token placeholder.", "The same state change succeeds without a fresh token."),
        ],
        "ssrf": [
            _change(location, selector or "url", current_value or "<url>", "<approved-callback-url>", "Replace the scanner-marked fetch target with one approved benign callback or public test URL.", "One bounded outbound fetch is confirmed without moving into internal targets."),
        ],
        "xxe": [
            _change("body", selector or "xml-body", current_value or "<xml>", "<benign-xml-entity-variant>", "Swap the scanner-marked XML section with one benign parser-behavior variant.", "The parser behavior changes in the same request path without touching sensitive targets."),
        ],
        "deserialization": [
            _change(location, selector or "serialized-object", current_value or "<serialized>", "<benign-serialized-variant>", "Replace the scanner-marked serialized object with one benign structure change.", "The sink shows controlled object handling without unsafe escalation."),
        ],
        "http-request-smuggling": [
            _change("header", "Transfer-Encoding/Content-Length", "<current-boundary>", "<bounded-parser-disagreement-variant>", "Replay the scanner-marked request boundary with one bounded parser-ambiguity change.", "The same front-end/back-end disagreement repeats at low noise."),
        ],
        "race-condition": [
            _change(location, selector or "workflow-step", current_value or "<step>", "<paired-concurrency-variant>", "Queue the same low-risk request pair the scanner context points to and keep the workflow reversible.", "The same timing-sensitive state transition is repeatable."),
        ],
        "injection": [
            _change(location, selector, current_value, "<benign-syntax-variant>", "Apply one benign syntax change to the scanner-marked sink to confirm interpretation rather than reflection.", "A stable, non-destructive behavioral delta appears."),
        ],
        "template-injection": [
            _change(location, selector, current_value, "<benign-template-marker>", "Use one benign template-evaluation marker in the scanner-marked sink.", "The same rendering path evaluates the marker instead of treating it as plain text."),
        ],
        "file-upload": [
            _change("body", selector or "file-part", current_value or "<file>", "<benign-unexpected-file-variant>", "Keep the same upload path but change the scanner-marked file metadata or type with a benign sample.", "The application accepts or serves the unexpected file handling variant."),
        ],
        "file-read": [
            _change(location, selector or "path", current_value or "<path>", "<benign-path-boundary-variant>", "Change only the scanner-marked path-handling section with one bounded file-boundary variant.", "The same path trust issue repeats without touching sensitive files."),
        ],
        "open-redirect": [
            _change(location, selector or "returnUrl", current_value or "<url>", "https://example.net/bridge-proof", "Replace the scanner-marked redirect target with one benign external destination.", "The application accepts the untrusted redirect target in the same workflow."),
        ],
        "cors": [
            _change("header", "Origin", "<current-origin>", "https://bridge-origin.example", "Replay the same request with one benign alternate Origin header.", "The response still trusts the alternate origin."),
        ],
        "mass-assignment": [
            _change("body", selector or "json-field", current_value or "<field>", "\"isAdmin\": true", "Add one benign privileged-field variant in the same JSON object the scanner highlighted.", "The field is accepted, persisted, or honored beyond baseline."),
        ],
        "host-header": [
            _change("header", "Host/X-Forwarded-Host", "<current-host>", "bridge-host.example", "Replay the same request with one benign host trust variant.", "Generated links, routing, or trust signals follow the injected host."),
        ],
        "web-cache-poisoning": [
            _change("header", selector or "cache-key-input", current_value or "<header>", "<benign-cache-key-variant>", "Change only the scanner-marked cache key input with one benign variant.", "The same shared response or cache behavior changes."),
        ],
        "clickjacking": [
            _change("request", selector or "frameable-page", current_value or "<page>", "<frame-check>", "Keep the scanner-marked page fixed and verify the UI control state around the missing frame protection.", "The same sensitive workflow is frameable."),
        ],
        "graphql": [
            _change("body", selector or "graphql-field", current_value or "<field>", "<same-object-higher-risk-field>", "Change only the scanner-marked GraphQL field or resolver path with one bounded variant.", "The same auth or schema boundary repeats on a stronger field."),
        ],
        "business-logic": [
            _change(location, selector or "workflow-value", current_value or "<value>", "<bounded-invariant-variant>", "Keep the same workflow and vary only the scanner-marked business rule input.", "The same invariant break repeats under one bounded comparison."),
        ],
        "general": [
            _change(location, selector, current_value, "<bounded-confirmation-variant>", "Keep the scanner-marked section fixed and change only that input in Repeater.", expected_signal or "A stable security-relevant delta appears in the same request path."),
        ],
    }
    normalized = vuln_class if vuln_class in profiles else "general"
    plan = list(profiles[normalized])
    related_classes = {str(item.get("vuln_hint") or "general").strip().lower() for item in related_issue_contexts}
    if vuln_class == "authorization" and "xss" in related_classes:
        plan.append(
            _change(
                "body" if location == "body" else location,
                selector or "rendered-field",
                current_value or "<value>",
                "<benign-shared-view-marker>",
                "After the authorization baseline is stable, send one benign marker through the same object field on the Burp-marked shared or admin-facing render path.",
                "The same unauthorized object is visible in the stronger trust boundary already marked by Burp.",
            )
        )
    if vuln_class == "xss" and "authorization" in related_classes:
        plan.append(
            _change(
                location,
                selector or "object-reference",
                current_value or "<value>",
                "<same-rendered-value-under-other-tenant-or-role>",
                "Keep the XSS marker benign and replay it through the object or role boundary already flagged by Burp.",
                "The same sink becomes reachable across the stronger boundary rather than only in one user view.",
            )
        )
    if vuln_class == "csrf" and ("authorization" in related_classes or "authentication" in related_classes):
        plan.append(
            _change(
                "header",
                "Origin/Referer/Cookie",
                "<current-browser-state>",
                "<cross-role-or-cross-auth-state-placeholder>",
                "Once the CSRF baseline is confirmed, compare the same state change under the related auth or role boundary Burp already flagged.",
                "The same state change bypasses both request-origin and boundary enforcement.",
            )
        )
    if issue_context.get("issue_name"):
        for item in plan:
            item["scanner_anchor"] = issue_context.get("issue_name", "")
    return plan


def _build_variant_requests(raw_request: str, mutation_plan: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not raw_request:
        return []
    variants = []
    for index, mutation in enumerate(mutation_plan[:3], start=1):
        request_text = _apply_mutation(raw_request, mutation)
        variants.append({
            "name": f"variant-{index}",
            "summary": mutation.get("instruction", ""),
            "expected_signal": mutation.get("expected_signal", ""),
            "request_text": request_text,
        })
    return variants


def _build_issue_chain_strategy(vuln_class: str, issue_context: dict[str, Any], related_issue_contexts: list[dict[str, Any]]) -> list[str]:
    if not related_issue_contexts:
        return []

    strategies: list[str] = []
    related_classes = {str(item.get("vuln_hint") or "general").strip().lower() for item in related_issue_contexts}
    related_names = [item.get("issue_name", "") for item in related_issue_contexts[:3] if item.get("issue_name")]
    if related_names:
        strategies.append(
            "Related Burp Scanner issues on the same target: " + ", ".join(related_names) + "."
        )

    if vuln_class == "authorization" and "xss" in related_classes:
        strategies.append("After confirming the access-control delta, check whether the same unauthorized object is rendered in the XSS-marked shared or admin-facing workflow with a benign render marker.")
    if vuln_class == "authorization" and ("csrf" in related_classes or "authentication" in related_classes):
        strategies.append("Keep the same object or action fixed and compare whether the authorization flaw combines with weaker auth-state or anti-CSRF enforcement on that exact workflow.")
    if vuln_class == "xss" and "authorization" in related_classes:
        strategies.append("Use the authorization-marked path to see whether the same reflected or stored sink becomes visible to a broader audience, but keep the marker benign.")
    if vuln_class == "csrf" and ("authorization" in related_classes or "authentication" in related_classes):
        strategies.append("Confirm the state-change request first, then test whether the same action is also reachable across the role or auth boundary already marked by Burp.")
    if vuln_class in {"ssrf", "xxe", "http-request-smuggling", "injection"} and "authorization" in related_classes:
        strategies.append("After reproducing the primary parser or server-side issue safely, test whether the same endpoint gains extra value only because the marked authorization boundary is weak.")
    if not strategies:
        strategies.append("Confirm the primary Burp-marked issue first, then use one related scanner issue on the same host or path to choose the next bounded escalation branch instead of broad exploration.")
    if issue_context.get("issue_name"):
        strategies.append(f"Keep '{issue_context.get('issue_name')}' as the anchor finding and treat any multi-issue chain as secondary until the baseline delta is stable.")
    return strategies[:5]


def _apply_mutation(raw_request: str, mutation: dict[str, Any]) -> str:
    parsed = _parse_request(raw_request)
    replacement = mutation.get("replacement", "")
    selector = mutation.get("selector", "")
    location = mutation.get("location", "")

    if location == "query" and selector:
        path = parsed["path"]
        split = urlsplit("https://placeholder" + path)
        params = []
        changed = False
        for key, value in parse_qsl(split.query, keep_blank_values=True):
            if key == selector and not changed:
                params.append((key, replacement))
                changed = True
            else:
                params.append((key, value))
        if not changed and selector:
            params.append((selector, replacement))
        new_path = urlunsplit(("", "", split.path, urlencode(params), split.fragment))
        parsed["path"] = new_path
    elif location == "header":
        headers = parsed["headers"]
        selector_tokens = [token.strip() for token in selector.split("/") if token.strip()]
        changed = False
        for token in selector_tokens:
            for index, (key, value) in enumerate(headers):
                if key.lower() == token.lower():
                    headers[index] = (key, replacement)
                    changed = True
                    break
            if changed:
                break
        if not changed and selector_tokens:
            headers.append((selector_tokens[0], replacement))
    elif location == "body":
        body = parsed["body"]
        current_value = mutation.get("current_value", "")
        if current_value and current_value in body:
            parsed["body"] = body.replace(current_value, replacement, 1)
        elif selector and selector in body:
            parsed["body"] = body.replace(selector, replacement, 1)
        else:
            parsed["body"] = body + ("" if not body else "\n") + replacement
    else:
        current_value = mutation.get("current_value", "")
        if current_value and current_value in parsed["path"]:
            parsed["path"] = parsed["path"].replace(current_value, replacement, 1)
        elif current_value and current_value in parsed["body"]:
            parsed["body"] = parsed["body"].replace(current_value, replacement, 1)

    return _serialize_request(parsed)


def _focus_targets(highlights: list[dict[str, Any]], request_text: str, target_url: str) -> list[dict[str, Any]]:
    focus = []
    for item in highlights:
        current_value = item.get("text") or _highlight_text_from_offsets(item, request_text)
        location = item.get("location") or _location_from_offsets(item, request_text) or _guess_location(current_value, request_text)
        focus.append({
            "location": location,
            "selector": item.get("selector") or item.get("label") or "",
            "current_value": current_value or "",
            "reason": item.get("reason") or item.get("label") or "",
            "start_offset": int(item.get("start_offset", -1) or -1),
            "end_offset": int(item.get("end_offset", -1) or -1),
        })
    if focus:
        return _dedupe_focus(focus)

    parsed = _parse_request(request_text)
    split = urlsplit("https://placeholder" + parsed["path"]) if parsed["path"] else urlsplit(target_url or "")
    query_items = parse_qsl(split.query, keep_blank_values=True)
    for key, value in query_items[:2]:
        focus.append({"location": "query", "selector": key, "current_value": value, "reason": "query parameter"})
    if not focus:
        body_keys = _body_keys(parsed["body"])
        for key in body_keys[:2]:
            focus.append({"location": "body", "selector": key, "current_value": key, "reason": "request body field"})
    return _dedupe_focus(focus or [{"location": "request", "selector": "", "current_value": "", "reason": "scanner-marked request"}])


def _normalize_highlights(raw_items: list[Any]) -> list[dict[str, Any]]:
    items = []
    for raw in raw_items[:8]:
        if isinstance(raw, dict):
            text = str(raw.get("text") or raw.get("value") or raw.get("highlight") or raw.get("content") or "").strip()
            location = str(raw.get("location") or raw.get("part") or raw.get("section") or "").strip().lower()
            label = str(raw.get("label") or raw.get("name") or raw.get("type") or "").strip()
            selector = str(raw.get("selector") or raw.get("parameter") or raw.get("field") or "").strip()
            try:
                start_offset = int(raw.get("start_offset", raw.get("startOffset", raw.get("start", -1))) or -1)
            except (TypeError, ValueError):
                start_offset = -1
            try:
                end_offset = int(raw.get("end_offset", raw.get("endOffset", raw.get("end", -1))) or -1)
            except (TypeError, ValueError):
                end_offset = -1
            if text or label or selector or start_offset >= 0 or end_offset >= 0:
                items.append({
                    "text": text,
                    "location": location,
                    "label": label,
                    "selector": selector,
                    "reason": str(raw.get("reason") or "").strip(),
                    "part": str(raw.get("part") or "").strip().lower(),
                    "start_offset": start_offset,
                    "end_offset": end_offset,
                })
        elif isinstance(raw, str) and raw.strip():
            items.append({"text": raw.strip(), "location": "", "label": "", "selector": "", "reason": "", "part": "", "start_offset": -1, "end_offset": -1})
    return items


def _highlight_text_from_offsets(item: dict[str, Any], request_text: str) -> str:
    start_offset = int(item.get("start_offset", -1) or -1)
    end_offset = int(item.get("end_offset", -1) or -1)
    part = str(item.get("part") or item.get("location") or "").lower()
    if part.startswith("response"):
        return ""
    if start_offset < 0 or end_offset <= start_offset:
        return ""
    content = request_text or ""
    if end_offset > len(content):
        return ""
    return content[start_offset:end_offset].strip()


def _location_from_offsets(item: dict[str, Any], request_text: str) -> str:
    start_offset = int(item.get("start_offset", -1) or -1)
    end_offset = int(item.get("end_offset", -1) or -1)
    if start_offset < 0 or end_offset <= start_offset:
        return ""
    content = request_text or ""
    if end_offset > len(content):
        return ""
    head, _, _ = content.partition("\r\n\r\n")
    normalized_head = head if head else content.partition("\n\n")[0]
    header_end = len(normalized_head)
    request_line_end = normalized_head.find("\r\n")
    if request_line_end < 0:
        request_line_end = normalized_head.find("\n")
    if request_line_end < 0:
        request_line_end = len(normalized_head)
    if end_offset <= request_line_end:
        request_line = content[:request_line_end]
        return "query" if "?" in request_line else "path"
    if start_offset < header_end:
        return "header"
    return "body"


def _local_resource_hints(payload: dict[str, Any], issue_context: dict[str, Any], vuln_class: str) -> tuple[list[str], list[str]]:
    query = " ".join(
        part
        for part in [
            issue_context.get("issue_name", ""),
            issue_context.get("detail", ""),
            payload.get("target_url", ""),
            vuln_class,
        ]
        if part
    ).strip()
    kb_search = search_local_knowledge(query, top_k=3)
    kb_hints = []
    for hit in kb_search.get("hits", [])[:3]:
        title = hit.get("title") or hit.get("file") or ""
        if title:
            kb_hints.append(f"Local KB: {title}")

    payload_ns = _payload_namespace(payload)
    rule_context = build_deterministic_context(payload_ns)
    fingerprint = build_history_fingerprint(payload_ns, rule_context)
    similar_hits = find_history_matches(fingerprint, limit=3)
    memory_summary = summarize_history_matches(similar_hits)
    memory_hints = []
    if memory_summary.get("note"):
        memory_hints.append(memory_summary["note"])
    for title in memory_summary.get("preferred_kb_titles", [])[:2]:
        memory_hints.append(f"Prior useful local note: {title}")
    return kb_hints, memory_hints


def _extract_repeater_request_text(payload: dict[str, Any]) -> str:
    for entry in payload.get("repeater_requests") or []:
        if isinstance(entry, dict):
            text = str(entry.get("request_text") or entry.get("raw_request") or entry.get("request") or "").strip()
            if text:
                return text
    return ""


def _parse_request(raw_request: str) -> dict[str, Any]:
    content = (raw_request or "").replace("\r\n", "\n")
    head, _, body = content.partition("\n\n")
    lines = [line for line in head.split("\n") if line]
    request_line = lines[0] if lines else "GET / HTTP/1.1"
    parts = request_line.split()
    method = parts[0] if len(parts) > 0 else "GET"
    path = parts[1] if len(parts) > 1 else "/"
    version = parts[2] if len(parts) > 2 else "HTTP/1.1"
    headers = []
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers.append((key.strip(), value.strip()))
    return {"method": method, "path": path, "version": version, "headers": headers, "body": body}


def _serialize_request(parsed: dict[str, Any]) -> str:
    lines = [f"{parsed['method']} {parsed['path']} {parsed['version']}"]
    for key, value in parsed.get("headers", []):
        lines.append(f"{key}: {value}")
    if parsed.get("body"):
        return "\r\n".join(lines) + "\r\n\r\n" + parsed["body"]
    return "\r\n".join(lines) + "\r\n\r\n"


def _body_keys(body: str) -> list[str]:
    body = (body or "").strip()
    if not body:
        return []
    if "=" in body and "&" in body:
        return [key for key, _ in parse_qsl(body, keep_blank_values=True)]
    if body.startswith("{"):
        try:
            value = json.loads(body)
        except Exception:
            return []
        if isinstance(value, dict):
            return [str(key) for key in value.keys()]
    return []


def _guess_location(text: str, request_text: str) -> str:
    normalized = text or ""
    parsed = _parse_request(request_text)
    if normalized and normalized in parsed["path"]:
        return "query" if "?" in parsed["path"] else "path"
    if normalized and normalized in parsed["body"]:
        return "body"
    for key, value in parsed["headers"]:
        if normalized and (normalized in key or normalized in value):
            return "header"
    return "request"


def _issue_vuln_class(issue: dict[str, Any]) -> str:
    normalized = " ".join(
        [
            str(issue.get("name") or ""),
            str(issue.get("detail") or ""),
        ]
    ).lower()
    mapping = [
        ("authorization", ("idor", "access control", "privilege")),
        ("xss", ("xss", "cross-site scripting")),
        ("csrf", ("csrf", "request forgery")),
        ("ssrf", ("ssrf", "server-side request forgery")),
        ("xxe", ("xxe", "xml external entity")),
        ("http-request-smuggling", ("smuggling", "desync")),
        ("injection", ("sql injection", "sqli", "injection")),
        ("authentication", ("authentication", "auth bypass")),
    ]
    for vuln_class, tokens in mapping:
        if any(token in normalized for token in tokens):
            return vuln_class
    return "general"


def _change(location: str, selector: str, current_value: str, replacement: str, instruction: str, expected_signal: str) -> dict[str, Any]:
    return {
        "location": location,
        "selector": selector,
        "current_value": current_value,
        "replacement": replacement,
        "instruction": instruction,
        "expected_signal": expected_signal,
    }


def _dedupe_focus(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for item in items:
        key = (item.get("location", ""), item.get("selector", ""), item.get("current_value", ""))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _to_payload_dict(payload_like) -> dict[str, Any]:
    if isinstance(payload_like, dict):
        return dict(payload_like)
    if hasattr(payload_like, "model_dump"):
        return payload_like.model_dump()
    if hasattr(payload_like, "dict"):
        return payload_like.dict()
    return dict(vars(payload_like))


def _payload_namespace(payload: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(**dict(payload))
