import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from server.bapp_adapters import normalize_bapp_findings, normalize_loaded_burp_tools
from server.bcheck_catalog import recommend_bchecks, summarize_recommendations
from server.collaborator_parser import summarize_collaborator_evidence
from server.confirmation_playbooks import build_confirmation_playbooks
from server.kali_tools import combined_tool_help_text, get_tool_inventory, inventory_summary_text, recommend_tools, summarize_tool_recommendations
from server.local_guidance_db import query_guidance_packs
from server.profiles import get_profile

SECURITY_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
)

IDENTIFIER_PARAMS = {
    "id",
    "user",
    "userid",
    "user_id",
    "account",
    "accountid",
    "account_id",
    "profile",
    "profileid",
    "profile_id",
    "order",
    "orderid",
    "order_id",
    "invoice",
    "invoiceid",
    "invoice_id",
    "tenant",
    "tenantid",
    "tenant_id",
    "resource",
    "resourceid",
    "resource_id",
    "object",
    "objectid",
    "object_id",
    "member",
    "memberid",
    "member_id",
    "customer",
    "customerid",
    "customer_id",
}
REDIRECT_PARAMS = {"next", "url", "return", "returnurl", "redirect", "redirect_uri", "redirecturl", "dest", "destination", "continue"}
URL_INPUT_PARAMS = {
    "url",
    "uri",
    "link",
    "target",
    "target_url",
    "callback",
    "callback_url",
    "webhook",
    "feed",
    "image",
    "endpoint",
    "load",
    "path",
    "return_to",
    "continue_to",
}
SEARCH_PARAMS = {"q", "query", "search", "term", "keyword", "lang", "message", "comment", "name"}
PATH_INPUT_PARAMS = {"path", "file", "filename", "folder", "dir", "directory", "document", "template", "view", "download"}
GRAPHQL_PARAM_NAMES = {"query", "variables", "operationname"}
SERIALIZED_PARAM_NAMES = {"data", "state", "object", "payload", "session", "token", "profile"}
PRIVILEGED_JSON_KEYS = {"role", "roles", "admin", "isadmin", "permission", "permissions", "status", "price", "balance", "credit", "limit"}
TEMPLATE_INPUT_PARAMS = {"template", "template_name", "view", "preview", "content", "html", "body", "email", "markup"}
INTERNAL_PATH_TOKENS = {"internal", "private", "backoffice", "staff", "ops", "intranet"}
API_VERSION_PATH_REGEX = r"/v\d+(?:/|$)"

CLASS_TARGET_PARAM_CANDIDATES = {
    "access-control": IDENTIFIER_PARAMS,
    "business-logic": IDENTIFIER_PARAMS | SEARCH_PARAMS,
    "command-injection": SEARCH_PARAMS | URL_INPUT_PARAMS,
    "cors": None,
    "crypto-failures": None,
    "csrf": None,
    "deserialization": SERIALIZED_PARAM_NAMES,
    "file-upload": None,
    "graphql": GRAPHQL_PARAM_NAMES,
    "http-request-smuggling": None,
    "information-disclosure": SEARCH_PARAMS | IDENTIFIER_PARAMS,
    "input-validation": SEARCH_PARAMS | IDENTIFIER_PARAMS | URL_INPUT_PARAMS,
    "insecure-design": IDENTIFIER_PARAMS | SEARCH_PARAMS,
    "jwt-token": None,
    "mass-assignment": PRIVILEGED_JSON_KEYS,
    "open-redirect": REDIRECT_PARAMS,
    "path-traversal": PATH_INPUT_PARAMS,
    "race-condition": IDENTIFIER_PARAMS | SEARCH_PARAMS,
    "security-misconfiguration": None,
    "secret-exposure": None,
    "session-management": None,
    "sqli": IDENTIFIER_PARAMS | SEARCH_PARAMS,
    "ssti": TEMPLATE_INPUT_PARAMS | SEARCH_PARAMS,
    "ssrf": URL_INPUT_PARAMS,
    "xss": SEARCH_PARAMS,
    "xxe": None,
}

INTRUDER_DEEMPHASIZED_CLASSES = {
    "authentication",
    "business-logic",
    "cache",
    "command-injection",
    "crypto-failures",
    "csrf",
    "deserialization",
    "file-upload",
    "http-request-smuggling",
    "information-disclosure",
    "insecure-design",
    "jwt-token",
    "mass-assignment",
    "race-condition",
    "secret-exposure",
    "security-misconfiguration",
    "session-management",
    "xxe",
}

RECIPE_DIR = Path(__file__).with_name("recipes")
DEFAULT_VULN_CLASSES = [
    "access-control",
    "authentication",
    "business-logic",
    "cache",
    "command-injection",
    "cors",
    "crypto-failures",
    "csrf",
    "deserialization",
    "file-upload",
    "graphql",
    "http-request-smuggling",
    "information-disclosure",
    "input-validation",
    "insecure-design",
    "jwt-token",
    "mass-assignment",
    "open-redirect",
    "path-traversal",
    "race-condition",
    "security-misconfiguration",
    "secret-exposure",
    "session-management",
    "sqli",
    "ssti",
    "ssrf",
    "xss",
    "xxe",
]

SIGNAL_DESCRIPTIONS = {
    "request_has_cookies": "The request includes cookies.",
    "request_has_authorization": "The request includes an Authorization header.",
    "request_has_bearer_token": "The request appears to carry a bearer token.",
    "request_has_jwt_like_token": "The request appears to carry a JWT-like token.",
    "request_has_json_body": "The request body is JSON.",
    "request_has_xml_body": "The request body appears to be XML.",
    "request_has_form_body": "The request body is form-urlencoded.",
    "request_has_file_upload": "The request content type indicates a file upload.",
    "request_has_identifier_params": "The request contains identifier-like parameter names.",
    "request_has_redirect_params": "The request contains redirect-like parameter names.",
    "request_has_url_input_params": "The request contains URL-like callback or fetch parameter names.",
    "request_has_search_like_params": "The request contains search or reflected-input style parameter names.",
    "request_has_graphql_marker": "The request looks like GraphQL traffic.",
    "request_has_nested_json": "The JSON body contains nested objects or lists.",
    "request_has_privileged_json_keys": "The JSON body contains sensitive or privilege-related field names.",
    "request_has_path_input_params": "The request contains file or path-style parameter names.",
    "request_has_template_input_params": "The request contains template or render-style parameter names.",
    "request_has_template_syntax_markers": "The request body or parameters include template syntax markers.",
    "request_has_serialized_blob": "The request body or parameters contain serialized-object style markers.",
    "request_has_chunked_transfer": "The request declares chunked transfer encoding.",
    "request_has_conflicting_length_headers": "The request includes both Transfer-Encoding and Content-Length headers.",
    "target_uses_plain_http": "The target URL uses plain HTTP.",
    "path_looks_login": "The path looks related to login or authentication.",
    "path_looks_admin": "The path looks related to admin or management functionality.",
    "path_looks_internal": "The path looks related to internal or back-office functionality.",
    "path_has_api_version": "The request path includes an API version marker such as /v1/ or /v2/.",
    "response_has_html": "The response looks like HTML.",
    "response_is_json": "The response looks like JSON.",
    "response_has_html_form": "The response contains an HTML form.",
    "response_has_password_field": "The response contains a password field.",
    "response_has_csrf_marker": "The response contains an obvious CSRF token marker.",
    "response_missing_security_headers": "Common browser security headers are missing.",
    "response_sets_cookie": "The response sets a cookie.",
    "response_cookie_missing_secure": "A response cookie appears to lack the Secure flag.",
    "response_cookie_missing_httponly": "A response cookie appears to lack the HttpOnly flag.",
    "response_cookie_missing_samesite": "A response cookie appears to lack the SameSite flag.",
    "response_has_error_keywords": "The response body preview includes error-like keywords.",
    "response_has_cors_header": "The response contains CORS headers.",
    "response_cors_reflects_origin": "The response reflects the Origin header or uses wildcard CORS.",
    "response_has_cache_headers": "The response contains cache-control or related caching headers.",
    "response_missing_cache_headers": "The response lacks explicit cache-control style headers.",
    "response_has_secret_keywords": "The response appears to expose keys, secrets, or private material markers.",
    "response_has_graphql_error": "The response body looks like a GraphQL error payload.",
}

REQUEST_SHAPE_CONFIDENCE_HINTS = {
    "xxe": ("request_has_xml_body", "The request shape already looks XML-driven."),
    "ssrf": ("request_has_url_input_params", "The request already contains URL-like fetch or callback inputs."),
    "open-redirect": ("request_has_redirect_params", "The request already contains redirect-like parameters."),
    "access-control": ("request_has_identifier_params", "The request already contains identifier-like parameters."),
    "sqli": ("request_has_identifier_params", "The request already contains identifier-like or query-style inputs."),
    "xss": ("request_has_search_like_params", "The request already contains reflection-style or search-style inputs."),
    "jwt-token": ("request_has_jwt_like_token", "The request already carries a JWT-like token."),
    "graphql": ("request_has_graphql_marker", "The request already looks like GraphQL traffic."),
    "path-traversal": ("request_has_path_input_params", "The request already contains file or path-style inputs."),
    "ssti": ("request_has_template_input_params", "The request already contains template or render-style inputs."),
}

GENERAL_KALI_TOOLS = [
    "curl: replay the exact request with controlled header, cookie, and parameter changes from Kali WSL.",
    "nuclei: run scoped checks using the suggested nuclei tags after you confirm the endpoint is in scope.",
]

GENERAL_REPEATER_GUIDANCE = [
    "Send the captured baseline request to Burp Repeater and keep one untouched tab as the control request.",
    "Create only one approved comparison variant at a time and compare status code, headers, redirect behavior, content length, and visible body deltas against the baseline.",
    "Record each Repeater comparison outcome in the Evidence Timeline so the next advisory can rank the hypothesis with real evidence.",
]

VULN_CLASS_REPEATER_GUIDANCE = {
    "access-control": "Compare the same endpoint under different approved sessions or roles and watch for object ownership, tenant, or authorization deltas.",
    "authentication": "Compare authenticated versus unauthenticated or expired-session responses and note redirect, token, and cookie transition behavior.",
    "business-logic": "Replay the workflow one step at a time in the expected order first, then note whether repeated or reordered requests change the server-side state.",
    "cache": "Keep the method and path fixed, then compare cache-control, vary, age, and content-length differences between repeated baseline requests.",
    "command-injection": "Record how the response changes when one benign formatting difference is introduced, and note timing, error text, and output-shape changes only.",
    "cors": "Compare response headers for the same request under different approved Origin values and record whether credentials or reflection behavior changes.",
    "crypto-failures": "Compare the same route over the observed transport, note whether cookies, redirects, or exposed material depend on HTTP versus HTTPS, and record any missing transport protections.",
    "csrf": "Compare baseline form or state-changing requests with one approved token/origin difference and note whether the server rejects, redirects, or accepts the request.",
    "deserialization": "Compare how one serialized or opaque object-style input is accepted, rejected, or normalized, and record parser or type errors without broad fuzzing.",
    "file-upload": "Compare filename, content type, and extension handling one change at a time and record validation or storage-path differences in the response.",
    "graphql": "Compare one baseline GraphQL operation with one approved field, variable, or introspection-related variation and record schema, authorization, and error-shape changes.",
    "http-request-smuggling": "Capture the exact baseline request framing and compare only one header-framing variation at a time while recording front-end versus back-end response mismatches.",
    "information-disclosure": "Capture the baseline error behavior, then compare one malformed but approved variant and note stack traces, verbose messages, or leaked identifiers.",
    "input-validation": "Vary one parameter at a time and compare status, error wording, reflection context, and schema-validation messages.",
    "insecure-design": "Replay the same workflow with one approved ordering, replay, or amount/state variation and record whether server-side guardrails stop the action.",
    "jwt-token": "Compare the same request across approved token states such as missing, expired, or lower-privilege tokens and record authorization deltas.",
    "mass-assignment": "Keep the route and object fixed, then compare one JSON field set at a time and record whether server-managed fields are silently accepted or ignored.",
    "open-redirect": "Keep the route fixed and compare how the application handles one approved redirect target variation, including status, Location, and allowlist behavior.",
    "path-traversal": "Keep the route fixed and compare one path or filename variation at a time while recording normalization, rejection, or retrieval differences.",
    "race-condition": "Replay the same approved state-changing action in parallel tabs or quick succession and record whether the server processes both operations inconsistently.",
    "security-misconfiguration": "Use Repeater to compare baseline headers across nearby authenticated, unauthenticated, and static responses and record missing protection headers.",
    "secret-exposure": "Compare baseline and verbose/error responses and record whether credentials, tokens, keys, or config fragments appear anywhere they should not.",
    "session-management": "Compare before-login, after-login, and after-logout behavior for the same route and note cookie rotation, invalidation, and cache differences.",
    "sqli": "Compare one approved baseline request against one minimally changed variant and record timing, status, and error-shape deltas without jumping to conclusions from one response.",
    "ssti": "Compare one template-looking input change at a time and record whether the application evaluates, escapes, or reflects template syntax as plain text.",
    "ssrf": "Record how the endpoint handles one approved URL-format change and note parsing, validation, redirect, or outbound-fetch indicators in the response only.",
    "xss": "Compare reflection context, encoding, and output placement across one approved input change at a time and note whether the reflection stays in HTML, attribute, script, or JSON context.",
    "xxe": "Compare XML parser behavior across one approved structural variation at a time and record parser errors, content-type expectations, and entity-handling differences.",
}

VULN_CLASS_KALI_TOOLS = {
    "access-control": [
        "curl: compare the same object ID across different sessions, roles, or tenants.",
        "ffuf: enumerate nearby identifiers or predictable object references only where the scope allows it.",
    ],
    "authentication": [
        "curl: replay token, cookie, and session transitions with explicit header changes.",
        "ffuf: enumerate nearby auth-related endpoints such as login, refresh, reset, and verify paths.",
    ],
    "business-logic": [
        "curl: replay the workflow one step at a time and try reordered, repeated, or skipped steps.",
        "ffuf: discover adjacent workflow endpoints, coupon paths, and state transition URLs.",
    ],
    "cache": [
        "curl: test cache-control, vary, and host/header permutations with repeated GET requests.",
        "nuclei: run focused cache and misconfiguration templates against only the approved host.",
    ],
    "command-injection": [
        "curl: send controlled separator, quoting, and time-delay variations manually before any heavier tooling.",
        "nuclei: run narrowly scoped command-injection templates if the endpoint is explicitly in scope.",
    ],
    "cors": [
        "curl: vary Origin and Access-Control headers to confirm reflection and credential behavior.",
        "nuclei: run CORS templates with the suggested tags after manual confirmation.",
    ],
    "crypto-failures": [
        "curl -I: compare transport and cookie/header protections across HTTP and HTTPS only where the target and policy allow both.",
        "testssl.sh: review TLS and certificate posture only if host-level testing is explicitly allowed in scope.",
    ],
    "csrf": [
        "curl: replay the state-changing request with modified Origin and Referer headers and without any token parameter.",
        "nuclei: use focused CSRF and form templates only after you confirm the endpoint is browser-reachable.",
    ],
    "deserialization": [
        "curl: replay one opaque object or serialized-style input at a time and record parser, type, or validation errors.",
        "nuclei: run narrowly scoped unsafe-deserialization templates only when the endpoint clearly processes serialized content.",
    ],
    "file-upload": [
        "curl: vary filename, content type, extension, and multipart boundaries in a controlled way.",
        "ffuf: discover upload-adjacent retrieval or preview paths if the application stores uploads under web paths.",
    ],
    "graphql": [
        "curl: replay one GraphQL query or variable change at a time and compare schema, authorization, and error responses.",
        "graphql-voyager / introspection tooling: only after confirming GraphQL is actually exposed and introspection is allowed in scope.",
    ],
    "http-request-smuggling": [
        "curl: preserve exact framing and compare one Content-Length or Transfer-Encoding difference at a time before heavier tooling.",
        "Burp Repeater: use HTTP/1 and HTTP/2 request editors to compare front-end and back-end handling instead of broad fuzzing first.",
    ],
    "information-disclosure": [
        "curl: trigger controlled malformed inputs and compare verbose error behavior across methods and headers.",
        "whatweb: fingerprint the exposed stack only if broader host enumeration is in scope.",
    ],
    "input-validation": [
        "curl: mutate types, missing fields, extra fields, and duplicate parameters one change at a time.",
        "ffuf: fuzz parameter values or names around the confirmed JSON or form surface with small wordlists.",
    ],
    "insecure-design": [
        "curl: replay one workflow step at a time and compare replays, skips, or reordering against the server-side state changes.",
        "Burp Repeater: keep separate tabs for each step so you can compare intended versus bypassed workflows cleanly.",
    ],
    "jwt-token": [
        "jwt-tool: inspect claims, algorithms, and token structure before attempting any scoped validation tests.",
        "curl: replay lower-privilege, expired, or role-changed tokens against the same object identifiers.",
    ],
    "mass-assignment": [
        "curl: add one privileged JSON field at a time and compare whether the server accepts, ignores, or normalizes it.",
        "ffuf: fuzz only the confirmed JSON keys if the API surface is clearly in scope and rate limits allow it.",
    ],
    "open-redirect": [
        "curl: test absolute URLs, protocol-relative URLs, encoded values, and allowlist bypass variants.",
        "ffuf: enumerate nearby redirect and return-style parameter names if discovery is in scope.",
    ],
    "path-traversal": [
        "curl: vary one filename or path sequence at a time and compare normalization or retrieval differences.",
        "ffuf: enumerate nearby download, export, and static-file style parameters only if discovery is allowed.",
    ],
    "race-condition": [
        "curl: replay the same state-changing request quickly in parallel tabs or terminals and compare the resulting state.",
        "Burp Repeater: use separate tabs to coordinate same-request replays and record which action wins.",
    ],
    "security-misconfiguration": [
        "curl -I: compare response headers across authenticated, unauthenticated, and static asset paths.",
        "dirsearch: enumerate nearby panels, backups, and static content if content discovery is in scope.",
    ],
    "secret-exposure": [
        "curl: compare normal and verbose/error responses for leaked tokens, keys, stack traces, or config fragments.",
        "trufflehog / regex grep: scan only downloaded or shared response artifacts if the program allows local secret triage.",
    ],
    "session-management": [
        "curl: compare cookie flags and session transitions before login, after login, and after logout.",
        "nuclei: run session and cookie-focused misconfiguration templates with narrow scope.",
    ],
    "sqli": [
        "curl: validate one quote, one boolean, and one timing variation manually before heavier tooling.",
        "sqlmap: only after a manual hypothesis exists and the target is explicitly in scope for controlled validation.",
    ],
    "ssti": [
        "curl: replay one template-syntax variation at a time and compare whether the application evaluates or escapes it.",
        "Burp Repeater: confirm rendering context before you consider any engine-specific follow-up.",
    ],
    "ssrf": [
        "curl: mutate URL parameters, schemes, ports, and redirect targets one control at a time.",
        "nuclei: use focused SSRF templates only when outbound-request testing is approved in scope.",
    ],
    "xss": [
        "curl: confirm which parameter reflects and in what response context before broader testing.",
        "ffuf: fuzz the confirmed reflected parameter with a small payload set if the endpoint is in scope.",
    ],
    "xxe": [
        "curl: send controlled XML parser variations, external entity markers, and harmless DTD probes one at a time.",
        "nuclei: run scoped XXE templates only after confirming the endpoint actually parses XML.",
    ],
}


def truncate_text(text: str, limit: int, label: str) -> str:
    if len(text) <= limit:
        return text
    omitted = len(text) - limit
    return f"{text[:limit]}\n[{label} truncated, omitted {omitted} characters]"


def parse_http_message(raw_message: str) -> dict:
    if not raw_message:
        return {"start_line": "", "headers": {}, "header_lines": [], "body": ""}

    normalized = raw_message.replace("\r\n", "\n")
    head, separator, body = normalized.partition("\n\n")
    lines = [line for line in head.split("\n") if line.strip()]

    if not lines:
        return {"start_line": "", "headers": {}, "header_lines": [], "body": normalized}

    headers = {}
    header_lines = []
    for line in lines[1:]:
        header_lines.append(line.strip())
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

    return {
        "start_line": lines[0].strip(),
        "headers": headers,
        "header_lines": header_lines,
        "body": body if separator else "",
    }


def summarize_http_message(
    raw_message: str,
    label: str,
    max_header_lines: int,
    max_body_chars: int,
) -> str:
    parsed = parse_http_message(raw_message)
    if not parsed["start_line"]:
        return f"{label}: <empty>"

    extra_headers = parsed["header_lines"][:max_header_lines]
    omitted_headers = max(0, len(parsed["header_lines"]) - len(extra_headers))
    parts = [
        f"{label} start line: {parsed['start_line']}",
        f"{label} headers:",
        "\n".join(extra_headers) if extra_headers else "<none>",
    ]

    if omitted_headers:
        parts.append(f"[{label} headers truncated, omitted {omitted_headers} lines]")

    if parsed["body"] or "\n\n" in raw_message.replace("\r\n", "\n"):
        body_preview = truncate_text(parsed["body"], max_body_chars, f"{label} body")
        parts.append(f"{label} body preview:\n{body_preview or '<empty>'}")

    return "\n\n".join(parts)


def load_recipes() -> list[dict]:
    recipes = []
    if not RECIPE_DIR.exists():
        return recipes

    for recipe_file in sorted(RECIPE_DIR.glob("*.json")):
        data = json.loads(recipe_file.read_text(encoding="utf-8"))
        if isinstance(data, list):
            recipes.extend(data)
    return recipes


def available_vuln_classes() -> list[str]:
    classes = list(DEFAULT_VULN_CLASSES)
    for recipe in load_recipes():
        vuln_class = (recipe.get("vuln_class") or "").strip()
        if vuln_class and vuln_class not in classes:
            classes.append(vuln_class)
    return classes


def resolve_review_scope(payload) -> dict:
    profile = get_profile(getattr(payload, "selected_profile", ""))
    include = [
        value.strip().lower()
        for value in getattr(payload, "review_scope_include_classes", []) or profile["default_review_scope"]
        if (value or "").strip()
    ]
    exclude = [
        value.strip().lower()
        for value in getattr(payload, "review_scope_exclude_classes", []) or []
        if (value or "").strip()
    ]

    allowed = [value for value in include if value not in exclude]
    if not allowed:
        allowed = [value for value in profile["default_review_scope"] if value not in exclude]
    return {
        "profile": profile,
        "allowed_classes": allowed,
        "suppressed_classes": exclude,
    }


def _manual_tooling_for_matches(features: dict, matched_recipes: list[dict]) -> list[str]:
    summarized = summarize_tool_recommendations(recommend_tools(features, matched_recipes))
    if summarized:
        return summarized[:8]

    suggestions = {}

    def add_tool(entry: str) -> None:
        tool_name = entry.split(":", 1)[0].strip().lower()
        suggestions[tool_name] = entry

    for item in GENERAL_KALI_TOOLS:
        add_tool(item)

    for recipe in matched_recipes[:4]:
        for item in recipe.get("recommended_tools", []):
            add_tool(item)
        for item in VULN_CLASS_KALI_TOOLS.get(recipe.get("vuln_class", ""), []):
            add_tool(item)

    return list(suggestions.values())[:8]


def _repeater_guidance(features: dict, matched_recipes: list[dict]) -> list[str]:
    guidance = list(GENERAL_REPEATER_GUIDANCE)
    seen_classes = set()

    for recipe in matched_recipes[:4]:
        vuln_class = (recipe.get("vuln_class") or "").strip().lower()
        if not vuln_class or vuln_class in seen_classes:
            continue
        seen_classes.add(vuln_class)
        suggestion = VULN_CLASS_REPEATER_GUIDANCE.get(vuln_class)
        if suggestion:
            guidance.append(suggestion)

    if "request_has_identifier_params" in features["signals"]:
        guidance.append("Keep the path and method fixed, then compare only the identifier-related parameters and record any ownership or authorization changes.")
    if "response_has_html" in features["signals"]:
        guidance.append("Use Burp Repeater's render and raw views together so you can compare both header changes and visible body differences.")

    deduped = []
    for item in guidance:
        if item not in deduped:
            deduped.append(item)
    return deduped[:6]


def _shell_quote(value: str) -> str:
    return "'" + (value or "").replace("'", "'\"'\"'") + "'"


def _shell_quote_argument(value: str) -> str:
    return '"' + (value or "").replace('"', '\\"') + '"'


def _base_target_url(target_url: str) -> str:
    parsed = urlparse(target_url or "")
    if not parsed.scheme or not parsed.netloc:
        return target_url or ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _pick_param(features: dict, candidates: set[str] | None = None) -> str:
    for name in features["param_names"]:
        if _leaf_param_matches(name, candidates):
            return name
    return features["param_names"][0] if features["param_names"] else "id"


def _record_param_source(param_locations: dict[str, str], name: str, location: str) -> None:
    current = param_locations.get(name)
    if not current:
        param_locations[name] = location
        return
    if location in current.split(" + "):
        return
    param_locations[name] = current + " + " + location


def _first_scalar_param_value(value) -> str:
    if isinstance(value, list):
        if not value:
            return ""
        return _first_scalar_param_value(value[0])
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return ""


def _flatten_json_paths(value, prefix: str = "") -> list[tuple[str, str]]:
    entries = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            entries.extend(_flatten_json_paths(child, child_prefix))
    elif isinstance(value, list):
        for index, child in enumerate(value[:5]):
            child_prefix = f"{prefix}[{index}]"
            entries.extend(_flatten_json_paths(child, child_prefix))
    else:
        scalar = _first_scalar_param_value(value)
        if prefix:
            entries.append((prefix, scalar))
    return entries


def _set_nested_json_value(target: dict, path: str, value):
    if not path:
        return
    tokens = re.findall(r"([^.\\[\\]]+)|\\[(\\d+)\\]", path)
    current = target
    normalized = []
    for name_token, index_token in tokens:
        normalized.append(name_token if name_token else int(index_token))
    for token in normalized[:-1]:
        if isinstance(token, int):
            if not isinstance(current, list):
                return
            if token >= len(current):
                return
            current = current[token]
        else:
            if not isinstance(current, dict):
                return
            current = current.setdefault(token, {})
    last = normalized[-1]
    if isinstance(last, int):
        if isinstance(current, list) and last < len(current):
            current[last] = value
    elif isinstance(current, dict):
        current[last] = value


def _leaf_param_matches(name: str, candidates: set[str] | None) -> bool:
    if candidates is None:
        return True
    leaf = re.split(r"[.\\[]", name.lower())[0]
    tail = re.split(r"[.\\[]", name.lower())[-1].rstrip("]")
    return name.lower() in candidates or leaf in candidates or tail in candidates


def _parse_response_delta_text(text: str) -> list[str]:
    delta = (text or "").strip()
    if not delta:
        return []
    notes = []
    status_match = re.search(r"(\d{3})\s*(?:->|to)\s*(\d{3})", delta)
    if status_match:
        notes.append(f"Observed status delta: {status_match.group(1)} -> {status_match.group(2)}.")
    length_match = re.search(r"(?:length|size)\s*(?:changed|delta|:)?\s*([+-]?\d+)", delta, flags=re.IGNORECASE)
    if length_match:
        notes.append(f"Observed body length delta: {length_match.group(1)}.")
    time_match = re.search(r"(?:time|timing|latency)\s*(?:changed|delta|:)?\s*([+-]?\d+(?:\.\d+)?)\s*(ms|s|sec|seconds)?", delta, flags=re.IGNORECASE)
    if time_match:
        unit = time_match.group(2) or "ms"
        notes.append(f"Observed timing delta: {time_match.group(1)} {unit}.")
    if "redirect" in delta.lower():
        notes.append("Operator noted a redirect behavior change.")
    if "error" in delta.lower():
        notes.append("Operator noted an error-shape change.")
    if not notes:
        notes.append("Operator supplied a response-delta note for this request.")
    return notes


def _scanner_issue_selected(payload) -> bool:
    annotations = {item.strip().lower() for item in (getattr(payload, "annotations", None) or []) if item}
    source_tool = (getattr(payload, "source_tool", "") or "").strip().lower()
    return (
        "audit_issue_selected" in annotations
        or "scanner_auto_triage" in annotations
        or "scanner_results_context" in annotations
        or "audit-issue" in source_tool
    )


def _structured_issue_family_from_text(text: str) -> str:
    normalized = (text or "").strip().lower()
    if not normalized:
        return ""
    if "cross-site scripting" in normalized or " xss" in normalized or normalized.startswith("xss"):
        return "xss"
    if "direct object reference" in normalized or "idor" in normalized or "access control" in normalized:
        return "access-control"
    if "server-side request forgery" in normalized or "ssrf" in normalized:
        return "ssrf"
    if "sql injection" in normalized or " sqli" in normalized:
        return "sqli"
    if "authentication" in normalized or "session" in normalized:
        return "authentication"
    if "template injection" in normalized or "ssti" in normalized:
        return "ssti"
    return ""


def _structured_dashboard_issue_class(payload) -> str:
    issue = getattr(payload, "burp_dashboard_issue", None) or {}
    if not isinstance(issue, dict):
        return ""
    issue_text = " ".join(
        str(issue.get(key) or "").strip()
        for key in ("name", "title", "issue_name", "detail", "issue_detail")
    ).strip()
    return _structured_issue_family_from_text(issue_text)


def _anchor_recipe_from_payload(payload, vuln_class: str) -> dict:
    issue = getattr(payload, "burp_dashboard_issue", None) or {}
    issue_name = str((issue or {}).get("name") or (issue or {}).get("title") or "").strip()
    issue_detail = str((issue or {}).get("detail") or (issue or {}).get("issue_detail") or "").strip()
    title_map = {
        "xss": "Burp Scanner XSS Review",
        "access-control": "Burp Scanner Access Control Review",
        "ssrf": "Burp Scanner SSRF Review",
        "sqli": "Burp Scanner SQL Injection Review",
        "authentication": "Burp Scanner Authentication Review",
        "ssti": "Burp Scanner Template Injection Review",
    }
    return {
        "title": title_map.get(vuln_class, f"Burp Scanner {vuln_class} Review"),
        "vuln_class": vuln_class,
        "summary": issue_name or f"Selected Burp scanner issue anchor for {vuln_class}.",
        "severity": str((issue or {}).get("severity") or "high").strip().lower() or "high",
        "evidence": [
            item for item in [
                issue_name,
                issue_detail,
                "Selected Burp scanner issue was forwarded as the primary anchor for this request family.",
            ]
            if item
        ],
    }


def _scanner_aligned_classes(payload, bapp_summary: dict) -> set[str]:
    aligned = set()
    if not _scanner_issue_selected(payload):
        return aligned

    anchor_class = _structured_dashboard_issue_class(payload)
    if anchor_class:
        aligned.add(anchor_class)
        return aligned

    for finding in bapp_summary.get("findings", []):
        tool = (finding.get("tool") or "").strip().lower()
        vuln_class = (finding.get("vuln_class") or "").strip().lower()
        if vuln_class and tool == "burp scanner":
            aligned.add(vuln_class)

    if not aligned:
        aligned.update(
            (item or "").strip().lower()
            for item in bapp_summary.get("suggested_vuln_classes", [])
            if item
        )
    return {item for item in aligned if item}


def _burp_insertion_point_summary(payload) -> str:
    text = " ".join([
        (getattr(payload, "tool_results_text", "") or ""),
        (getattr(payload, "bapp_findings_text", "") or ""),
    ]).lower()
    if "request body" in text:
        return "request body"
    if "query string" in text or "query parameter" in text:
        return "query string"
    if "cookie" in text:
        return "cookie"
    if "header" in text:
        return "header"
    if "path" in text:
        return "path"
    return ""


def _request_identity_summary(features: dict, payload) -> str:
    query_names = sorted((features.get("query_params") or {}).keys())
    form_names = sorted((features.get("form_params") or {}).keys())
    json_keys = sorted((features.get("json_body") or {}).keys())[:8]
    identity_parts = [
        f"{(features.get('method') or '').upper()} {features.get('path') or '/'}",
        f"request content-type={(features.get('request_content_type') or '<none>')}",
        f"response content-type={(features.get('response_content_type') or '<none>')}",
    ]
    if query_names:
        identity_parts.append("query keys=" + ", ".join(query_names[:8]))
    if form_names:
        identity_parts.append("form keys=" + ", ".join(form_names[:8]))
    if json_keys:
        identity_parts.append("json keys=" + ", ".join(json_keys))
    insertion_point = _burp_insertion_point_summary(payload)
    if insertion_point:
        identity_parts.append("burp insertion point=" + insertion_point)
    return " | ".join(identity_parts)


def _score_recipe_confidence(payload, recipe: dict, features: dict, bapp_summary: dict, collaborator_summary: dict) -> tuple[float, list[str]]:
    vuln_class = (recipe.get("vuln_class") or "general").strip().lower()
    evidence_count = max(1, len(recipe.get("evidence", [])))
    score = min(0.32 + (0.09 * evidence_count), 0.84)
    reasons = [f"{evidence_count} deterministic signal(s) matched the [{vuln_class}] playbook."]
    anchor_class = _structured_dashboard_issue_class(payload)

    if recipe.get("severity") == "high":
        score = min(score + 0.05, 0.92)
        reasons.append("The matched playbook is high severity.")

    scanner_classes = _scanner_aligned_classes(payload, bapp_summary)
    if vuln_class in scanner_classes:
        boost = 0.16 if _scanner_issue_selected(payload) else 0.08
        score = min(score + boost, 0.96)
        reasons.append("Burp Scanner already marked this request with the same vulnerability class.")
    elif _scanner_issue_selected(payload) and scanner_classes:
        score = max(score - 0.05, 0.18)
        reasons.append("Burp Scanner marked a different primary class, so this hypothesis stays conservative.")

    if anchor_class and vuln_class == anchor_class:
        score = min(score + 0.18, 0.98)
        reasons.append("The selected Burp dashboard issue explicitly anchors this vulnerability class.")
    elif anchor_class and vuln_class != anchor_class:
        score = max(score - 0.16, 0.12)
        reasons.append("The selected Burp dashboard issue anchors a different primary class, so this recipe is deprioritized.")

    if vuln_class in {(item or "").strip().lower() for item in bapp_summary.get("suggested_vuln_classes", []) if item}:
        score = min(score + 0.05, 0.96)
        reasons.append("Burp findings or BApp evidence also align with this class.")

    signal_hint = REQUEST_SHAPE_CONFIDENCE_HINTS.get(vuln_class)
    if signal_hint and signal_hint[0] in features.get("signals", set()):
        score = min(score + 0.04, 0.96)
        reasons.append(signal_hint[1])

    if (getattr(payload, "response_delta_text", "") or "").strip():
        score = min(score + 0.03, 0.96)
        reasons.append("An operator-supplied response delta was captured for this request.")

    if getattr(payload, "evidence_timeline_entries", None):
        score = min(score + 0.03, 0.96)
        reasons.append("The operator already captured an evidence timeline for this request.")

    if vuln_class in {"xxe", "ssrf"} and collaborator_summary.get("has_positive_interaction"):
        score = min(score + 0.10, 0.97)
        reasons.append("Collaborator evidence supports a callback-oriented class on this request.")
    elif vuln_class in {"xxe", "ssrf"} and collaborator_summary.get("has_negative_interaction"):
        score = max(score - 0.04, 0.18)
        reasons.append("Collaborator notes say no callback was observed, so the impact confidence stays conservative.")

    if vuln_class == "xxe" and collaborator_summary.get("dns_hits", 0):
        score = min(score + 0.05, 0.98)
        reasons.append("Collaborator DNS interactions fit outbound entity resolution or external lookup behavior.")
    if vuln_class == "ssrf" and (collaborator_summary.get("http_hits", 0) or collaborator_summary.get("dns_hits", 0)):
        score = min(score + 0.05, 0.98)
        reasons.append("Collaborator callback traffic fits a server-side fetch or outbound request hypothesis.")

    insertion_point = _burp_insertion_point_summary(payload)
    if vuln_class == "xxe" and insertion_point == "request body":
        score = min(score + 0.04, 0.97)
        reasons.append("Burp highlighted the request body, which fits XML parser confirmation work.")
    if vuln_class in {"sqli", "xss", "access-control"} and insertion_point in {"query string", "path", "cookie", "header"}:
        score = min(score + 0.03, 0.97)
        reasons.append(f"Burp highlighted the {insertion_point}, which fits this confirmation path.")

    return round(max(0.12, min(score, 0.98)), 2), reasons


def _rank_recipes_for_payload(payload, features: dict, recipes: list[dict], bapp_summary: dict) -> list[dict]:
    if not recipes:
        return []

    collaborator_summary = summarize_collaborator_evidence(getattr(payload, "collaborator_evidence_text", "") or "")
    ranked = []
    for index, recipe in enumerate(recipes):
        confidence, _ = _score_recipe_confidence(payload, recipe, features, bapp_summary, collaborator_summary)
        evidence_count = len(recipe.get("evidence", []) or [])
        severity = (recipe.get("severity") or "").strip().lower()
        ranked.append((confidence, evidence_count, severity == "high", index, recipe))

    ranked.sort(key=lambda item: (-item[0], -item[1], -int(item[2]), item[3]))
    return [item[4] for item in ranked]


def _target_descriptor_for_class(features: dict, vuln_class: str) -> tuple[str, str]:
    if vuln_class == "security-misconfiguration":
        return "response headers", "response comparison"
    if vuln_class == "crypto-failures":
        return "transport security, cookie flags, and any exposed key material", "request/response metadata"
    if vuln_class == "csrf":
        return "`Origin` / `Referer` headers and any anti-CSRF field", "headers plus state-changing form/body fields"
    if vuln_class == "deserialization":
        return "serialized blob carrier or object-style field", "request body or encoded parameter"
    if vuln_class in {"authentication", "jwt-token"}:
        return "`Authorization` header or session cookie", "request headers"
    if vuln_class == "graphql":
        return "`query` / `variables` body fields", "GraphQL request body"
    if vuln_class == "http-request-smuggling":
        return "`Transfer-Encoding` / `Content-Length` header combination", "request headers"
    if vuln_class == "mass-assignment":
        return "privileged JSON fields such as `role`, `admin`, or `permissions`", "json body"
    if vuln_class == "path-traversal":
        return "file or path input parameter", "query string or request body"
    if vuln_class == "race-condition":
        return "the state-changing action and target object identifier", "request body or workflow step"
    if vuln_class == "secret-exposure":
        return "response body secret-like material", "response comparison"
    if vuln_class == "session-management":
        return "session cookie value and login/logout transitions", "cookies and auth flow state"
    if vuln_class == "ssti":
        return "template or render-controlled input", "request parameter or body field"
    if vuln_class == "cache":
        return "`Cache-Control`, `Pragma`, and the same cacheable route", "request headers plus the captured GET route"
    if vuln_class == "cors":
        return "`Origin` header", "request headers"
    if vuln_class == "file-upload":
        return "multipart filename, content type, and extension fields", "multipart body"
    if vuln_class == "insecure-design":
        return "the state-changing workflow input", "workflow request body or identifier parameter"
    if vuln_class == "xxe":
        return "XML body structure", "request body"

    target_param = _pick_param(features, CLASS_TARGET_PARAM_CANDIDATES.get(vuln_class))
    param_locations = features.get("param_locations", {})
    return f"`{target_param}`", param_locations.get(target_param, "request parameter")


def _apply_source_tool_bias(payload, steps: list[str]) -> list[str]:
    source_tool = (getattr(payload, "source_tool", "") or "").strip().lower()
    if not steps:
        return steps
    if "intruder" in source_tool:
        biased = ["Primary lane [intruder]: stay in Intruder for the next step and keep the payload set short, ordered, and evidence-driven."]
        for item in steps:
            if "Repeater" in item and "Intruder" not in item:
                continue
            biased.append(item)
        return biased[:6]
    if "repeater" in source_tool:
        biased = ["Primary lane [repeater]: stay in Repeater for the next step and confirm one delta at a time before considering Intruder."]
        for item in steps:
            if item.lower().startswith("intruder focus"):
                continue
            biased.append(item)
        return biased[:6]
    return steps


def _extract_first_int(text: str) -> str:
    match = re.search(r"(\d+)", text or "")
    return match.group(1) if match else ""


def _split_nonempty_lines(text: str) -> list[str]:
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def _header_flags_for_tool(tool_name: str, payload) -> str:
    headers = _split_nonempty_lines(getattr(payload, "custom_headers_text", "") or "")
    if not headers:
        return ""

    help_text = combined_tool_help_text(getattr(payload, "tool_help_text", "") or "")
    supported_by_help = help_text.lower()
    if tool_name == "curl":
        return "".join(f" -H {_shell_quote_argument(header)}" for header in headers[:4])
    if tool_name == "nuclei" and ("-H" in help_text or "--header" in supported_by_help):
        return "".join(f" -H {_shell_quote_argument(header)}" for header in headers[:4])
    if tool_name == "ffuf" and ("-H" in help_text or "--header" in supported_by_help):
        return "".join(f" -H {_shell_quote_argument(header)}" for header in headers[:4])
    return ""


def _rate_limit_flags_for_tool(tool_name: str, payload) -> str:
    rate_limit = _extract_first_int(getattr(payload, "rate_limit_text", "") or "")
    concurrency = _extract_first_int(getattr(payload, "max_concurrency_text", "") or "")
    help_text = combined_tool_help_text(getattr(payload, "tool_help_text", "") or "")
    lower_help = help_text.lower()
    flags = []

    if tool_name == "nuclei":
        if rate_limit and "-rate-limit" in lower_help:
            flags.append(f"-rate-limit {rate_limit}")
        if concurrency and re.search(r"(^|\s)-c(\s|$)", help_text):
            flags.append(f"-c {concurrency}")
    elif tool_name == "ffuf":
        if rate_limit and re.search(r"(^|\s)-rate(\s|$)", help_text):
            flags.append(f"-rate {rate_limit}")
        if concurrency and re.search(r"(^|\s)-t(\s|$)", help_text):
            flags.append(f"-t {concurrency}")
    elif tool_name == "dirsearch":
        if concurrency and ("--threads" in lower_help or "-t " in lower_help):
            flags.append(f"--threads {concurrency}")
        if rate_limit and "--max-rate" in lower_help:
            flags.append(f"--max-rate {rate_limit}")
    elif tool_name == "sqlmap":
        if concurrency and "--threads" in lower_help:
            flags.append(f"--threads {concurrency}")

    return (" " + " ".join(flags)) if flags else ""


def _scope_note(payload) -> str:
    include = (getattr(payload, "scope_includes_text", "") or "").strip()
    exclude = (getattr(payload, "scope_excludes_text", "") or "").strip()
    notes = []
    if include:
        notes.append(f"In-scope: {include}")
    if exclude:
        notes.append(f"Out-of-scope: {exclude}")
    return " | ".join(notes)


def _method_supports_body(method: str) -> bool:
    return (method or "").upper() in {"POST", "PUT", "PATCH", "DELETE", "OPTIONS"}


def _content_type_flag(features: dict, curl_headers: str) -> str:
    request_content_type = (features.get("request_content_type") or "").strip()
    if not request_content_type:
        return ""
    if "content-type:" in (curl_headers or "").lower():
        return ""
    return f" -H {_shell_quote_argument('Content-Type: ' + request_content_type)}"


def _updated_target_url(target_url: str, param_name: str, param_value: str) -> str:
    parsed = urlparse(target_url or "")
    if not parsed.scheme and not parsed.netloc:
        return target_url or ""
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param_name] = [param_value]
    return parsed._replace(query=urlencode(query, doseq=True)).geturl()


def _updated_form_body(features: dict, param_name: str | None = None, param_value: str | None = None) -> str:
    form_params = {
        key: list(values)
        for key, values in (features.get("form_params") or {}).items()
    }
    if param_name:
        form_params[param_name] = [param_value or ""]
    return urlencode(form_params, doseq=True)


def _updated_json_body(features: dict, param_name: str | None = None, param_value: str | None = None) -> str:
    json_body = features.get("json_body")
    if isinstance(json_body, dict):
        updated = dict(json_body)
        if param_name:
            if "." in param_name or "[" in param_name:
                _set_nested_json_value(updated, param_name, param_value)
            else:
                updated[param_name] = param_value
        return json.dumps(updated, ensure_ascii=True)
    if param_name:
        return json.dumps({param_name: param_value}, ensure_ascii=True)
    return ""


def _request_body_flags(features: dict, curl_headers: str, param_name: str | None = None, param_value: str | None = None) -> str:
    method = (features.get("method") or "GET").upper()
    if not _method_supports_body(method):
        return ""

    location = (features.get("param_locations") or {}).get(param_name or "", "")
    request_body = ((features.get("request_summary") or {}).get("body") or "").strip()
    request_content_type = (features.get("request_content_type") or "").lower()
    content_type_flag = _content_type_flag(features, curl_headers)

    if "form body" in location or ("application/x-www-form-urlencoded" in request_content_type and request_body):
        body = _updated_form_body(features, param_name, param_value)
        if body:
            return f"{content_type_flag} --data {_shell_quote(body)}"
    if "json body" in location or ("application/json" in request_content_type and request_body):
        body = _updated_json_body(features, param_name, param_value)
        if body:
            return f"{content_type_flag} --data-raw {_shell_quote(body)}"
    if request_body:
        return f"{content_type_flag} --data-raw {_shell_quote(request_body)}"
    return ""


def _curl_request_command(
    target_url: str,
    features: dict,
    curl_headers: str,
    *,
    param_name: str | None = None,
    param_value: str | None = None,
    extra_headers: list[str] | None = None,
    force_method: str | None = None,
    use_head: bool = False,
) -> str:
    method = (force_method or features.get("method") or "GET").upper()
    location = (features.get("param_locations") or {}).get(param_name or "", "")
    effective_url = target_url
    if param_name and "query string" in location:
        effective_url = _updated_target_url(target_url, param_name, param_value or "")

    command = "curl -k -I" if use_head else "curl -i"
    if not use_head and method != "GET":
        command += f" -X {method}"
    command += f" {_shell_quote(effective_url)}"
    for header in extra_headers or []:
        command += f" -H {_shell_quote_argument(header)}"
    command += curl_headers
    if not use_head:
        command += _request_body_flags(features, curl_headers, param_name, param_value)
    return command


def _command_templates(payload, features: dict, matched_recipes: list[dict], nuclei_tags: str, seclists_path: str) -> list[str]:
    return _command_template_service.build_command_templates(
        payload,
        features,
        matched_recipes,
        nuclei_tags,
        seclists_path,
        {
            "base_target_url": _base_target_url,
            "header_flags_for_tool": _header_flags_for_tool,
            "rate_limit_flags_for_tool": _rate_limit_flags_for_tool,
            "curl_request_command": _curl_request_command,
            "shell_quote": _shell_quote,
            "shell_quote_argument": _shell_quote_argument,
            "pick_param": _pick_param,
            "updated_form_body": _updated_form_body,
            "updated_json_body": _updated_json_body,
            "method_supports_body": _method_supports_body,
            "scope_note": _scope_note,
            "IDENTIFIER_PARAMS": IDENTIFIER_PARAMS,
            "REDIRECT_PARAMS": REDIRECT_PARAMS,
            "URL_INPUT_PARAMS": URL_INPUT_PARAMS,
            "SEARCH_PARAMS": SEARCH_PARAMS,
            "PATH_INPUT_PARAMS": PATH_INPUT_PARAMS,
            "GRAPHQL_PARAM_NAMES": GRAPHQL_PARAM_NAMES,
            "TEMPLATE_INPUT_PARAMS": TEMPLATE_INPUT_PARAMS,
            "PRIVILEGED_JSON_KEYS": PRIVILEGED_JSON_KEYS,
        },
    )


def _command_tool_name(command: str) -> str:
    return _command_template_service.command_tool_name(command)


def _label_manual_commands(commands: list[str], payload) -> list[str]:
    return _command_template_service.label_manual_commands(commands, payload, get_tool_inventory())


def _build_request_plan(
        primary_recipe: dict | None,
        features: dict,
        manual_tooling: list[str],
        manual_commands: list[str],
        payload_recommendations: list[str],
        preferred_burp_tools: list[str],
        payload=None,
) -> tuple[str, list[str]]:
    source_tool = (getattr(payload, "source_tool", "") or "").strip().lower()
    source_mode = "intruder" if "intruder" in source_tool else "repeater" if "repeater" in source_tool else ""
    if primary_recipe is None:
        primary_mode = "Intruder first with a very short custom list, but keep the baseline request fixed for comparison." if source_mode == "intruder" else "Repeater first, Intruder only after one field proves meaningful."
        return (
            "Capture one untouched baseline and stay in the current Burp tool lane until the first meaningful delta is proven.",
            [
                "Target parameter: first responsive parameter or current route.",
                f"Primary mode: {primary_mode}",
                f"Best Burp helper: {_best_burp_helper_label(preferred_burp_tools)}",
                f"Starter payloads: {payload_recommendations[0] if payload_recommendations else 'build a short custom list from the baseline.'}",
                f"Best command: {manual_commands[0] if manual_commands else 'curl replay of the baseline request.'}",
            ],
        )

    vuln_class = (primary_recipe.get("vuln_class") or "general").strip().lower()
    title = primary_recipe.get("title") or "Manual review"
    target_label, target_location = _target_descriptor_for_class(features, vuln_class)
    if source_mode == "intruder":
        mode = "Intruder first with a narrow custom list, then Repeater only if a clean baseline comparison is needed."
    elif source_mode == "repeater":
        mode = "Repeater first and stay there until one approved delta is proven."
    else:
        mode = "Repeater first" if vuln_class in INTRUDER_DEEMPHASIZED_CLASSES else "Repeater then Intruder"
    primary_action = (
        f"{title}: test {target_label} in {target_location} with one approved variation, keep the baseline fixed, and confirm the delta before moving wider."
    )
    plan = [
        f"Hypothesis: [{vuln_class}] {title}",
        f"Target parameter: {target_label} in {target_location}",
        f"Primary mode: {mode}",
        f"Best Burp helper: {_best_burp_helper_label(preferred_burp_tools)}",
        f"Best Kali tool: {manual_tooling[0] if manual_tooling else 'curl'}",
        f"Best command: {manual_commands[0] if manual_commands else 'No command template available yet.'}",
        f"Starter payloads: {payload_recommendations[0] if payload_recommendations else 'No payload starter list available yet.'}",
    ]
    return primary_action, plan[:6]


def extract_features(payload) -> dict:
    constants = {
        "security_headers": SECURITY_HEADERS,
        "identifier_params": IDENTIFIER_PARAMS,
        "redirect_params": REDIRECT_PARAMS,
        "url_input_params": URL_INPUT_PARAMS,
        "search_params": SEARCH_PARAMS,
        "path_input_params": PATH_INPUT_PARAMS,
        "template_input_params": TEMPLATE_INPUT_PARAMS,
        "template_marker_patterns": ("{{", "}}", "{%", "%}", "${", "#{", "<%", "%>"),
        "privileged_json_keys": PRIVILEGED_JSON_KEYS,
        "graphql_param_names": GRAPHQL_PARAM_NAMES,
        "internal_path_tokens": INTERNAL_PATH_TOKENS,
        "api_version_path_regex": API_VERSION_PATH_REGEX,
    }
    return _extract_rule_features(
        payload,
        parse_http_message=parse_http_message,
        first_scalar_param_value=_first_scalar_param_value,
        flatten_json_paths=_flatten_json_paths,
        record_param_source=_record_param_source,
        parse_response_delta_text=_parse_response_delta_text,
        constants=constants,
    )


def _matches_recipe(recipe: dict, features: dict) -> bool:
    return _matches_recipe_via_service(recipe, features, leaf_param_matches=_leaf_param_matches)


def match_recipes(features: dict, allowed_classes: list[str] | None = None, suppressed_classes: list[str] | None = None) -> list[dict]:
    return _match_rule_recipes(
        features,
        recipes=load_recipes(),
        signal_descriptions=SIGNAL_DESCRIPTIONS,
        leaf_param_matches=_leaf_param_matches,
        allowed_classes=allowed_classes,
        suppressed_classes=suppressed_classes,
    )


def aggregate_recipe_output(payload, features: dict, matched_recipes: list[dict], review_scope: dict, bapp_summary: dict) -> dict:
    helpers = {
        "loaded_burp_helpers": _loaded_burp_helpers,
        "summarize_collaborator_evidence": summarize_collaborator_evidence,
        "scanner_aligned_classes": _scanner_aligned_classes,
        "request_identity_summary": _request_identity_summary,
        "manual_tooling_for_matches": _manual_tooling_for_matches,
        "repeater_guidance": _repeater_guidance,
        "payload_recommendations": _payload_recommendations,
        "build_local_resource_hints": _build_local_resource_hints,
        "query_guidance_packs": _query_guidance_packs,
        "recommend_bchecks": recommend_bchecks,
        "summarize_recommendations": summarize_recommendations,
        "label_manual_commands": _label_manual_commands,
        "command_templates": _command_templates,
        "build_request_plan": _build_request_plan,
        "build_impact_paths": _build_impact_paths,
        "project_readiness": _project_readiness,
        "build_burp_action_checklist": _build_burp_action_checklist,
        "build_burp_settings_recommendations": _build_burp_settings_recommendations,
        "inventory_summary_text": inventory_summary_text,
        "build_confirmation_playbooks": build_confirmation_playbooks,
        "recommend_tools": recommend_tools,
        "score_recipe_confidence": _score_recipe_confidence,
        "apply_source_tool_bias": _apply_source_tool_bias,
        "build_primary_suggestion_steps": _build_primary_suggestion_steps,
    }
    return _build_deterministic_aggregate(
        payload,
        features,
        matched_recipes,
        review_scope,
        bapp_summary,
        helpers=helpers,
    )


def estimate_complexity(payload, features: dict, matched_recipes: list[dict]) -> dict:
    request_size = len(payload.raw_request or "")
    response_size = len(payload.raw_response or "")
    score = 0

    if request_size > 3000:
        score += 1
    if request_size > 12000:
        score += 1
    if response_size > 8000:
        score += 1
    if response_size > 30000:
        score += 1
    if len(features["param_names"]) >= 5:
        score += 1
    if len(matched_recipes) >= 3:
        score += 1

    if score <= 1:
        level = "low"
        eta = "about 15 to 45 seconds on a healthy local model"
        recommendation = "A full local analysis should be reasonable in one pass."
    elif score <= 3:
        level = "medium"
        eta = "about 45 to 120 seconds on a small local model"
        recommendation = "If this feels too slow, test one endpoint variant at a time or trim large response bodies."
    else:
        level = "high"
        eta = "2 to 5 minutes on a small local model, depending on Ollama performance"
        recommendation = "Reduce complexity by testing one request variant at a time, limiting very large responses, or focusing on one hypothesis first."

    return {
        "level": level,
        "eta": eta,
        "recommendation": recommendation,
    }


def _recipes_from_bapp_summary(bapp_summary: dict, allowed_classes: list[str], suppressed_classes: list[str]) -> list[dict]:
    synthetic_recipes = []
    seen = set()
    for finding in bapp_summary.get("findings", []):
        vuln_class = (finding.get("vuln_class") or "general").strip().lower()
        if vuln_class in suppressed_classes or vuln_class not in allowed_classes:
            continue
        dedupe_key = (vuln_class, finding.get("tool", "").strip().lower())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        synthetic_recipes.append({
            "title": f"{finding.get('tool', 'Burp finding')} correlated guidance",
            "summary": finding.get("summary", "Burp scan evidence suggests this class is worth confirming."),
            "severity": "info",
            "vuln_class": vuln_class,
            "nuclei_tags": [vuln_class.replace("-injection", ""), vuln_class],
            "seclists_path": "",
            "operator_questions": [
                "What exact request variant or evidence from Burp best supports this finding so far?",
                "Do you want to confirm this finding first in Burp Repeater, Intruder, or a minimal Kali WSL command?"
            ],
            "source_refs": list(finding.get("source_links", [])),
            "evidence": [finding.get("evidence", "Correlated Burp scan or BApp evidence.")],
        })
    return synthetic_recipes


IMPACT_PATHS_BY_CLASS = {
    "access-control": "Try to prove cross-tenant or cross-role access to a real object, sensitive field, or privileged action rather than only a status-code difference.",
    "authentication": "Try to prove account takeover, authentication bypass, or a trust-boundary break in login, refresh, MFA, or session transition behavior.",
    "business-logic": "Try to prove a durable workflow abuse such as unauthorized discounting, state progression, redemption, quota bypass, or financial/business state change.",
    "cache": "Try to prove cache poisoning, cache deception, or leakage of protected or user-specific content through shared caching behavior.",
    "command-injection": "Try to prove server-side command execution impact, file-system interaction clues, or privileged process behavior rather than only a parser anomaly.",
    "cors": "Try to prove credentialed cross-origin data access to sensitive responses, not only permissive header reflection on harmless content.",
    "crypto-failures": "Try to prove usable session exposure, downgrade to insecure transport, or exposure of cryptographic material that affects real user or system trust.",
    "csrf": "Try to prove a meaningful state-changing action can be triggered cross-site against a real victim context, not only that a token is absent.",
    "deserialization": "Try to prove server-side object processing that reaches privileged behavior, file access, or code-path abuse rather than only a type error.",
    "file-upload": "Try to prove storage, retrieval, overwrite, parsing, or execution impact from an uploaded file rather than only permissive metadata handling.",
    "graphql": "Try to prove unauthorized field access, schema exposure with protected data paths, or object-level authorization bypass through GraphQL operations.",
    "http-request-smuggling": "Try to prove front-end/back-end desync impact such as internal route reachability, cache poisoning, request hijacking, or auth-boundary confusion.",
    "information-disclosure": "Try to prove the disclosed information is real, sensitive, and usable for attack progression or direct impact, not only verbose but harmless metadata.",
    "input-validation": "Try to push the weak validation toward a concrete trust-boundary break such as injection, path abuse, or dangerous downstream interpretation.",
    "insecure-design": "Try to prove the design weakness enables unauthorized action, policy bypass, or durable abuse rather than a cosmetic workflow inconsistency.",
    "jwt-token": "Try to prove claim-trust abuse, audience confusion, role escalation, or token-boundary failure affecting protected resources.",
    "mass-assignment": "Try to prove a privileged server-managed field can be set by the client to alter role, ownership, pricing, or permissions.",
    "open-redirect": "Try to prove the redirect reaches a meaningful impact path such as token leakage, OAuth misuse, or trusted-flow redirection. If not, classify it as low impact.",
    "path-traversal": "Try to prove arbitrary file read, template path control, source disclosure, or access to protected filesystem-backed content.",
    "race-condition": "Try to prove duplicate redemption, double spend, quota bypass, or inconsistent state change caused by parallel or repeated requests.",
    "security-misconfiguration": "Try to prove the misconfiguration exposes an admin surface, dangerous default, protected content, or another reward-relevant weakness.",
    "secret-exposure": "Try to prove the exposed material is a real reusable secret, key, token, or credential with access beyond the current low-privilege view.",
    "session-management": "Try to prove session fixation, session reuse after logout, session hijackability, or boundary confusion between authenticated states.",
    "sqli": "Try to prove backend query influence, protected data exposure, or authentication/authorization impact rather than relying on a single generic database error.",
    "ssti": "Try to prove server-side template evaluation that reaches data exposure, server-side code execution paths, or privileged rendering behavior.",
    "ssrf": "Try to prove server-side outbound requests to internal services, metadata endpoints, private hosts, or protected network paths.",
    "xss": "Try to prove execution in a sensitive rendering context that can affect session data, privileged actions, or trusted user interaction.",
    "xxe": "Try to prove parser-driven impact such as server-side file access, local content exposure, or outbound fetch behavior rather than only XML error variance.",
}

BURP_HELPER_PRIORITIES = {
    "access-control": ["Autorize/AuthMatrix", "Logger++", "Comparer"],
    "authentication": ["Autorize/AuthMatrix", "Logger++", "Comparer"],
    "business-logic": ["Logger++", "Repeater", "Intruder"],
    "cache": ["Logger++", "Param Miner", "Comparer"],
    "command-injection": ["Logger++", "Repeater", "Intruder"],
    "cors": ["Logger++", "Repeater", "Comparer"],
    "csrf": ["Logger++", "Repeater", "Comparer"],
    "graphql": ["Logger++", "Param Miner", "Repeater"],
    "information-disclosure": ["Logger++", "Comparer", "Repeater"],
    "input-validation": ["Param Miner", "Logger++", "Intruder"],
    "jwt-token": ["JWT Editor", "Logger++", "Comparer"],
    "mass-assignment": ["Logger++", "Repeater", "Intruder"],
    "open-redirect": ["Logger++", "Comparer", "Repeater"],
    "path-traversal": ["Logger++", "Repeater", "Intruder"],
    "race-condition": ["Logger++", "Repeater", "Turbo Intruder"],
    "session-management": ["Autorize/AuthMatrix", "Logger++", "Comparer"],
    "sqli": ["Logger++", "Repeater", "Intruder"],
    "ssti": ["Logger++", "Repeater", "Intruder"],
    "ssrf": ["Collaborator Everywhere", "Logger++", "Repeater"],
    "xss": ["Logger++", "Comparer", "Intruder"],
    "xxe": ["Collaborator Everywhere", "Logger++", "Content Type Converter"],
}

BURP_TOOL_USAGE_NOTES = {
    "Logger++": "use it first to isolate the baseline request, confirming delta, and impact request with status, length, header, and timing comparisons.",
    "Param Miner": "use it before wider fuzzing when hidden parameters, cache keys, or unlinked inputs could explain the behavior.",
    "Autorize/AuthMatrix": "use it before broader scanning to compare roles, sessions, or tenants cleanly for authorization questions.",
    "JWT Editor": "use it to decode, inspect, and reissue token variants safely instead of hand-editing JWT structures.",
    "Active Scan++": "use it only after you narrow to one in-scope insertion point that justifies additional focused scan depth.",
    "Turbo Intruder": "use it only after Repeater proves the hypothesis and the program rules explicitly allow the request volume.",
    "Collaborator Everywhere": "use it only where the program allows callback-style evidence and you need broader passive visibility for outbound interactions.",
    "Content Type Converter": "use it when the same request should be compared across JSON, XML, and form encodings without rebuilding it manually.",
    "Repeater": "keep it as the primary confirmation tool before scanning or brute-force expansion.",
    "Intruder": "use it only after Repeater identifies the exact insertion point and short payload order worth expanding.",
    "Comparer": "use it when the baseline versus confirming response diff is noisy and needs a cleaner visual comparison.",
}


def build_rule_context(payload) -> dict:
    features = extract_features(payload)
    review_scope = resolve_review_scope(payload)
    burp_evidence_text = "\n\n".join(
        item for item in [
            getattr(payload, "bapp_findings_text", "") or "",
            getattr(payload, "logger_evidence_text", "") or "",
        ] if item.strip()
    )
    bapp_summary = normalize_bapp_findings(burp_evidence_text)
    matched_recipes = match_recipes(features, review_scope["allowed_classes"], review_scope["suppressed_classes"])
    synthetic_recipes = _recipes_from_bapp_summary(
        bapp_summary,
        review_scope["allowed_classes"],
        review_scope["suppressed_classes"],
    )
    anchor_class = _structured_dashboard_issue_class(payload)
    if anchor_class and not any(
        (item.get("vuln_class") or "").strip().lower() == anchor_class
        for item in [*matched_recipes, *synthetic_recipes]
    ):
        synthetic_recipes.append(_anchor_recipe_from_payload(payload, anchor_class))
    for recipe in synthetic_recipes:
        if not any(
            existing.get("title") == recipe["title"] and existing.get("vuln_class") == recipe["vuln_class"]
            for existing in matched_recipes
        ):
            matched_recipes.append(recipe)
    matched_recipes = _rank_recipes_for_payload(payload, features, matched_recipes, bapp_summary)
    aggregate = aggregate_recipe_output(payload, features, matched_recipes, review_scope, bapp_summary)
    complexity = estimate_complexity(payload, features, matched_recipes)
    return {
        "features": features,
        "matched_recipes": matched_recipes,
        "aggregate": aggregate,
        "complexity": complexity,
        "review_scope": review_scope,
        "bapp_summary": bapp_summary,
    }


from server.providers import command_template_service as _command_template_service
from server.providers.deterministic_aggregate_service import (
    build_aggregate_recipe_output as _build_deterministic_aggregate,
)
from server.providers import deterministic_guidance_service as _deterministic_guidance_service
from server.providers.feature_recipe_service import (
    extract_features as _extract_rule_features,
    match_recipes as _match_rule_recipes,
    matches_recipe as _matches_recipe_via_service,
)


def _payload_examples_for_class(vuln_class: str, sample: str) -> list[str]:
    return _deterministic_guidance_service.payload_examples_for_class(vuln_class, sample)


def _payload_recommendations(features: dict, matched_recipes: list[dict]) -> list[str]:
    return _deterministic_guidance_service.payload_recommendations(features, matched_recipes, _target_descriptor_for_class)


def _build_local_resource_hints(matched_recipes: list[dict]) -> list[str]:
    return _deterministic_guidance_service.build_local_resource_hints(matched_recipes)


def _query_guidance_packs(vuln_classes: list[str], top_k: int = 3) -> dict:
    return query_guidance_packs(vuln_classes, top_k=top_k)


def _build_primary_suggestion_steps(recipe: dict, features: dict) -> list[str]:
    return _deterministic_guidance_service.build_primary_suggestion_steps(
        recipe,
        features,
        _target_descriptor_for_class,
        INTRUDER_DEEMPHASIZED_CLASSES,
    )


def _build_impact_paths(matched_recipes: list[dict], bapp_summary: dict) -> list[str]:
    return _deterministic_guidance_service.build_impact_paths(matched_recipes, bapp_summary, IMPACT_PATHS_BY_CLASS)


def _project_readiness(payload, matched_recipes: list[dict], preferred_burp_tools: list[str], bcheck_recommendations: list[str]) -> tuple[str, list[str]]:
    return _deterministic_guidance_service.project_readiness(payload, matched_recipes, preferred_burp_tools, bcheck_recommendations)


def _build_burp_action_checklist(
    payload,
    matched_recipes: list[dict],
    preferred_burp_tools: list[str],
    bcheck_recommendations: list[str],
    readiness_summary: str,
) -> list[str]:
    return _deterministic_guidance_service.build_burp_action_checklist(
        payload,
        matched_recipes,
        preferred_burp_tools,
        bcheck_recommendations,
        readiness_summary,
        INTRUDER_DEEMPHASIZED_CLASSES,
    )


def _loaded_burp_helpers(payload, matched_recipes: list[dict], bapp_summary: dict) -> tuple[dict, list[str]]:
    return _deterministic_guidance_service.loaded_burp_helpers(
        payload,
        matched_recipes,
        bapp_summary,
        BURP_HELPER_PRIORITIES,
        BURP_TOOL_USAGE_NOTES,
    )


def _best_burp_helper_label(preferred_burp_tools: list[str]) -> str:
    return _deterministic_guidance_service.best_burp_helper_label(preferred_burp_tools)


def _build_burp_settings_recommendations(
    payload,
    matched_recipes: list[dict],
    bcheck_recommendations: list[str],
    loaded_burp_tools: dict,
    preferred_burp_tools: list[str],
) -> list[str]:
    return _deterministic_guidance_service.build_burp_settings_recommendations(
        payload,
        matched_recipes,
        bcheck_recommendations,
        loaded_burp_tools,
        preferred_burp_tools,
    )
