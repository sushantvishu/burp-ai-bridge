import json
import re
from urllib.parse import parse_qs, urlparse


TEMPLATE_SYNTAX_MARKERS = (
    "{{",
    "}}",
    "{%",
    "%}",
    "${",
    "#{",
    "<%",
    "%>",
)


def _canonical_param_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _param_name_tokens(name: str) -> set[str]:
    normalized = (name or "").lower()
    parts = re.split(r"[^a-z0-9]+", normalized)
    tokens = {part for part in parts if part}
    canonical = _canonical_param_name(normalized)
    if canonical:
        tokens.add(canonical)
    return tokens


def _param_name_matches(name: str, known_names: set[str] | list[str] | tuple[str, ...] | None) -> bool:
    if not known_names:
        return False
    known_lower = {str(item).strip().lower() for item in known_names if str(item).strip()}
    if not known_lower:
        return False
    known_canonical = {_canonical_param_name(item) for item in known_lower if item}
    tokens = _param_name_tokens(name)
    return bool(tokens.intersection(known_lower) or tokens.intersection(known_canonical))


def _has_template_syntax(text: str, markers: tuple[str, ...]) -> bool:
    if not text:
        return False
    lower_text = text.lower()
    if any(marker in lower_text for marker in markers):
        return True
    return bool(re.search(r"(?:\{\{.*\}\}|\$\{[^}]+\}|<%.*%>|#\{[^}]+\})", text, flags=re.DOTALL))


def _matches_path_version(path: str, pattern) -> bool:
    if not path:
        return False
    if isinstance(pattern, re.Pattern):
        return bool(pattern.search(path))
    return bool(re.search(str(pattern), path))


def extract_features(
    payload,
    *,
    parse_http_message,
    first_scalar_param_value,
    flatten_json_paths,
    record_param_source,
    parse_response_delta_text,
    constants: dict,
) -> dict:
    request = parse_http_message(payload.raw_request)
    response = parse_http_message(payload.raw_response)

    url = urlparse(payload.target_url or "")
    path = url.path or ""
    query_params = parse_qs(url.query, keep_blank_values=True)
    request_headers = request["headers"]
    response_headers = response["headers"]
    request_content_type = request_headers.get("content-type", "")
    response_content_type = response_headers.get("content-type", "")
    request_body = request["body"]
    response_body = response["body"] or ""
    lower_path = path.lower()
    lower_request_body = request_body.lower()
    lower_response_body = response_body.lower()

    form_params = {}
    json_body = {}
    json_entries = {}
    json_path_entries = {}
    if "application/x-www-form-urlencoded" in request_content_type and request_body:
        form_params = parse_qs(request_body, keep_blank_values=True)

    json_keys = []
    if "application/json" in request_content_type and request_body.strip():
        try:
            request_json = json.loads(request_body)
            if isinstance(request_json, dict):
                json_body = request_json
                json_keys = [str(key) for key in request_json.keys()]
                json_entries = {
                    str(key): first_scalar_param_value(value)
                    for key, value in request_json.items()
                }
                json_path_entries = {path: sample for path, sample in flatten_json_paths(request_json)}
        except json.JSONDecodeError:
            pass

    combined_param_names = {*query_params.keys(), *form_params.keys(), *json_keys, *json_path_entries.keys()}
    has_nested_json = any(isinstance(value, (dict, list)) for value in json_body.values())
    has_privileged_json_keys = any(
        _param_name_matches(str(key), constants.get("privileged_json_keys"))
        for key in json_body.keys()
    )
    has_api_version_path = _matches_path_version(lower_path, constants.get("api_version_path_regex", r"/v\d+(?:/|$)"))
    has_internal_path = any(
        token in lower_path
        for token in constants.get(
            "internal_path_tokens",
            ("internal", "private", "backoffice", "staff", "ops", "intranet"),
        )
    )
    has_graphql_marker = (
        "graphql" in lower_path
        or "application/graphql" in request_content_type
        or any(_param_name_matches(name, constants.get("graphql_param_names")) for name in combined_param_names)
        or "\"query\"" in lower_request_body
        or "\"mutation\"" in lower_request_body
        or "\"operationname\"" in lower_request_body
    )
    has_path_input_params = any(_param_name_matches(name, constants.get("path_input_params")) for name in combined_param_names)
    has_template_input_params = any(
        _param_name_matches(name, constants.get("template_input_params"))
        for name in combined_param_names
    )
    has_serialized_blob = bool(
        re.search(r"(rO0AB|ACED0005|__type|\$type|java\.lang\.|O:\d+:|a:\d+:\{|s:\d+:)", request_body or "")
    ) or any(
        re.search(r"(rO0AB|ACED0005|__type|\$type|O:\d+:|a:\d+:\{|s:\d+:)", sample or "")
        for sample in json_entries.values()
    )

    param_locations = {}
    param_samples = {}
    for name, values in query_params.items():
        record_param_source(param_locations, name, "query string")
        sample = first_scalar_param_value(values)
        if sample:
            param_samples[name] = sample
    for name, values in form_params.items():
        record_param_source(param_locations, name, "form body")
        sample = first_scalar_param_value(values)
        if sample and name not in param_samples:
            param_samples[name] = sample
    for name in json_keys:
        record_param_source(param_locations, name, "json body")
        sample = json_entries.get(name, "")
        if sample and name not in param_samples:
            param_samples[name] = sample
    for name, sample in json_path_entries.items():
        record_param_source(param_locations, name, "json body path")
        if sample and name not in param_samples:
            param_samples[name] = sample

    param_names = sorted(combined_param_names)
    template_markers = tuple(constants.get("template_marker_patterns", TEMPLATE_SYNTAX_MARKERS))
    has_template_syntax_markers = _has_template_syntax(request_body, template_markers) or any(
        _has_template_syntax(sample or "", template_markers) for sample in param_samples.values()
    )

    set_cookie = response_headers.get("set-cookie", "")
    origin = request_headers.get("origin", "")
    acao = response_headers.get("access-control-allow-origin", "")
    authorization_value = request_headers.get("authorization", "")

    start_line = response["start_line"]
    status_code = "<unknown>"
    if start_line:
        parts = start_line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = parts[1]

    missing_security_headers = [
        header for header in constants["security_headers"] if header not in response_headers
    ]

    signals = set()

    if "cookie" in request_headers:
        signals.add("request_has_cookies")
    if "authorization" in request_headers:
        signals.add("request_has_authorization")
        if authorization_value.lower().startswith("bearer "):
            signals.add("request_has_bearer_token")
            token_value = authorization_value[7:].strip()
            if token_value.count(".") == 2:
                signals.add("request_has_jwt_like_token")
    if "application/json" in request_content_type:
        signals.add("request_has_json_body")
    if "xml" in request_content_type or request_body.lstrip().startswith("<?xml"):
        signals.add("request_has_xml_body")
    if "application/x-www-form-urlencoded" in request_content_type:
        signals.add("request_has_form_body")
    if "multipart/form-data" in request_content_type:
        signals.add("request_has_file_upload")
    if has_graphql_marker:
        signals.add("request_has_graphql_marker")
    if has_nested_json:
        signals.add("request_has_nested_json")
    if has_privileged_json_keys:
        signals.add("request_has_privileged_json_keys")
    if any(_param_name_matches(name, constants.get("identifier_params")) for name in param_names):
        signals.add("request_has_identifier_params")
    if any(_param_name_matches(name, constants.get("redirect_params")) for name in param_names):
        signals.add("request_has_redirect_params")
    if any(_param_name_matches(name, constants.get("url_input_params")) for name in param_names):
        signals.add("request_has_url_input_params")
    if any(_param_name_matches(name, constants.get("search_params")) for name in param_names):
        signals.add("request_has_search_like_params")
    if has_path_input_params:
        signals.add("request_has_path_input_params")
    if has_template_input_params:
        signals.add("request_has_template_input_params")
    if has_template_syntax_markers:
        signals.add("request_has_template_syntax_markers")
    if has_serialized_blob:
        signals.add("request_has_serialized_blob")
    if request_headers.get("transfer-encoding", "").lower().find("chunked") != -1:
        signals.add("request_has_chunked_transfer")
    if "transfer-encoding" in request_headers and "content-length" in request_headers:
        signals.add("request_has_conflicting_length_headers")
    if url.scheme.lower() == "http":
        signals.add("target_uses_plain_http")
    if any(token in lower_path for token in ("login", "signin", "auth", "session")):
        signals.add("path_looks_login")
    if any(token in lower_path for token in ("admin", "manage", "dashboard")):
        signals.add("path_looks_admin")
    if has_internal_path:
        signals.add("path_looks_internal")
    if has_api_version_path:
        signals.add("path_has_api_version")
    if "text/html" in response_content_type or "<html" in lower_response_body:
        signals.add("response_has_html")
    if "application/json" in response_content_type or lower_response_body.lstrip().startswith("{"):
        signals.add("response_is_json")
    if "graphql" in lower_response_body and "\"errors\"" in lower_response_body:
        signals.add("response_has_graphql_error")
    if "<form" in lower_response_body:
        signals.add("response_has_html_form")
    if "type=\"password\"" in lower_response_body or "type='password'" in lower_response_body:
        signals.add("response_has_password_field")
    if any(token in lower_response_body for token in ("csrf", "__requestverificationtoken", "authenticity_token")):
        signals.add("response_has_csrf_marker")
    if missing_security_headers:
        signals.add("response_missing_security_headers")
    if set_cookie:
        signals.add("response_sets_cookie")
        set_cookie_lower = set_cookie.lower()
        if "secure" not in set_cookie_lower:
            signals.add("response_cookie_missing_secure")
        if "httponly" not in set_cookie_lower:
            signals.add("response_cookie_missing_httponly")
        if "samesite" not in set_cookie_lower:
            signals.add("response_cookie_missing_samesite")
    if any(token in lower_response_body for token in ("stack trace", "exception", "sql syntax", "warning:", "fatal error")):
        signals.add("response_has_error_keywords")
    if re.search(
        r"(api[_-]?key|secret|private[_-]?key|aws_access_key_id|-----begin [a-z ]*private key-----)",
        lower_response_body,
    ):
        signals.add("response_has_secret_keywords")
    if acao or "access-control-allow-credentials" in response_headers:
        signals.add("response_has_cors_header")
    if acao == "*" or (origin and acao and acao == origin):
        signals.add("response_cors_reflects_origin")
    if any(header in response_headers for header in ("cache-control", "pragma", "expires", "vary")):
        signals.add("response_has_cache_headers")
    else:
        signals.add("response_missing_cache_headers")

    observations = [
        f"Method: {payload.http_method or '<unknown>'}",
        f"Path: {path or '<none>'}",
        f"Request parameter names: {', '.join(param_names) if param_names else '<none>'}",
        f"Request content type: {request_content_type or '<none>'}",
        f"Response status: {status_code}",
        f"Response content type: {response_content_type or '<none>'}",
        f"Response server header: {response_headers.get('server', '<unknown>')}",
    ]

    if missing_security_headers:
        observations.append("Missing security headers: " + ", ".join(missing_security_headers))
    if "request_has_graphql_marker" in signals:
        observations.append("Request appears to target a GraphQL operation.")
    if "path_has_api_version" in signals:
        observations.append("Path appears versioned (for example /v1/ or /v2/).")
    if "path_looks_internal" in signals:
        observations.append("Path appears related to internal or back-office functionality.")
    if "request_has_serialized_blob" in signals:
        observations.append("Request body or parameter values contain serialized-object style markers.")
    if "request_has_template_syntax_markers" in signals:
        observations.append("Request input includes template-style syntax markers that can indicate SSTI surface.")
    if "request_has_conflicting_length_headers" in signals:
        observations.append("Request includes both Transfer-Encoding and Content-Length headers.")
    if "response_has_secret_keywords" in signals:
        observations.append("Response body preview contains secret-like keywords or private key markers.")
    if "target_uses_plain_http" in signals:
        observations.append("Target URL uses plain HTTP transport.")
    if "request_has_jwt_like_token" in signals:
        observations.append("Authorization header appears JWT-like.")
    if "response_has_cache_headers" in signals:
        observations.append("Response includes explicit cache-related headers.")
    if "response_missing_cache_headers" in signals:
        observations.append("Response lacks explicit cache-related headers.")
    for note in parse_response_delta_text(getattr(payload, "response_delta_text", "") or ""):
        observations.append(note)
    if set_cookie:
        cookie_flags = [
            name.replace("response_cookie_missing_", "").upper()
            for name in (
                "response_cookie_missing_secure",
                "response_cookie_missing_httponly",
                "response_cookie_missing_samesite",
            )
            if name in signals
        ]
        observations.append(
            "Response sets cookies" + (f" with missing flags: {', '.join(cookie_flags)}" if cookie_flags else ".")
        )

    return {
        "path": path,
        "method": (payload.http_method or "").upper(),
        "status_code": status_code,
        "request_content_type": request_content_type,
        "response_content_type": response_content_type,
        "param_names": param_names,
        "query_params": query_params,
        "form_params": form_params,
        "json_body": json_body,
        "param_locations": param_locations,
        "param_samples": param_samples,
        "signals": signals,
        "missing_security_headers": missing_security_headers,
        "request_summary": request,
        "response_summary": response,
        "observations": observations,
    }


def matches_recipe(recipe: dict, features: dict, *, leaf_param_matches) -> bool:
    signals = features["signals"]

    if any(flag not in signals for flag in recipe.get("all_of", [])):
        return False
    if recipe.get("any_of") and not any(flag in signals for flag in recipe["any_of"]):
        return False
    if any(flag in signals for flag in recipe.get("none_of", [])):
        return False

    if recipe.get("methods_any") and features["method"] not in recipe["methods_any"]:
        return False

    path_lower = features["path"].lower()
    if recipe.get("path_keywords_any") and not any(
        keyword.lower() in path_lower for keyword in recipe["path_keywords_any"]
    ):
        return False

    param_names = {name.lower() for name in features["param_names"]}
    recipe_param_names = {name.lower() for name in recipe.get("param_names_any", [])}
    if recipe.get("param_names_any") and not (
        param_names.intersection(recipe_param_names)
        or any(leaf_param_matches(name, recipe_param_names) for name in features["param_names"])
    ):
        return False

    request_content_type = (features["request_content_type"] or "").lower()
    if recipe.get("request_content_types_any") and not any(
        item.lower() in request_content_type for item in recipe["request_content_types_any"]
    ):
        return False

    response_content_type = (features["response_content_type"] or "").lower()
    if recipe.get("response_content_types_any") and not any(
        item.lower() in response_content_type for item in recipe["response_content_types_any"]
    ):
        return False

    return True


def match_recipes(
    features: dict,
    *,
    recipes: list[dict],
    signal_descriptions: dict,
    leaf_param_matches,
    allowed_classes: list[str] | None = None,
    suppressed_classes: list[str] | None = None,
) -> list[dict]:
    matches = []
    param_names = {name.lower() for name in features["param_names"]}
    path_lower = features["path"].lower()
    allowed = {value.lower() for value in (allowed_classes or [])}
    suppressed = {value.lower() for value in (suppressed_classes or [])}

    for recipe in recipes:
        vuln_class = (recipe.get("vuln_class") or "").strip().lower()
        if allowed and vuln_class and vuln_class not in allowed:
            continue
        if vuln_class and vuln_class in suppressed:
            continue
        if not matches_recipe(recipe, features, leaf_param_matches=leaf_param_matches):
            continue

        evidence = []
        for signal in recipe.get("all_of", []) + recipe.get("any_of", []):
            if signal in features["signals"] and signal in signal_descriptions:
                description = signal_descriptions[signal]
                if description not in evidence:
                    evidence.append(description)

        matched_params = [
            name for name in recipe.get("param_names_any", [])
            if name.lower() in param_names
        ]
        if matched_params:
            evidence.append("Matched parameter names: " + ", ".join(matched_params))

        matched_path_keywords = [
            keyword for keyword in recipe.get("path_keywords_any", [])
            if keyword.lower() in path_lower
        ]
        if matched_path_keywords:
            evidence.append("Matched path keywords: " + ", ".join(matched_path_keywords))

        matches.append({
            **recipe,
            "evidence": evidence,
        })

    return matches
