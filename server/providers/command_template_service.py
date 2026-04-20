import re
from urllib.parse import urlparse

from server.settings import (
    EXECUTION_DEFAULT_MAX_CONCURRENCY,
    EXECUTION_DEFAULT_RATE_LIMIT,
    EXECUTION_HARD_MAX_CONCURRENCY,
    EXECUTION_HARD_MAX_RATE_LIMIT,
    EXECUTION_KILL_SWITCH,
    EXECUTION_SCOPE_ENFORCEMENT_ENABLED,
)


def _extract_positive_int(text: str) -> int:
    match = re.search(r"(\d+)", text or "")
    if not match:
        return 0
    try:
        value = int(match.group(1))
    except ValueError:
        return 0
    return value if value > 0 else 0


def _scope_rules(text: str) -> list[str]:
    if not text:
        return []
    return [part.strip() for part in re.split(r"[,\n]+", text) if part.strip()]


def _normalized_host(value: str) -> str:
    parsed = urlparse(value if "://" in (value or "") else f"https://{value}")
    return (parsed.netloc or parsed.path or "").split(":", 1)[0].strip().lower()


def _rule_matches_target(rule: str, target_url: str, target_host: str, target_path: str) -> bool:
    normalized = (rule or "").strip().lower()
    if not normalized:
        return False
    if normalized.startswith("*."):
        return target_host.endswith(normalized[1:])
    if "://" in normalized:
        parsed = urlparse(normalized)
        rule_host = (parsed.netloc or "").split(":", 1)[0].strip().lower()
        rule_path = parsed.path or "/"
        return bool(rule_host and target_host == rule_host and target_path.startswith(rule_path))
    if "/" in normalized:
        if normalized.startswith("/"):
            return target_path.startswith(normalized)
        rule_host = _normalized_host(normalized)
        rule_path = "/" + normalized.split("/", 1)[1] if "/" in normalized else "/"
        return bool(rule_host and target_host == rule_host and target_path.startswith(rule_path))
    host = _normalized_host(normalized)
    return target_host == host or target_host.endswith("." + host)


def _execution_budget(payload, target_url: str) -> dict:
    parsed = urlparse(target_url or "")
    target_host = (parsed.netloc or "").split(":", 1)[0].strip().lower()
    target_path = parsed.path or "/"
    include_rules = _scope_rules(getattr(payload, "scope_includes_text", "") or "")
    exclude_rules = _scope_rules(getattr(payload, "scope_excludes_text", "") or "")
    rate_requested = _extract_positive_int(getattr(payload, "rate_limit_text", "") or "")
    concurrency_requested = _extract_positive_int(getattr(payload, "max_concurrency_text", "") or "")
    rate_effective = min(
        rate_requested or max(1, int(EXECUTION_DEFAULT_RATE_LIMIT or 1)),
        max(1, int(EXECUTION_HARD_MAX_RATE_LIMIT or 1)),
    )
    concurrency_effective = min(
        concurrency_requested or max(1, int(EXECUTION_DEFAULT_MAX_CONCURRENCY or 1)),
        max(1, int(EXECUTION_HARD_MAX_CONCURRENCY or 1)),
    )

    kill_switch_active = bool(EXECUTION_KILL_SWITCH)
    policy_text = " ".join(
        [
            getattr(payload, "program_policy_text", "") or "",
            getattr(payload, "saved_program_policy_text", "") or "",
        ]
    ).lower()
    if any(marker in policy_text for marker in ("kill switch", "killswitch", "no automation", "manual only", "do not automate")):
        kill_switch_active = True

    blocked_reason = ""
    if kill_switch_active:
        blocked_reason = "Kill-switch is active for execution suggestions."
    if not blocked_reason and EXECUTION_SCOPE_ENFORCEMENT_ENABLED:
        excluded = next(
            (rule for rule in exclude_rules if _rule_matches_target(rule, target_url, target_host, target_path)),
            "",
        )
        if excluded:
            blocked_reason = f"Target is out-of-scope by rule: {excluded}"
        elif include_rules and not any(
            _rule_matches_target(rule, target_url, target_host, target_path) for rule in include_rules
        ):
            blocked_reason = "Target does not match in-scope rules."

    return {
        "blocked": bool(blocked_reason),
        "reason": blocked_reason,
        "include_rules": include_rules,
        "exclude_rules": exclude_rules,
        "rate_effective": rate_effective,
        "concurrency_effective": concurrency_effective,
    }


def _enforce_tool_limits(command: str, tool: str, budget: dict) -> str:
    normalized_tool = (tool or "").strip().lower()
    if not command or command.startswith("#"):
        return command
    rate = int(budget.get("rate_effective", 0) or 0)
    concurrency = int(budget.get("concurrency_effective", 0) or 0)

    updated = command
    if normalized_tool == "nuclei":
        if "-rate-limit" not in updated and rate:
            updated += f" -rate-limit {rate}"
        if re.search(r"(^|\s)-c(\s|$)", updated) is None and concurrency:
            updated += f" -c {concurrency}"
    elif normalized_tool == "ffuf":
        if re.search(r"(^|\s)-rate(\s|$)", updated) is None and rate:
            updated += f" -rate {rate}"
        if re.search(r"(^|\s)-t(\s|$)", updated) is None and concurrency:
            updated += f" -t {concurrency}"
    elif normalized_tool == "dirsearch":
        if "--threads" not in updated and concurrency:
            updated += f" --threads {concurrency}"
    elif normalized_tool == "sqlmap":
        if "--threads" not in updated and concurrency:
            updated += f" --threads {concurrency}"
    return updated


def build_command_templates(payload, features: dict, matched_recipes: list[dict], nuclei_tags: str, seclists_path: str, helpers: dict) -> list[str]:
    target_url = payload.target_url or ""
    base_url = helpers["base_target_url"](target_url)
    parsed_target = urlparse(target_url or "")
    target_host = parsed_target.netloc or ""
    commands = {}
    method = (features.get("method") or "GET").upper()
    curl_headers = helpers["header_flags_for_tool"]("curl", payload)
    nuclei_headers = helpers["header_flags_for_tool"]("nuclei", payload)
    ffuf_headers = helpers["header_flags_for_tool"]("ffuf", payload)
    nuclei_limits = helpers["rate_limit_flags_for_tool"]("nuclei", payload)
    ffuf_limits = helpers["rate_limit_flags_for_tool"]("ffuf", payload)
    dirsearch_limits = helpers["rate_limit_flags_for_tool"]("dirsearch", payload)
    sqlmap_limits = helpers["rate_limit_flags_for_tool"]("sqlmap", payload)
    budget = _execution_budget(payload, target_url)
    expansion_allowed = not budget["blocked"]

    def add_command(key: str, command: str) -> None:
        commands[key] = _enforce_tool_limits(command, key, budget)

    if budget["blocked"]:
        blocked = [
            f"# Execution blocked: {budget['reason']}",
            (
                f"# Safety budget enforced: rate<={budget['rate_effective']} req/sec, "
                f"concurrency<={budget['concurrency_effective']}."
            ),
            "# Continue with manual baseline comparison only until scope/policy is updated.",
        ]
        scope_note = helpers["scope_note"](payload)
        if scope_note:
            blocked.append(f"# Scope note: {scope_note}")
        return blocked[:6]

    if target_url:
        add_command("curl", helpers["curl_request_command"](target_url, features, curl_headers))
        if expansion_allowed:
            add_command("httpx", f"httpx -u {helpers['shell_quote'](target_url)} -status-code -title -tech-detect -content-length")
    if target_url and nuclei_tags and expansion_allowed:
        add_command("nuclei", f"nuclei -u {helpers['shell_quote'](target_url)} -tags {helpers['shell_quote'](nuclei_tags)}{nuclei_headers}{nuclei_limits}")
    if expansion_allowed and base_url and ("response_has_html" in features["signals"] or "path_looks_admin" in features["signals"]):
        add_command("katana", f"katana -u {helpers['shell_quote'](base_url)} -d 2 -jc")
    if expansion_allowed and target_host and parsed_target.scheme.lower() == "https":
        add_command("tlsx", f"tlsx -u {helpers['shell_quote'](target_host)} -silent")
    if expansion_allowed and base_url and ("response_has_html" in features["signals"] or "path_looks_admin" in features["signals"]):
        discovery_wordlist = seclists_path if "/Discovery/Web-Content/" in (seclists_path or "") else "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
        add_command("dirsearch", f"dirsearch -u {helpers['shell_quote'](base_url)} -w {helpers['shell_quote'](discovery_wordlist)}{dirsearch_limits}")

    vuln_classes = [recipe.get("vuln_class", "general") for recipe in matched_recipes[:4]]
    identifier_param = helpers["pick_param"](features, helpers["IDENTIFIER_PARAMS"])
    redirect_param = helpers["pick_param"](features, helpers["REDIRECT_PARAMS"])
    url_param = helpers["pick_param"](features, helpers["URL_INPUT_PARAMS"])
    search_param = helpers["pick_param"](features, helpers["SEARCH_PARAMS"])
    sqli_param = helpers["pick_param"](features, helpers["IDENTIFIER_PARAMS"] | helpers["SEARCH_PARAMS"])
    path_param = helpers["pick_param"](features, helpers["PATH_INPUT_PARAMS"])
    graphql_param = helpers["pick_param"](features, helpers["GRAPHQL_PARAM_NAMES"])
    template_param = helpers["pick_param"](features, helpers["TEMPLATE_INPUT_PARAMS"])
    privileged_param = helpers["pick_param"](features, helpers["PRIVILEGED_JSON_KEYS"])

    for vuln_class in vuln_classes:
        if vuln_class == "sqli" and target_url:
            sqlmap_command = f"sqlmap -u {helpers['shell_quote'](target_url)} -p {helpers['shell_quote'](sqli_param)} --batch --risk 1 --level 1"
            sqli_location = (features.get("param_locations") or {}).get(sqli_param, "")
            if helpers["method_supports_body"](method):
                if "form body" in sqli_location:
                    sqlmap_command += f" --method={method} --data {helpers['shell_quote'](helpers['updated_form_body'](features))}"
                elif "json body" in sqli_location:
                    sqlmap_command += f" --method={method} --data {helpers['shell_quote'](helpers['updated_json_body'](features))}"
                    if "application/json" in (features.get("request_content_type") or "").lower():
                        sqlmap_command += " --headers " + helpers["shell_quote_argument"]("Content-Type: application/json")
            if expansion_allowed:
                add_command("sqlmap", sqlmap_command + sqlmap_limits)
        elif vuln_class == "access-control" and target_url:
            add_command("idor-curl", helpers["curl_request_command"](target_url, features, curl_headers, param_name=identifier_param, param_value="REPLACE_ID", extra_headers=["Cookie: SESSION=REPLACE_ME"]))
        elif vuln_class == "csrf" and target_url:
            add_command("csrf-curl", helpers["curl_request_command"](target_url, features, curl_headers, extra_headers=["Origin: https://example.com", "Referer: https://example.com/"]))
        elif vuln_class == "cors" and target_url:
            add_command("cors-curl", helpers["curl_request_command"](target_url, features, curl_headers, force_method="OPTIONS", extra_headers=["Origin: https://example.com", f"Access-Control-Request-Method: {method}"]))
        elif vuln_class == "security-misconfiguration" and target_url:
            add_command("curl-head", helpers["curl_request_command"](target_url, features, curl_headers, use_head=True))
        elif vuln_class in {"jwt-token", "authentication"} and target_url:
            add_command("jwt-tool", "jwt-tool REPLACE_JWT -d")
            add_command("auth-curl", helpers["curl_request_command"](target_url, features, curl_headers, extra_headers=["Authorization: Bearer REPLACE_JWT"]))
        elif vuln_class == "open-redirect" and target_url:
            add_command("redirect-curl", helpers["curl_request_command"](target_url, features, curl_headers, param_name=redirect_param, param_value="https://example.org/"))
        elif vuln_class == "ssrf" and target_url:
            add_command("ssrf-curl", helpers["curl_request_command"](target_url, features, curl_headers, param_name=url_param, param_value="http://127.0.0.1:80/"))
        elif vuln_class == "xss" and target_url:
            add_command("xss-curl", helpers["curl_request_command"](target_url, features, curl_headers, param_name=search_param, param_value="XSSMARK"))
            if expansion_allowed:
                add_command("dalfox", f"dalfox url {helpers['shell_quote'](target_url)} -p {helpers['shell_quote'](search_param)}")
        elif vuln_class == "cache" and target_url:
            add_command("cache-curl", helpers["curl_request_command"](target_url, features, curl_headers, extra_headers=["Cache-Control: no-cache", "Pragma: no-cache"]))
        elif vuln_class == "command-injection" and target_url:
            add_command("cmdi-curl", helpers["curl_request_command"](target_url, features, curl_headers, param_name=search_param, param_value="test;id"))
        elif vuln_class == "graphql" and target_url:
            add_command("graphql-curl", helpers["curl_request_command"](target_url, features, curl_headers, param_name=graphql_param, param_value="query {__typename}", force_method="POST"))
        elif vuln_class == "path-traversal" and target_url:
            add_command("traversal-curl", helpers["curl_request_command"](target_url, features, curl_headers, param_name=path_param, param_value="../file.txt"))
        elif vuln_class == "ssti" and target_url:
            add_command("ssti-curl", helpers["curl_request_command"](target_url, features, curl_headers, param_name=template_param, param_value="{{7-7}}"))
        elif vuln_class == "mass-assignment" and target_url:
            add_command("mass-assignment-curl", helpers["curl_request_command"](target_url, features, curl_headers, param_name=privileged_param, param_value="admin"))
        elif vuln_class == "xxe" and target_url:
            add_command("xxe-baseline-curl", f"curl -i {helpers['shell_quote'](target_url)} -H 'Content-Type: application/xml' --data-binary @baseline.xml")
            add_command("xxe-variant-curl", f"curl -i {helpers['shell_quote'](target_url)} -H 'Content-Type: application/xml' --data-binary @xml-no-doctype.xml")
        elif vuln_class in {"access-control", "authentication"} and base_url:
            wordlist = seclists_path if seclists_path else "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt"
            if expansion_allowed:
                add_command("ffuf", f"ffuf -u {helpers['shell_quote'](base_url + '/FUZZ')} -w {helpers['shell_quote'](wordlist)}{ffuf_headers}{ffuf_limits}")

    scope_note = helpers["scope_note"](payload)
    commands["budget-note"] = (
        f"# Safety budget: rate<={budget['rate_effective']} req/sec, concurrency<={budget['concurrency_effective']}."
    )
    if scope_note:
        commands["scope-note"] = f"# Scope note: {scope_note}"

    return list(commands.values())[:8]


def command_tool_name(command: str) -> str:
    stripped = (command or "").strip()
    if not stripped or stripped.startswith("#"):
        return ""
    first = stripped.split()[0]
    return first.split("/")[-1]


def label_manual_commands(commands: list[str], payload, inventory: dict) -> list[str]:
    installed = {item["binary"]: item["installed"] for item in inventory.get("tools", [])}
    include_scope = bool((getattr(payload, "scope_includes_text", "") or "").strip())
    discovery_tools = {"ffuf", "dirsearch", "katana", "naabu", "subfinder", "dnsx", "httpx", "tlsx"}
    labeled = []
    for command in commands:
        tool_name = command_tool_name(command)
        if not tool_name:
            labeled.append(command)
            continue
        if not installed.get(tool_name, False):
            label = "ready-after-install"
        elif tool_name in discovery_tools and not include_scope:
            label = "needs-scope-confirmation"
        else:
            label = "safe-now"
        labeled.append(f"[{label}] {command}")
    return labeled[:8]
