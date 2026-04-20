import shlex
import subprocess
import time
from datetime import datetime, timezone

WSL_DISTRO = "kali-linux"
INVENTORY_CACHE_TTL_SECONDS = 180
WSL_OUTPUT_ENCODING = "utf-8"
WSL_OUTPUT_ERRORS = "replace"

TOOL_DEFINITIONS = {
    "curl": {
        "binary": "curl",
        "repo_url": "https://github.com/curl/curl",
        "summary": "Replay the exact request with controlled header, cookie, and body changes.",
        "install_hint": "sudo apt install -y curl",
        "version_flags": [["--version"]],
        "help_flags": [["--help"]],
    },
    "jq": {
        "binary": "jq",
        "repo_url": "https://github.com/jqlang/jq",
        "summary": "Filter and normalize JSON responses while comparing deltas from repeated requests.",
        "install_hint": "sudo apt install -y jq",
        "version_flags": [["--version"]],
        "help_flags": [["--help"]],
    },
    "nuclei": {
        "binary": "nuclei",
        "repo_url": "https://github.com/projectdiscovery/nuclei",
        "summary": "Template-driven HTTP scanner for confirmed hypotheses and narrow follow-up checks.",
        "install_hint": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "version_flags": [["-version"], ["--version"]],
        "help_flags": [["-h"], ["--help"]],
    },
    "httpx": {
        "binary": "httpx",
        "repo_url": "https://github.com/projectdiscovery/httpx",
        "summary": "Collect status, headers, tech fingerprints, and response metadata for related routes.",
        "install_hint": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "version_flags": [["-version"], ["--version"]],
        "help_flags": [["-h"], ["--help"]],
    },
    "katana": {
        "binary": "katana",
        "repo_url": "https://github.com/projectdiscovery/katana",
        "summary": "Crawl nearby routes and JavaScript-discovered paths before choosing narrower checks.",
        "install_hint": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "version_flags": [["-version"], ["--version"]],
        "help_flags": [["-h"], ["--help"]],
    },
    "naabu": {
        "binary": "naabu",
        "repo_url": "https://github.com/projectdiscovery/naabu",
        "summary": "Fast port scan helper for host-level scope where infrastructure checks are explicitly allowed.",
        "install_hint": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "version_flags": [["-version"], ["--version"]],
        "help_flags": [["-h"], ["--help"]],
    },
    "subfinder": {
        "binary": "subfinder",
        "repo_url": "https://github.com/projectdiscovery/subfinder",
        "summary": "Passive subdomain discovery for broader scoped host inventory work.",
        "install_hint": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "version_flags": [["-version"], ["--version"]],
        "help_flags": [["-h"], ["--help"]],
    },
    "dnsx": {
        "binary": "dnsx",
        "repo_url": "https://github.com/projectdiscovery/dnsx",
        "summary": "Resolve and validate discovered hostnames before HTTP follow-up.",
        "install_hint": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "version_flags": [["-version"], ["--version"]],
        "help_flags": [["-h"], ["--help"]],
    },
    "tlsx": {
        "binary": "tlsx",
        "repo_url": "https://github.com/projectdiscovery/tlsx",
        "summary": "Inspect TLS protocol and certificate posture on HTTPS targets.",
        "install_hint": "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
        "version_flags": [["-version"], ["--version"]],
        "help_flags": [["-h"], ["--help"]],
    },
    "interactsh-client": {
        "binary": "interactsh-client",
        "repo_url": "https://github.com/projectdiscovery/interactsh",
        "summary": "Out-of-band callback client for SSRF-style checks when callback testing is explicitly allowed.",
        "install_hint": "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
        "version_flags": [["-version"], ["--version"]],
        "help_flags": [["-h"], ["--help"]],
    },
    "notify": {
        "binary": "notify",
        "repo_url": "https://github.com/projectdiscovery/notify",
        "summary": "Route finished scan results into chat or ticketing systems after manual review.",
        "install_hint": "go install github.com/projectdiscovery/notify/cmd/notify@latest",
        "version_flags": [["-version"], ["--version"]],
        "help_flags": [["-h"], ["--help"]],
    },
    "ffuf": {
        "binary": "ffuf",
        "repo_url": "https://github.com/ffuf/ffuf",
        "summary": "Shortlist-driven fuzzing for paths, identifiers, and narrow parameter discovery.",
        "install_hint": "sudo apt install -y ffuf",
        "version_flags": [["-V"], ["--version"]],
        "help_flags": [["-h"], ["--help"]],
    },
    "sqlmap": {
        "binary": "sqlmap",
        "repo_url": "https://github.com/sqlmapproject/sqlmap",
        "summary": "Parameter-focused SQL injection follow-up once a concrete target field is known.",
        "install_hint": "sudo apt install -y sqlmap",
        "version_flags": [["--version"]],
        "help_flags": [["-h"], ["--help"]],
    },
    "dalfox": {
        "binary": "dalfox",
        "repo_url": "https://github.com/hahwul/dalfox",
        "summary": "XSS-oriented request testing once you know the reflective parameter and context.",
        "install_hint": "go install github.com/hahwul/dalfox/v2@latest",
        "version_flags": [["version"], ["--version"]],
        "help_flags": [["-h"], ["--help"]],
    },
    "dirsearch": {
        "binary": "dirsearch",
        "repo_url": "https://github.com/maurosoria/dirsearch",
        "summary": "Directory and file discovery when adjacent routes or backups are in scope.",
        "install_hint": "git clone https://github.com/maurosoria/dirsearch.git",
        "version_flags": [["--version"]],
        "help_flags": [["-h"], ["--help"]],
    },
}

CLASS_TOOL_MAP = {
    "access-control": ["curl", "httpx", "ffuf", "nuclei"],
    "authentication": ["curl", "httpx", "ffuf", "nuclei"],
    "business-logic": ["curl", "httpx", "katana"],
    "cache": ["curl", "httpx", "nuclei"],
    "command-injection": ["curl", "nuclei", "httpx"],
    "cors": ["curl", "httpx", "nuclei"],
    "crypto-failures": ["curl", "tlsx", "httpx", "nuclei"],
    "csrf": ["curl", "httpx", "katana", "nuclei"],
    "deserialization": ["curl", "httpx", "nuclei"],
    "file-upload": ["curl", "httpx", "katana"],
    "graphql": ["curl", "jq", "httpx", "katana", "nuclei"],
    "http-request-smuggling": ["curl", "httpx", "nuclei"],
    "information-disclosure": ["curl", "httpx", "katana", "ffuf", "dirsearch", "nuclei"],
    "input-validation": ["curl", "httpx", "ffuf", "dalfox"],
    "insecure-design": ["curl", "httpx", "katana"],
    "jwt-token": ["curl", "jq", "httpx"],
    "mass-assignment": ["curl", "jq", "httpx", "nuclei"],
    "open-redirect": ["curl", "httpx", "dalfox", "nuclei"],
    "path-traversal": ["curl", "httpx", "ffuf", "dirsearch", "nuclei"],
    "race-condition": ["curl", "httpx", "ffuf"],
    "security-misconfiguration": ["curl", "httpx", "tlsx", "katana", "nuclei"],
    "secret-exposure": ["curl", "jq", "httpx", "katana", "nuclei"],
    "session-management": ["curl", "httpx", "nuclei"],
    "sqli": ["curl", "sqlmap", "httpx", "nuclei"],
    "ssti": ["curl", "httpx", "nuclei"],
    "ssrf": ["curl", "httpx", "nuclei", "interactsh-client"],
    "xss": ["curl", "httpx", "katana", "dalfox"],
    "xxe": ["curl", "httpx", "nuclei"],
}

_INVENTORY_CACHE = {
    "fetched_at": 0.0,
    "value": None,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_wsl_command(args: list[str], timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["wsl.exe", "-d", WSL_DISTRO, "--", *args],
        capture_output=True,
        text=True,
        encoding=WSL_OUTPUT_ENCODING,
        errors=WSL_OUTPUT_ERRORS,
        timeout=timeout,
        check=False,
    )


def _run_wsl_bash(script: str, timeout: int = 15) -> subprocess.CompletedProcess:
    return _run_wsl_command(["bash", "--noprofile", "--norc", "-lc", script], timeout=timeout)


def _read_distro_name() -> str:
    result = _run_wsl_bash("grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2-", timeout=10)
    text = (result.stdout or result.stderr or "").strip().strip('"')
    return text or WSL_DISTRO


def _command_path(binary: str) -> str:
    result = _run_wsl_bash(f"command -v {shlex.quote(binary)}", timeout=10)
    return (result.stdout or "").strip()


def _run_binary(binary: str, flag_sets: list[list[str]], timeout: int = 12, max_lines: int = 8) -> str:
    for flag_set in flag_sets:
        result = _run_wsl_command([binary, *flag_set], timeout=timeout)
        output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        if output:
            lines = [line.rstrip() for line in output.splitlines() if line.strip()]
            return "\n".join(lines[:max_lines])
    return ""


def get_tool_inventory(force_refresh: bool = False) -> dict:
    cached = _INVENTORY_CACHE["value"]
    if (
        not force_refresh
        and cached is not None
        and (time.time() - _INVENTORY_CACHE["fetched_at"]) < INVENTORY_CACHE_TTL_SECONDS
    ):
        return cached

    try:
        distro_name = _read_distro_name()
        tools = []
        for tool_name, definition in TOOL_DEFINITIONS.items():
            binary = definition["binary"]
            path = _command_path(binary)
            installed = bool(path)
            version = _run_binary(binary, definition["version_flags"], timeout=10, max_lines=1) if installed else ""
            help_preview = _run_binary(binary, definition["help_flags"], timeout=12, max_lines=10) if installed else ""
            tools.append({
                "name": tool_name,
                "binary": binary,
                "repo_url": definition["repo_url"],
                "summary": definition["summary"],
                "install_hint": definition["install_hint"],
                "installed": installed,
                "command_path": path,
                "version": version,
                "help_preview": help_preview,
            })

        installed_count = sum(1 for item in tools if item["installed"])
        inventory = {
            "available": True,
            "distro": WSL_DISTRO,
            "distro_name": distro_name,
            "detected_at": _utc_now(),
            "installed_count": installed_count,
            "missing_count": len(tools) - installed_count,
            "tools": tools,
            "tool_help_text": build_tool_help_text_from_tools(tools, distro_name),
        }
    except (FileNotFoundError, subprocess.SubprocessError, OSError) as exception:
        inventory = {
            "available": False,
            "distro": WSL_DISTRO,
            "distro_name": "",
            "detected_at": _utc_now(),
            "installed_count": 0,
            "missing_count": len(TOOL_DEFINITIONS),
            "tools": [
                {
                    "name": tool_name,
                    "binary": definition["binary"],
                    "repo_url": definition["repo_url"],
                    "summary": definition["summary"],
                    "install_hint": definition["install_hint"],
                    "installed": False,
                    "command_path": "",
                    "version": "",
                    "help_preview": "",
                }
                for tool_name, definition in TOOL_DEFINITIONS.items()
            ],
            "tool_help_text": "",
            "error": str(exception),
        }

    _INVENTORY_CACHE["value"] = inventory
    _INVENTORY_CACHE["fetched_at"] = time.time()
    return inventory


def build_tool_help_text_from_tools(tools: list[dict], distro_name: str) -> str:
    lines = [f"Kali WSL distro: {distro_name}"]
    installed = [item for item in tools if item["installed"]]
    missing = [item for item in tools if not item["installed"]]

    lines.append("Installed tools:")
    if installed:
        for item in installed:
            version = item["version"] or "installed"
            lines.append(f"- {item['name']}: {version}")
            if item["help_preview"]:
                lines.append(item["help_preview"])
    else:
        lines.append("- None detected.")

    lines.append("Missing tools:")
    if missing:
        for item in missing:
            lines.append(f"- {item['name']}: install with {item['install_hint']}")
    else:
        lines.append("- None")

    return "\n".join(lines)


def combined_tool_help_text(manual_tool_help: str = "", force_refresh: bool = False) -> str:
    inventory = get_tool_inventory(force_refresh=force_refresh)
    parts = []
    if (manual_tool_help or "").strip():
        parts.append(manual_tool_help.strip())
    if inventory.get("tool_help_text"):
        parts.append(inventory["tool_help_text"])
    return "\n\n".join(parts)


def inventory_summary_text(force_refresh: bool = False) -> str:
    inventory = get_tool_inventory(force_refresh=force_refresh)
    if not inventory.get("available"):
        return "Kali WSL inventory is unavailable."

    lines = [
        f"Kali WSL: {inventory.get('distro_name') or inventory.get('distro')}",
        f"Installed tools: {inventory.get('installed_count', 0)}",
        f"Missing tools: {inventory.get('missing_count', 0)}",
    ]
    installed = [item["name"] for item in inventory.get("tools", []) if item.get("installed")]
    missing = [item["name"] for item in inventory.get("tools", []) if not item.get("installed")]
    lines.append("Installed set: " + (", ".join(installed[:10]) if installed else "none"))
    if missing:
        lines.append("Missing set: " + ", ".join(missing[:10]))
    return "\n".join(lines)


def recommend_tools(features: dict, matched_recipes: list[dict], limit: int = 6) -> list[dict]:
    inventory = get_tool_inventory()
    inventory_map = {item["name"]: item for item in inventory.get("tools", [])}
    scored = {}

    def add_tool(tool_name: str, reason: str, score: int) -> None:
        if tool_name not in TOOL_DEFINITIONS:
            return
        item = scored.setdefault(tool_name, {"score": 0, "reasons": []})
        item["score"] += score
        if reason not in item["reasons"]:
            item["reasons"].append(reason)

    add_tool("curl", "exact request replay and comparison", 4)
    if "response_is_json" in features.get("signals", set()) or "request_has_json_body" in features.get("signals", set()):
        add_tool("jq", "JSON response inspection", 2)
    if "response_has_html" in features.get("signals", set()):
        add_tool("katana", "HTML and route crawl context", 2)
    if "target_uses_plain_http" not in features.get("signals", set()):
        add_tool("httpx", "HTTP metadata and fingerprinting", 3)
        add_tool("tlsx", "TLS posture review", 1)

    seen_classes = []
    for recipe in matched_recipes[:4]:
        vuln_class = (recipe.get("vuln_class") or "").strip().lower()
        if vuln_class and vuln_class not in seen_classes:
            seen_classes.append(vuln_class)
            for tool_name in CLASS_TOOL_MAP.get(vuln_class, []):
                add_tool(tool_name, f"matched {vuln_class}", 5)

    ranked = []
    for tool_name, detail in scored.items():
        inventory_entry = inventory_map.get(tool_name, {})
        tool_def = TOOL_DEFINITIONS[tool_name]
        final_score = detail["score"] + (2 if inventory_entry.get("installed") else 0)
        ranked.append({
            "name": tool_name,
            "repo_url": tool_def["repo_url"],
            "summary": tool_def["summary"],
            "installed": bool(inventory_entry.get("installed")),
            "version": inventory_entry.get("version", ""),
            "install_hint": tool_def["install_hint"],
            "reasons": detail["reasons"],
            "score": final_score,
        })

    ranked.sort(key=lambda item: (-item["score"], item["name"]))
    return ranked[: max(1, min(limit, 8))]


def summarize_tool_recommendations(recommendations: list[dict]) -> list[str]:
    lines = []
    for item in recommendations:
        status = "installed" if item.get("installed") else "missing in Kali WSL"
        version = f" | {item['version']}" if item.get("version") else ""
        reason = "; ".join(item.get("reasons", []))
        install_hint = f" | Install: {item['install_hint']}" if not item.get("installed") else ""
        lines.append(
            f"{item['name']} [{status}{version}]: {item['summary']} "
            f"Why: {reason}. Repo: {item['repo_url']}{install_hint}"
        )
    return lines
