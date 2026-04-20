import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from server.settings import BCHECKS_SYNC_ON_START, BCHECKS_SYNC_URL

BASE_DIR = Path(__file__).resolve().parent
EXTERNAL_DIR = BASE_DIR / "external"
REPO_DIR = EXTERNAL_DIR / "BChecks-main"
REPO_HOME_URL = "https://github.com/PortSwigger/BChecks"
REPO_WEB_ROOT = "https://github.com/PortSwigger/BChecks/blob/main"
COMMON_HTTP_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "OPTIONS",
    "HEAD",
    "TRACE",
    "CONNECT",
    "TRACK",
}
CLASS_KEYWORDS = {
    "access-control": (
        "admin accessible",
        "auth bypass",
        "authentication bypass",
        "authorization bypass",
        "unauth",
        "unauthorized",
        "forbidden bypass",
        "403",
        "401",
        "middleware-bypass",
    ),
    "authentication": (
        "basic auth",
        "password grant",
        "default password",
        "ntlm",
        "openid",
    ),
    "business-logic": (
        "rate limiter",
        "method override",
        "workflow",
        "logic",
    ),
    "cache": (
        "cache",
        "cached",
        "cloudflare",
    ),
    "command-injection": (
        "ognl",
        "shell",
        "rce",
        "command",
        "exec",
        "log4shell",
        "spring4shell",
    ),
    "cors": (
        "cors",
        "access-control-allow-origin",
    ),
    "crypto-failures": (
        "unencrypted",
        "plain http",
        "http methods",
    ),
    "csrf": (
        "csrf",
        "cross-site request forgery",
    ),
    "deserialization": (
        "deserialization",
        "deserialize",
        "fastjson",
        "prototype pollution",
    ),
    "graphql": (
        "graphql",
        "graphiql",
        "introspection",
    ),
    "http-request-smuggling": (
        "smuggling",
        "request smuggling",
        "cl.te",
        "te.cl",
    ),
    "information-disclosure": (
        "directory listing",
        "stacktrace",
        "stack trace",
        "exposed",
        "disclosure",
        "debug",
        "swagger",
        "phpinfo",
        "profiler",
        "source file",
        "metrics",
        "prometheus",
        "actuator",
        "js map",
        ".ds_store",
    ),
    "input-validation": (
        "crlf",
        "csv injection",
        "email-splitting",
        "transformation",
    ),
    "insecure-design": (
        "http methods",
        "method override",
        "password grant",
    ),
    "jwt-token": (
        "jwt",
        "jws",
        "token",
    ),
    "mass-assignment": (
        "mass assignment",
    ),
    "open-redirect": (
        "open redirect",
        "openredirect",
        "redirect",
    ),
    "path-traversal": (
        "path traversal",
        "file read",
        "directory traversal",
        "backup file",
        "backup exposed",
        "webbackup",
        "git directory",
        "svn-exposed",
    ),
    "race-condition": (
        "race",
        "rate limiter",
    ),
    "security-misconfiguration": (
        "config",
        "misconfiguration",
        "samesite",
        "missing-security-txt",
        "security-txt",
        "options",
        "allow-methods",
        "content-security-policy",
        "debug mode",
        "tomcat manager",
        "mod_info",
        "laravel",
        "symfony",
        "actuator",
        "swagger",
        "prometheus",
    ),
    "secret-exposure": (
        "secret",
        "token",
        "credential",
        "private key",
        "aws",
        "api key",
        "webhook",
        "client_secret",
        "password in javascript",
        "leak",
    ),
    "session-management": (
        "samesite",
        "cookie",
        "session",
        "basic auth",
    ),
    "sqli": (
        "sql injection",
        "sqli",
    ),
    "ssti": (
        "template injection",
        "ssti",
        "razor",
    ),
    "ssrf": (
        "ssrf",
        "collaborator",
        "request_uri",
        "out-of-band",
    ),
    "xss": (
        "xss",
        "cross-site scripting",
        "script injection",
    ),
    "xxe": (
        "xxe",
        "xml external entity",
    ),
}
SIGNAL_CLASS_HINTS = {
    "request_has_graphql_marker": {"graphql"},
    "request_has_url_input_params": {"ssrf", "open-redirect"},
    "request_has_redirect_params": {"open-redirect"},
    "request_has_serialized_blob": {"deserialization"},
    "request_has_path_input_params": {"path-traversal"},
    "request_has_template_input_params": {"ssti"},
    "request_has_conflicting_length_headers": {"http-request-smuggling"},
    "request_has_chunked_transfer": {"http-request-smuggling"},
    "response_has_secret_keywords": {"secret-exposure"},
    "target_uses_plain_http": {"crypto-failures"},
}
_CATALOG_CACHE = {
    "signature": None,
    "entries": [],
}


def _utc_iso(timestamp: float | None) -> str:
    if not timestamp:
        return ""
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def _quoted_items(raw: str) -> list[str]:
    return [item.strip() for item in re.findall(r'"([^"]+)"', raw or "") if item.strip()]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _parse_metadata(text: str) -> dict:
    metadata = {
        "language": "",
        "name": "",
        "description": "",
        "author": "",
        "tags": [],
    }
    in_metadata = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not in_metadata:
            if line.strip() == "metadata:":
                in_metadata = True
            continue
        if line and not line.startswith((" ", "\t")):
            break
        normalized = line.strip()
        if not normalized or ":" not in normalized:
            continue
        key, value = normalized.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "tags":
            metadata["tags"] = _quoted_items(value)
        elif key in {"language", "name", "description", "author"}:
            metadata[key] = value.strip().strip('"')
    return metadata


def _scan_mode(text: str, tags: list[str]) -> str:
    lower_text = text.lower()
    lower_tags = {tag.lower() for tag in tags}
    if "passive" in lower_tags:
        return "passive"
    if "given insertion point then" in lower_text or "send payload" in lower_text:
        return "active"
    if "send request" in lower_text or "run for each" in lower_text:
        return "active"
    if "given response then" in lower_text:
        return "passive"
    return "mixed"


def _execution_context(text: str) -> str:
    lower_text = text.lower()
    if "given insertion point then" in lower_text:
        return "insertion-point"
    if "given host then" in lower_text:
        return "host"
    if "given response then" in lower_text:
        return "response"
    if "given request then" in lower_text:
        return "request"
    return "generic"


def _extract_methods(text: str) -> list[str]:
    methods = []
    for match in re.findall(r'"(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|TRACE|CONNECT|TRACK)"', text, flags=re.IGNORECASE):
        method = match.upper()
        if method in COMMON_HTTP_METHODS and method not in methods:
            methods.append(method)
    return methods


def _infer_vuln_classes(relative_path: str, metadata: dict, text: str) -> list[str]:
    primary_haystack = " ".join([
        relative_path.lower(),
        (metadata.get("name") or "").lower(),
        (metadata.get("description") or "").lower(),
        " ".join(tag.lower() for tag in metadata.get("tags", [])),
    ])
    classes = []
    for vuln_class, keywords in CLASS_KEYWORDS.items():
        if any(keyword in primary_haystack for keyword in keywords):
            classes.append(vuln_class)

    if not classes:
        secondary_haystack = text[:1200].lower()
        for vuln_class, keywords in CLASS_KEYWORDS.items():
            if any(keyword in secondary_haystack for keyword in keywords):
                classes.append(vuln_class)

    if not classes:
        if "vulnerabilities-cved/" in relative_path.lower():
            classes.append("security-misconfiguration")
        elif "other/tokens/" in relative_path.lower():
            classes.append("secret-exposure")
        elif "other/graphql/" in relative_path.lower():
            classes.append("graphql")
        elif "other/http methods/" in relative_path.lower():
            classes.append("security-misconfiguration")
        elif "other/files/" in relative_path.lower():
            classes.append("information-disclosure")
        else:
            classes.append("information-disclosure")

    deduped = []
    for vuln_class in classes:
        if vuln_class not in deduped:
            deduped.append(vuln_class)
    return deduped[:4]


def _usage_hint(entry: dict) -> str:
    method_hint = f" Methods seen in the check: {', '.join(entry['methods'])}." if entry["methods"] else ""
    if entry["requires_collaborator"]:
        return "Requires Burp Collaborator and should only be enabled where callback-based checks are permitted." + method_hint
    if entry["execution_context"] == "insertion-point":
        return "Parameter-focused BCheck; use it when the request exposes clear insertion points." + method_hint
    if entry["execution_context"] == "host":
        return "Host and path discovery style BCheck; useful for adjacent exposed paths and framework fingerprints." + method_hint
    if entry["scan_mode"] == "passive":
        return "Passive BCheck; safe for response and header correlation without active payload expansion." + method_hint
    return "Active companion BCheck; enable it when the matched hypothesis is in scope and worth confirming." + method_hint


def _entry_signature() -> tuple:
    if not REPO_DIR.exists():
        return ("missing", 0, 0)
    bcheck_files = list(REPO_DIR.rglob("*.bcheck"))
    latest_mtime = max((path.stat().st_mtime for path in bcheck_files), default=0)
    return (str(REPO_DIR.resolve()), len(bcheck_files), int(latest_mtime))


def _build_catalog() -> list[dict]:
    if not REPO_DIR.exists():
        return []

    entries = []
    for path in sorted(REPO_DIR.rglob("*.bcheck")):
        relative_path = path.relative_to(REPO_DIR).as_posix()
        text = _read_text(path)
        metadata = _parse_metadata(text)
        entry = {
            "name": metadata["name"] or path.stem,
            "description": metadata["description"] or "No description provided.",
            "author": metadata["author"] or "unknown",
            "language": metadata["language"] or "unknown",
            "tags": metadata["tags"],
            "relative_path": relative_path,
            "collection": relative_path.split("/", 1)[0],
            "source_url": f"{REPO_WEB_ROOT}/{quote(relative_path)}",
            "scan_mode": _scan_mode(text, metadata["tags"]),
            "execution_context": _execution_context(text),
            "requires_collaborator": "collaborator" in text.lower(),
            "methods": _extract_methods(text),
        }
        entry["vuln_classes"] = _infer_vuln_classes(relative_path, metadata, text)
        entry["usage_hint"] = _usage_hint(entry)
        entries.append(entry)
    return entries


def list_bchecks(force_reload: bool = False) -> list[dict]:
    signature = _entry_signature()
    if not force_reload and _CATALOG_CACHE["signature"] == signature:
        return [dict(entry) for entry in _CATALOG_CACHE["entries"]]

    entries = _build_catalog()
    _CATALOG_CACHE["signature"] = signature
    _CATALOG_CACHE["entries"] = entries
    return [dict(entry) for entry in entries]


def get_bcheck_status() -> dict:
    entries = list_bchecks()
    last_updated = ""
    if REPO_DIR.exists():
        mtimes = [path.stat().st_mtime for path in REPO_DIR.rglob("*.bcheck")]
        last_updated = _utc_iso(max(mtimes, default=0))

    vuln_classes = []
    collections = []
    for entry in entries:
        if entry["collection"] not in collections:
            collections.append(entry["collection"])
        for vuln_class in entry["vuln_classes"]:
            if vuln_class not in vuln_classes:
                vuln_classes.append(vuln_class)

    return {
        "available": bool(entries),
        "repo_dir": str(REPO_DIR),
        "source_url": REPO_HOME_URL,
        "total_checks": len(entries),
        "top_level_groups": collections,
        "mapped_vuln_classes": vuln_classes,
        "last_updated": last_updated,
    }


def query_bchecks(limit: int = 100, vuln_class: str = "", search: str = "") -> list[dict]:
    normalized_class = (vuln_class or "").strip().lower()
    search_term = (search or "").strip().lower()
    entries = []
    for entry in list_bchecks():
        if normalized_class and normalized_class not in entry["vuln_classes"]:
            continue
        if search_term:
            haystack = " ".join([
                entry["name"],
                entry["description"],
                entry["relative_path"],
                " ".join(entry["tags"]),
                " ".join(entry["vuln_classes"]),
            ]).lower()
            if search_term not in haystack:
                continue
        entries.append(entry)
    return entries[: max(1, min(limit, 500))]


def _target_classes(features: dict, matched_recipes: list[dict], allowed_classes: list[str]) -> list[str]:
    classes = []
    for recipe in matched_recipes[:4]:
        vuln_class = (recipe.get("vuln_class") or "").strip().lower()
        if vuln_class and vuln_class not in classes:
            classes.append(vuln_class)
    if classes:
        return classes

    for signal in features.get("signals", set()):
        for vuln_class in SIGNAL_CLASS_HINTS.get(signal, set()):
            if vuln_class not in classes:
                classes.append(vuln_class)
    if classes:
        return classes

    for vuln_class in allowed_classes:
        if vuln_class not in classes:
            classes.append(vuln_class)
    return classes[:6]


def recommend_bchecks(features: dict, matched_recipes: list[dict], allowed_classes: list[str], limit: int = 4) -> list[dict]:
    wanted_classes = _target_classes(features, matched_recipes, allowed_classes)
    if not wanted_classes:
        return []

    path_terms = {part for part in features.get("path", "").lower().split("/") if part}
    method = (features.get("method") or "").upper()
    scored = []
    for entry in list_bchecks():
        score = 0
        reasons = []
        overlap = [vuln_class for vuln_class in entry["vuln_classes"] if vuln_class in wanted_classes]
        if overlap:
            score += 6 + len(overlap)
            reasons.append("matches target class " + ", ".join(overlap))
        elif not any(vuln_class in allowed_classes for vuln_class in entry["vuln_classes"]):
            continue

        if method and entry["methods"] and method in entry["methods"]:
            score += 2
            reasons.append(f"mentions {method}")
        if method and not entry["methods"] and entry["scan_mode"] == "passive":
            score += 1
            reasons.append("works as a passive cross-check")
        if entry["requires_collaborator"] and "collaborator" not in " ".join(features.get("observations", [])).lower():
            score -= 1
        if "graphql" in path_terms and "graphql" in entry["vuln_classes"]:
            score += 2
            reasons.append("path already looks GraphQL-related")
        if path_terms and any(term and term in entry["relative_path"].lower() for term in path_terms):
            score += 1
            reasons.append("path terminology overlaps")
        if "response_has_secret_keywords" in features.get("signals", set()) and "secret-exposure" in entry["vuln_classes"]:
            score += 2
            reasons.append("response already looks secret-bearing")
        if entry["collection"] == "archived":
            score -= 2
            reasons.append("legacy archived check")

        if score <= 0:
            continue

        scored.append((score, reasons, entry))

    scored.sort(key=lambda item: (-item[0], item[2]["relative_path"]))
    recommendations = []
    for score, reasons, entry in scored[: max(1, min(limit, 8))]:
        recommendation = dict(entry)
        recommendation["why"] = "; ".join(reasons) or "adjacent upstream coverage"
        recommendation["score"] = score
        recommendations.append(recommendation)
    return recommendations


def summarize_recommendations(recommendations: list[dict]) -> list[str]:
    lines = []
    for entry in recommendations:
        classes = ", ".join(entry["vuln_classes"])
        tags = ", ".join(entry["tags"][:4]) if entry["tags"] else "untagged"
        lines.append(
            f"[{classes}] {entry['name']} | {entry['relative_path']} | {entry['scan_mode']} | "
            f"Why: {entry['why']} | Tags: {tags}"
        )
    return lines


def _safe_extract(zip_path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    destination_root = destination.resolve()
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            member_path = destination / member.filename
            resolved = member_path.resolve()
            try:
                resolved.relative_to(destination_root)
            except ValueError:
                raise ValueError(f"Unsafe archive member path: {member.filename}")
        archive.extractall(destination)


def sync_bchecks_repository() -> dict:
    EXTERNAL_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="bchecks-download-", dir=str(EXTERNAL_DIR)) as temp_dir:
        temp_root = Path(temp_dir)
        temp_zip = temp_root / "bchecks.zip"
        extract_root = temp_root / "extract"

        request = Request(
            BCHECKS_SYNC_URL,
            headers={"User-Agent": "Burp-AI-Bridge/1.0"},
        )
        try:
            with urlopen(request, timeout=45) as response, temp_zip.open("wb") as handle:
                shutil.copyfileobj(response, handle)
        except HTTPError as exc:
            raise RuntimeError(f"BChecks sync failed with HTTP {exc.code}.") from exc
        except URLError as exc:
            raise RuntimeError(f"BChecks sync failed: {exc.reason}.") from exc

        _safe_extract(temp_zip, extract_root)

        candidate_roots = [path for path in extract_root.iterdir() if path.is_dir()]
        if not candidate_roots:
            raise RuntimeError("BChecks archive did not contain a repository directory.")

        extracted_repo = candidate_roots[0]
        if REPO_DIR.exists():
            shutil.rmtree(REPO_DIR)
        shutil.move(str(extracted_repo), str(REPO_DIR))

    return get_bcheck_status()


def initialize_bchecks() -> dict:
    if BCHECKS_SYNC_ON_START:
        try:
            return sync_bchecks_repository()
        except RuntimeError:
            pass
    return get_bcheck_status()
