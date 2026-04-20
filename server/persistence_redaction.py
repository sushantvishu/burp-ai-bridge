import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from server.privacy_utils import sanitize_free_text, sanitize_http_message

_SENSITIVE_KEY_TOKENS = (
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "secret",
    "api_key",
    "api-key",
    "apikey",
    "session",
    "jwt",
    "csrf",
    "password",
    "bearer",
)
_SENSITIVE_QUERY_KEYS = {
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "key",
    "session",
    "sessionid",
    "session_id",
    "jwt",
    "authorization",
    "auth",
    "csrf",
    "csrf_token",
    "password",
}
_RAW_MESSAGE_KEYS = {
    "raw_request",
    "raw_response",
    "raw-request",
    "raw-response",
    "request",
    "response",
    "request_text",
    "response_text",
    "request-text",
    "response-text",
}
_JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\b")
_HEADER_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(authorization|cookie|set-cookie|x-api-key|api-key|x-csrf-token|csrf-token)\b\s*[:=]\s*([^\s,;]+)"
)
_URL_LIKE_PATTERN = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_QUERY_PARAM_PATTERN = re.compile(
    r"(?i)([?&](?:token|access_token|refresh_token|id_token|api_key|apikey|key|session|sessionid|session_id|jwt|authorization|auth|csrf|csrf_token|password)=)([^&\s]+)"
)


def redact_persisted_data(value: Any, key_path: tuple[str, ...] = ()) -> Any:
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            normalized_key = str(key)
            redacted[normalized_key] = _redact_mapping_value(normalized_key, item, key_path + (normalized_key,))
        return redacted
    if isinstance(value, list):
        return [redact_persisted_data(item, key_path) for item in value]
    if isinstance(value, tuple):
        return [redact_persisted_data(item, key_path) for item in value]
    if isinstance(value, str):
        return _redact_string_value(value, key_path)
    return value


def _redact_mapping_value(key: str, value: Any, key_path: tuple[str, ...]) -> Any:
    normalized_key = key.lower().replace("_", "-")
    if normalized_key in _RAW_MESSAGE_KEYS and isinstance(value, str):
        return _redact_http_message(value)
    if _looks_sensitive_key(normalized_key):
        if isinstance(value, (dict, list, tuple)):
            return redact_persisted_data(value, key_path)
        return "<redacted>"
    return redact_persisted_data(value, key_path)


def _redact_string_value(value: str, key_path: tuple[str, ...]) -> str:
    if not value:
        return value

    last_key = (key_path[-1] if key_path else "").lower().replace("_", "-")
    if last_key in _RAW_MESSAGE_KEYS:
        return _redact_http_message(value)
    if _looks_sensitive_key(last_key):
        return "<redacted>"

    sanitized = sanitize_free_text(value, "STRICT")
    sanitized = _redact_jwts(sanitized)
    sanitized = _redact_header_assignments(sanitized)
    sanitized = _redact_query_params(sanitized)
    return sanitized


def _redact_http_message(value: str) -> str:
    sanitized = sanitize_free_text(sanitize_http_message(value, "STRICT"), "STRICT")
    sanitized = _redact_jwts(sanitized)
    return _QUERY_PARAM_PATTERN.sub(r"\1<redacted>", sanitized)


def _looks_sensitive_key(key: str) -> bool:
    return any(token in key for token in _SENSITIVE_KEY_TOKENS)


def _redact_jwts(value: str) -> str:
    return _JWT_PATTERN.sub("<redacted-jwt>", value)


def _redact_header_assignments(value: str) -> str:
    def _replace(match: re.Match) -> str:
        return f"{match.group(1)}: <redacted>"

    return _HEADER_ASSIGNMENT_PATTERN.sub(_replace, value)


def _redact_query_params(value: str) -> str:
    scrubbed = _QUERY_PARAM_PATTERN.sub(r"\1<redacted>", value)
    if "?" not in value and not _URL_LIKE_PATTERN.match(value):
        return scrubbed
    try:
        parts = urlsplit(value)
    except ValueError:
        return scrubbed
    if not parts.query:
        return scrubbed
    redacted_query = []
    for key, item in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in _SENSITIVE_QUERY_KEYS:
            redacted_query.append((key, "<redacted>"))
        else:
            redacted_query.append((key, item))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(redacted_query, doseq=True), parts.fragment))
