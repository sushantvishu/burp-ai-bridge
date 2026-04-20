import re

VALID_PRIVACY_MODES = {"STRICT", "BALANCED", "OFF"}


def normalize_privacy_mode(value: str | None, default: str = "STRICT") -> str:
    candidate = (value or "").strip().upper()
    if candidate in VALID_PRIVACY_MODES:
        return candidate
    return default


def _mask_value(value: str) -> str:
    if len(value) <= 6:
        return "***"
    return value[:3] + "***" + value[-2:]


def _mask_cookie_header(line: str, mode: str) -> str:
    name, _, value = line.partition(":")
    cookie_pairs = []
    for part in value.split(";"):
        piece = part.strip()
        if not piece:
            continue
        if "=" not in piece:
            cookie_pairs.append(piece)
            continue
        cookie_name, cookie_value = piece.split("=", 1)
        masked_value = "***" if mode == "STRICT" else _mask_value(cookie_value)
        cookie_pairs.append(f"{cookie_name}={masked_value}")
    return f"{name}: " + "; ".join(cookie_pairs)


def _mask_authorization_header(line: str, mode: str) -> str:
    name, _, value = line.partition(":")
    auth_value = value.strip()
    if not auth_value:
        return f"{name}: <empty>"
    if mode == "STRICT":
        return f"{name}: <redacted>"
    parts = auth_value.split(None, 1)
    if len(parts) == 2:
        return f"{name}: {parts[0]} {_mask_value(parts[1])}"
    return f"{name}: {_mask_value(auth_value)}"


def sanitize_http_message(raw_message: str, mode: str) -> str:
    normalized_mode = normalize_privacy_mode(mode)
    if normalized_mode == "OFF":
        return raw_message

    lines = raw_message.replace("\r\n", "\n").split("\n")
    sanitized = []
    for line in lines:
        lower = line.lower()
        if lower.startswith("cookie:"):
            sanitized.append(_mask_cookie_header(line, normalized_mode))
        elif lower.startswith("authorization:"):
            sanitized.append(_mask_authorization_header(line, normalized_mode))
        elif normalized_mode == "STRICT" and any(token in lower for token in ("x-api-key:", "csrf-token:", "x-csrf-token:", "set-cookie:")):
            name, _, _ = line.partition(":")
            sanitized.append(f"{name}: <redacted>")
        else:
            sanitized.append(line)
    return "\n".join(sanitized)


def sanitize_free_text(text: str, mode: str) -> str:
    normalized_mode = normalize_privacy_mode(mode)
    if normalized_mode == "OFF":
        return text

    sanitized = text
    sanitized = re.sub(r"(?i)(authorization\s*:\s*)(.+)", r"\1<redacted>", sanitized)
    sanitized = re.sub(r"(?i)(cookie\s*:\s*)(.+)", r"\1<redacted>", sanitized)
    sanitized = re.sub(r"(?i)(set-cookie\s*:\s*)(.+)", r"\1<redacted>", sanitized)
    sanitized = re.sub(r"(?i)(csrf[_\- ]?token\s*[=:]\s*)(\S+)", r"\1<redacted>", sanitized)

    if normalized_mode == "STRICT":
        sanitized = re.sub(r"\b[A-Za-z0-9_\-]{24,}\b", "<redacted-token>", sanitized)

    return sanitized
