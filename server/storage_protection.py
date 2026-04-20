from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from server.settings import PERSISTENCE_REPLAY_PROTECTION_MODE, PERSISTENCE_STORAGE_SEAL_KEY

_RAW_MESSAGE_KEYS = {
    "raw_request",
    "raw_response",
    "request_text",
    "response_text",
    "request",
    "response",
}


def serialize_jsonl_record(record: dict[str, Any]) -> str:
    protected = protect_record_for_storage(record)
    return json.dumps(protected, ensure_ascii=True)


def deserialize_jsonl_record(line: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return verify_record_seal(payload)


def protect_record_for_storage(record: dict[str, Any]) -> dict[str, Any]:
    protected = _apply_replay_protection(record)
    return _apply_storage_seal(protected)


def verify_record_seal(record: dict[str, Any]) -> dict[str, Any]:
    value = dict(record)
    seal = value.pop("_storage_seal", "")
    if not seal:
        return value
    expected = _seal_for_record(value)
    value["_storage_seal_valid"] = bool(expected) and hmac.compare_digest(seal, expected)
    return value


def _apply_replay_protection(record: dict[str, Any]) -> dict[str, Any]:
    mode = (PERSISTENCE_REPLAY_PROTECTION_MODE or "off").strip().lower()
    if mode not in {"hash-raw", "strict"}:
        return dict(record)
    return _transform_for_replay_protection(record, mode=mode)


def _transform_for_replay_protection(value: Any, *, mode: str, key_path: tuple[str, ...] = ()) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _transform_for_replay_protection(item, mode=mode, key_path=key_path + (str(key),))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_transform_for_replay_protection(item, mode=mode, key_path=key_path) for item in value]
    if isinstance(value, str):
        last_key = (key_path[-1] if key_path else "").strip().lower()
        if last_key in _RAW_MESSAGE_KEYS:
            return _sealed_text_placeholder(value, strict=(mode == "strict"))
    return value


def _sealed_text_placeholder(value: str, *, strict: bool) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    length = len(value)
    detail = f"sha256={digest};len={length}"
    return f"<protected-http-message:{detail}>"


def _apply_storage_seal(record: dict[str, Any]) -> dict[str, Any]:
    sealed = dict(record)
    seal = _seal_for_record(sealed)
    if seal:
        sealed["_storage_seal"] = seal
    return sealed


def _seal_for_record(record: dict[str, Any]) -> str:
    secret = (PERSISTENCE_STORAGE_SEAL_KEY or "").strip()
    if not secret:
        return ""
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
