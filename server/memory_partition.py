from __future__ import annotations

import re
from types import SimpleNamespace
from urllib.parse import urlparse


def build_partition_key(
    *,
    target_url: str = "",
    program_platform: str = "",
    program_policy_template: str = "",
    selected_profile: str = "",
) -> str:
    host = _normalized_host(target_url)
    platform = _slug(program_platform or program_policy_template or "generic")
    profile = _slug(selected_profile or "default")
    return f"{platform}:{profile}:{host}"


def partition_from_payload(payload_like) -> str:
    source = _payload_dict(payload_like)
    return build_partition_key(
        target_url=source.get("target_url", "") or "",
        program_platform=source.get("program_platform", "") or "",
        program_policy_template=source.get("program_policy_template", "") or "",
        selected_profile=source.get("selected_profile", "") or "",
    )


def partition_summary(partition_key: str) -> dict[str, str]:
    value = (partition_key or "").strip()
    parts = value.split(":")
    if len(parts) != 3:
        return {"platform": "generic", "profile": "default", "host": "unknown-host"}
    return {
        "platform": parts[0] or "generic",
        "profile": parts[1] or "default",
        "host": parts[2] or "unknown-host",
    }


def _payload_dict(payload_like) -> dict:
    if isinstance(payload_like, dict):
        return dict(payload_like)
    if isinstance(payload_like, SimpleNamespace):
        return vars(payload_like)
    if hasattr(payload_like, "model_dump"):
        return payload_like.model_dump()
    if hasattr(payload_like, "dict"):
        return payload_like.dict()
    return dict(vars(payload_like))


def _normalized_host(target_url: str) -> str:
    candidate = (target_url or "").strip()
    if not candidate:
        return "unknown-host"
    parsed = urlparse(candidate)
    host = (parsed.hostname or parsed.netloc or "").strip().lower()
    return _slug(host or "unknown-host")


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower()).strip("-")
    return normalized or "unknown"
