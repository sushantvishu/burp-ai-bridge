import hashlib
import json
from datetime import datetime, timezone

from server.knowledge_base import MEMORY_DIR, ensure_storage
from server.memory_partition import partition_from_payload
from server.persistence_redaction import redact_persisted_data
from server.settings import AUDIT_LOG_JSONL_MAX_RECORDS
from server.storage_protection import deserialize_jsonl_record, serialize_jsonl_record

AUDIT_LOG_PATH = MEMORY_DIR / "audit_log.jsonl"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _last_hash() -> str:
    ensure_storage()
    if not AUDIT_LOG_PATH.exists():
        return ""

    last_line = ""
    for line in AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines():
        if line.strip():
            last_line = line
    if not last_line:
        return ""
    try:
        payload = deserialize_jsonl_record(last_line)
    except Exception:
        payload = None
    if not payload:
        return ""
    return payload.get("entry_hash", "")


def append_audit_event(event_type: str, data: dict) -> None:
    ensure_storage()
    payload = dict(data)
    payload.setdefault("memory_partition_key", partition_from_payload(payload))
    redacted_data = redact_persisted_data(payload)
    event = {
        "timestamp": _utc_now(),
        "event_type": event_type,
        "previous_hash": _last_hash(),
        "data": redacted_data,
    }
    canonical = json.dumps(event, sort_keys=True, ensure_ascii=True)
    event["entry_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(serialize_jsonl_record(event) + "\n")
    _prune_audit_log(AUDIT_LOG_PATH, AUDIT_LOG_JSONL_MAX_RECORDS)


def read_audit_events(limit: int | None = None) -> list[dict]:
    ensure_storage()
    if not AUDIT_LOG_PATH.exists():
        return []

    lines = AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines()
    if limit is not None:
        lines = lines[-limit:]

    records = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        payload = deserialize_jsonl_record(line)
        if not payload:
            continue
        records.append(payload)
    return records


def paginate_audit_events(
    *,
    limit: int = 20,
    cursor: int = 0,
    request_id: str = "",
    job_id: str = "",
    event_type: str = "",
) -> dict:
    records = list(reversed(_filter_audit_events(
        read_audit_events(),
        request_id=request_id,
        job_id=job_id,
        event_type=event_type,
    )))
    safe_cursor = max(0, int(cursor or 0))
    safe_limit = max(1, min(int(limit or 20), 200))
    window = records[safe_cursor:safe_cursor + safe_limit]
    next_cursor = safe_cursor + len(window)
    return {
        "cursor": safe_cursor,
        "limit": safe_limit,
        "total": len(records),
        "count": len(window),
        "next_cursor": next_cursor if next_cursor < len(records) else None,
        "items": window,
    }


def audit_events_jsonl(records: list[dict]) -> str:
    return "".join(json.dumps(record, ensure_ascii=True) + "\n" for record in records)


def audit_events_markdown(page: dict) -> str:
    items = page.get("items") or []
    lines = [
        "# Audit Events",
        "",
        f"- Total matches: {page.get('total', 0)}",
        f"- Returned: {page.get('count', len(items))}",
        f"- Cursor: {page.get('cursor', 0)}",
        f"- Next cursor: {page.get('next_cursor') if page.get('next_cursor') is not None else '<none>'}",
        "",
        "## Items",
    ]
    if not items:
        lines.append("- None")
        return "\n".join(lines) + "\n"

    for item in items:
        data = item.get("data") or {}
        lines.append(
            f"- {item.get('timestamp') or '<unknown>'} | {item.get('event_type') or '<unknown>'} | "
            f"request_id={data.get('request_id') or '<none>'} | job_id={data.get('job_id') or '<none>'}"
        )
        lines.append(
            f"  entry_hash={item.get('entry_hash') or '<none>'} previous_hash={item.get('previous_hash') or '<none>'}"
        )
    return "\n".join(lines) + "\n"


def _filter_audit_events(records: list[dict], *, request_id: str = "", job_id: str = "", event_type: str = "") -> list[dict]:
    normalized_request_id = (request_id or "").strip()
    normalized_job_id = (job_id or "").strip()
    normalized_event_type = (event_type or "").strip().lower()
    filtered = []
    for record in records:
        data = record.get("data") or {}
        if normalized_request_id and (data.get("request_id") or "").strip() != normalized_request_id:
            continue
        if normalized_job_id and (data.get("job_id") or "").strip() != normalized_job_id:
            continue
        if normalized_event_type and (record.get("event_type") or "").strip().lower() != normalized_event_type:
            continue
        filtered.append(record)
    return filtered


def _prune_audit_log(path, max_records: int) -> None:
    if max_records <= 0 or not path.exists():
        return

    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) <= max_records:
        return

    retained = lines[-max_records:]
    path.write_text(("\n".join(retained) + "\n") if retained else "", encoding="utf-8")
