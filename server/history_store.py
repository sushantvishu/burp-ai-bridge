import json
from collections import defaultdict
from pathlib import Path

from server.knowledge_base import MEMORY_DIR, ensure_storage
from server.memory_partition import partition_from_payload
from server.persistence_redaction import redact_persisted_data
from server.review_dataset import append_review_example
from server.settings import HISTORY_JSONL_MAX_RECORDS
from server.state.store import (
    append_analysis_snapshot,
    get_burp_session_snapshot,
    append_phase_snapshots,
    append_provider_diagnostics,
    apply_hypothesis_state,
    latest_hypothesis_state_map,
)
from server.storage_protection import deserialize_jsonl_record, serialize_jsonl_record

ANALYSIS_HISTORY_PATH = MEMORY_DIR / "analysis_history.jsonl"


def _analysis_run(record: dict) -> dict:
    value = record.get("analysis_run")
    return value if isinstance(value, dict) else {}


def build_memory_promotion_profile(record: dict) -> dict:
    analysis_run = _analysis_run(record)
    result = record.get("result") or {}
    phases = analysis_run.get("phases") or analysis_run.get("phase_results") or {}
    hypotheses = analysis_run.get("hypotheses") or []
    confirmed_classes: list[str] = []
    high_conf_classes: list[str] = []
    for item in hypotheses:
        if not isinstance(item, dict):
            continue
        vuln_class = (item.get("vuln_class") or "").strip().lower()
        if not vuln_class:
            continue
        status = (item.get("status") or "suspected").strip().lower()
        confidence = float(item.get("confidence") or 0.0)
        if status == "confirmed" and vuln_class not in confirmed_classes:
            confirmed_classes.append(vuln_class)
        elif confidence >= 0.78 and vuln_class not in high_conf_classes:
            high_conf_classes.append(vuln_class)

    validation_status = ((phases.get("validate") or {}).get("validation_status") or "").strip().lower()
    impact_reportable = bool((phases.get("impact") or {}).get("reportable"))
    evidence_count = len(analysis_run.get("evidence") or [])
    fallback_used = bool(result.get("fallback_used"))

    score = 0
    score += len(confirmed_classes) * 4
    score += len(high_conf_classes) * 2
    if validation_status == "confirmed":
        score += 2
    if impact_reportable:
        score += 2
    if evidence_count >= 3:
        score += 1
    if fallback_used:
        score -= 2

    promoted = bool(confirmed_classes or impact_reportable or score >= 4)
    reasons: list[str] = []
    if confirmed_classes:
        reasons.append("confirmed hypotheses present")
    if impact_reportable:
        reasons.append("impact is reportable")
    if validation_status == "confirmed":
        reasons.append("validation status is confirmed")
    if not promoted:
        reasons.append("evidence is not yet strong enough for memory promotion")

    return {
        "promoted": promoted,
        "score": score,
        "confirmed_classes": confirmed_classes[:6],
        "high_confidence_classes": high_conf_classes[:6],
        "validation_status": validation_status,
        "impact_reportable": impact_reportable,
        "evidence_count": evidence_count,
        "reasons": reasons[:4],
    }


def append_history_record(record: dict) -> Path:
    ensure_storage()
    enriched_record = dict(record)
    enriched_record.setdefault("memory_partition_key", partition_from_payload(enriched_record))
    enriched_record["memory_promotion"] = build_memory_promotion_profile(enriched_record)
    redacted_record = redact_persisted_data(enriched_record)
    with ANALYSIS_HISTORY_PATH.open("a", encoding="utf-8") as handle:
        handle.write(serialize_jsonl_record(redacted_record) + "\n")
    _prune_history_jsonl(ANALYSIS_HISTORY_PATH, HISTORY_JSONL_MAX_RECORDS)
    append_analysis_snapshot(redacted_record)
    append_phase_snapshots(redacted_record)
    append_provider_diagnostics(redacted_record)
    if (redacted_record.get("memory_promotion") or {}).get("promoted"):
        append_review_example(redacted_record)
    return ANALYSIS_HISTORY_PATH


def read_history_records(limit: int | None = None) -> list[dict]:
    ensure_storage()
    if not ANALYSIS_HISTORY_PATH.exists():
        return []

    lines = ANALYSIS_HISTORY_PATH.read_text(encoding="utf-8").splitlines()
    if limit is not None:
        lines = lines[-limit:]

    records = []
    latest_states = latest_hypothesis_state_map()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        payload = deserialize_jsonl_record(line)
        if not payload:
            continue
        records.append(apply_hypothesis_state(payload, latest_states))
    return records


def filter_history_records(records: list[dict], *, request_id: str = "", status: str = "") -> list[dict]:
    normalized_request_id = (request_id or "").strip()
    normalized_status = (status or "").strip().lower()
    filtered = []
    for record in records:
        if normalized_request_id and (record.get("request_id") or "").strip() != normalized_request_id:
            continue
        if normalized_status and (record.get("status") or "").strip().lower() != normalized_status:
            continue
        filtered.append(record)
    return filtered


def paginate_history_records(
    *,
    limit: int = 20,
    cursor: int = 0,
    request_id: str = "",
    status: str = "",
) -> dict:
    records = list(reversed(filter_history_records(read_history_records(), request_id=request_id, status=status)))
    safe_cursor = max(0, int(cursor or 0))
    safe_limit = max(1, min(int(limit or 20), 100))
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


def history_records_jsonl(records: list[dict]) -> str:
    normalized_records = [_to_record_dict(record) for record in records]
    return "".join(json.dumps(record, ensure_ascii=True) + "\n" for record in normalized_records)


def history_records_markdown(page: dict) -> str:
    items = page.get("items") or []
    lines = [
        "# Recent Analysis History",
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
        item = _to_record_dict(item)
        result = item.get("result") or {}
        analysis_run = _analysis_run(item)
        lines.append(
            f"- {item.get('created_at') or '<unknown>'} | {item.get('job_id') or '<unknown>'} | "
            f"{item.get('request_id') or '<unknown>'} | {item.get('status') or '<unknown>'} | "
            f"{item.get('target_url') or '<unknown>'}"
        )
        lines.append(
            f"  backend={result.get('analysis_backend') or '<unknown>'}, "
            f"fallback={bool(result.get('fallback_used'))}, "
            f"hypotheses={len(analysis_run.get('hypotheses') or [])}, "
            f"evidence={len(analysis_run.get('evidence') or [])}"
        )
    return "\n".join(lines) + "\n"


def _to_record_dict(record) -> dict:
    if isinstance(record, dict):
        return dict(record)
    if hasattr(record, "model_dump"):
        return record.model_dump()
    if hasattr(record, "dict"):
        return record.dict()
    return dict(vars(record))


def get_batch_records(batch_id: str) -> list[dict]:
    return [record for record in read_history_records() if record.get("batch_id") == batch_id]


def get_job_record(job_id: str) -> dict | None:
    for record in read_history_records():
        if record.get("job_id") == job_id:
            return record
    return None


def summarize_batch(records: list[dict]) -> dict:
    if not records:
        return {
            "batch_id": "",
            "total": 0,
            "completed": 0,
            "failed": 0,
            "grouped_vuln_classes": {},
            "grouped_hypothesis_classes": {},
            "combined_tags": [],
            "source_links": [],
            "questions_for_user": [],
            "suggested_wordlists": [],
            "total_hypotheses": 0,
            "total_evidence_items": 0,
            "items": [],
        }

    grouped = defaultdict(int)
    grouped_hypotheses = defaultdict(int)
    combined_tags = []
    source_links = []
    questions = []
    wordlists = []
    items = []
    total_hypotheses = 0
    total_evidence_items = 0

    for record in records:
        result = record.get("result") or {}
        analysis_run = _analysis_run(record)
        for vuln in result.get("potential_vulnerabilities", []):
            if isinstance(vuln, str) and vuln.startswith("[") and "]" in vuln:
                vuln_class = vuln[1:vuln.index("]")]
            else:
                vuln_class = "general"
            grouped[vuln_class] += 1

        hypotheses = analysis_run.get("hypotheses") or []
        total_hypotheses += len(hypotheses)
        total_evidence_items += len(analysis_run.get("evidence") or [])
        for hypothesis in hypotheses:
            vuln_class = (hypothesis.get("vuln_class") or "general").strip() or "general"
            grouped_hypotheses[vuln_class] += 1

        for tag in (result.get("nuclei_tags") or "").split(","):
            tag = tag.strip()
            if tag and tag not in combined_tags:
                combined_tags.append(tag)

        wordlist = result.get("seclists_path")
        if wordlist and wordlist not in wordlists:
            wordlists.append(wordlist)

        for link in result.get("source_links", []):
            if link and link not in source_links:
                source_links.append(link)

        for question in result.get("questions_for_user", []):
            if question and question not in questions:
                questions.append(question)

        items.append({
            "job_id": record.get("job_id"),
            "target_url": record.get("target_url"),
            "status": record.get("status"),
            "analysis": result.get("analysis") if result else None,
            "potential_vulnerabilities": result.get("potential_vulnerabilities", []) if result else [],
            "hypothesis_count": len(hypotheses),
            "evidence_count": len(analysis_run.get("evidence") or []),
        })

    return {
        "batch_id": records[0].get("batch_id") or "",
        "total": len(records),
        "completed": sum(1 for record in records if record.get("status") == "completed"),
        "failed": sum(1 for record in records if record.get("status") == "failed"),
        "grouped_vuln_classes": dict(grouped),
        "grouped_hypothesis_classes": dict(grouped_hypotheses),
        "combined_tags": combined_tags,
        "source_links": source_links,
        "questions_for_user": questions[:8],
        "suggested_wordlists": wordlists,
        "total_hypotheses": total_hypotheses,
        "total_evidence_items": total_evidence_items,
        "items": items,
    }


def batch_summary_markdown(summary: dict) -> str:
    lines = [
        f"# Batch Summary: {summary.get('batch_id') or 'unknown'}",
        "",
        f"- Total items: {summary.get('total', 0)}",
        f"- Completed: {summary.get('completed', 0)}",
        f"- Failed: {summary.get('failed', 0)}",
        f"- Stored hypotheses: {summary.get('total_hypotheses', 0)}",
        f"- Stored evidence items: {summary.get('total_evidence_items', 0)}",
        "",
        "## Vulnerability Classes",
    ]

    grouped = summary.get("grouped_vuln_classes", {})
    if grouped:
        for vuln_class, count in grouped.items():
            lines.append(f"- `{vuln_class}`: {count}")
    else:
        lines.append("- None")

    lines.extend(["", "## Hypothesis Classes"])
    hypothesis_groups = summary.get("grouped_hypothesis_classes", {})
    if hypothesis_groups:
        for vuln_class, count in hypothesis_groups.items():
            lines.append(f"- `{vuln_class}`: {count}")
    else:
        lines.append("- None")

    lines.extend(["", "## Combined Tags"])
    tags = summary.get("combined_tags", [])
    lines.append("- " + ", ".join(tags) if tags else "- None")

    lines.extend(["", "## Source Links"])
    links = summary.get("source_links", [])
    if links:
        for link in links:
            lines.append(f"- {link}")
    else:
        lines.append("- None")

    lines.extend(["", "## Follow-up Questions"])
    questions = summary.get("questions_for_user", [])
    if questions:
        for question in questions:
            lines.append(f"- {question}")
    else:
        lines.append("- None")

    lines.extend(["", "## Items"])
    for item in summary.get("items", []):
        lines.append(
            f"- {item.get('target_url')} [{item.get('status')}] "
            f"(hypotheses={item.get('hypothesis_count', 0)}, evidence={item.get('evidence_count', 0)})"
        )
        for vuln in item.get("potential_vulnerabilities", []):
            lines.append(f"  - {vuln}")

    return "\n".join(lines) + "\n"


def job_summary_markdown(record: dict) -> str:
    result = record.get("result") or {}
    analysis_run = _analysis_run(record)
    snapshot = get_burp_session_snapshot(record.get("snapshot_id") or "")
    lines = [
        f"# AI Bridge Report: {record.get('job_id') or 'unknown'}",
        "",
        f"- Request ID: {record.get('request_id') or '<unknown>'}",
        f"- Snapshot ID: {record.get('snapshot_id') or '<none>'}",
        f"- Target URL: {record.get('target_url') or '<unknown>'}",
        f"- Method: {record.get('http_method') or '<unknown>'}",
        f"- Status: {record.get('status') or '<unknown>'}",
        f"- Profile: {record.get('selected_profile') or 'mcp-grounded-llama32'}",
        f"- Program platform: {record.get('program_platform') or record.get('program_policy_template') or '<none>'}",
        f"- Privacy Mode: {record.get('privacy_mode_override') or 'OFF'}",
        "",
        "## Review Scope",
        "- Included classes: " + ", ".join(record.get("review_scope_include_classes") or [] or ["<none>"]),
        "- Excluded classes: " + ", ".join(record.get("review_scope_exclude_classes") or [] or ["<none>"]),
        "",
        "## Analysis",
        result.get("analysis") or "No analysis was stored.",
        "",
        "## Primary Next Action",
        result.get("primary_next_action") or "No primary next action was stored.",
        "",
        "## Model Execution",
        f"- Backend: {result.get('analysis_backend') or '<unknown>'}",
        f"- Summary: {result.get('model_execution_summary') or '<none>'}",
        f"- Fallback used: {result.get('fallback_used') if result.get('fallback_used') is not None else '<unknown>'}",
        "",
        "## Request Plan",
        "## Potential Vulnerabilities",
    ]

    trace = result.get("model_execution_trace") or []
    if trace:
        lines.append("### Provider Trace")
        for item in trace:
            lines.append(f"- {item}")
        lines.append("")

    provider_failover = result.get("provider_failover") or {}
    if provider_failover:
        lines.append("### Provider Failover")
        lines.append(f"- Final status: {provider_failover.get('final_status') or '<unknown>'}")
        lines.append(f"- Final backend: {provider_failover.get('final_backend') or '<unknown>'}")
        lines.append(f"- MCP fallback triggered: {bool(provider_failover.get('mcp_fallback_triggered'))}")
        missing_fields = provider_failover.get("missing_fields") or []
        lines.append("- Missing fields backfilled: " + (", ".join(missing_fields) if missing_fields else "<none>"))
        for outcome in provider_failover.get("outcomes") or []:
            provider = outcome.get("provider") or "provider"
            status = outcome.get("status") or "unknown"
            detail = outcome.get("detail") or ""
            lines.append(f"- {provider}: {status} | {detail}")
        lines.append("")

    request_plan = result.get("request_plan") or []
    if request_plan:
        lines.pop()
        for item in request_plan:
            lines.append(f"- {item}")
        lines.extend(["", "## Potential Vulnerabilities"])
    else:
        lines.append("- None")
        lines.extend(["", "## Potential Vulnerabilities"])

    vulnerabilities = result.get("potential_vulnerabilities") or []
    if vulnerabilities:
        for vulnerability in vulnerabilities:
            lines.append(f"- {vulnerability}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Analysis Run",
        f"- Final recommendation: {analysis_run.get('final_recommendation') or '<none>'}",
        f"- Fallback reason: {analysis_run.get('fallback_reason') or '<none>'}",
        f"- Hypotheses stored: {len(analysis_run.get('hypotheses') or [])}",
        f"- Evidence items stored: {len(analysis_run.get('evidence') or [])}",
    ])
    provider_trace = analysis_run.get("provider_trace") or []
    if provider_trace:
        lines.append("- Provider trace in analysis run:")
        for item in provider_trace:
            lines.append(f"  - {item}")

    phases = analysis_run.get("phases") or {}
    lines.extend([
        "",
        "## Phases",
    ])
    if phases:
        for phase_name, phase_result in phases.items():
            lines.append(f"- {phase_name}: {json.dumps(phase_result, ensure_ascii=True)}")
    else:
        lines.append("- None")

    hypotheses = analysis_run.get("hypotheses") or []
    lines.extend([
        "",
        "## Hypotheses",
    ])
    if hypotheses:
        for item in hypotheses:
            lines.append(
                f"- [{item.get('vuln_class') or 'general'}] {item.get('summary') or '<no summary>'} "
                f"(confidence={item.get('confidence', 0.0)}, status={item.get('status') or 'suspected'})"
            )
    else:
        lines.append("- None")

    evidence = analysis_run.get("evidence") or []
    lines.extend([
        "",
        "## Evidence Items",
    ])
    if evidence:
        for item in evidence:
            lines.append(
                f"- [{item.get('source') or 'analysis'}] {item.get('summary') or '<no summary>'} "
                f"(confidence={item.get('confidence', 0.0)})"
            )
    else:
        lines.append("- None")

    if snapshot:
        lines.extend([
            "",
            "## Burp Session Snapshot",
            f"- Created at: {snapshot.get('created_at') or '<unknown>'}",
            f"- Issue: {((snapshot.get('issue_context') or {}).get('issue_name') or '<none>')}",
            f"- Proxy history entries: {((snapshot.get('proxy_history') or {}).get('count') or 0)}",
            f"- Repeater entries: {((snapshot.get('repeater_context') or {}).get('count') or 0)}",
        ])

    lines.extend([
        "",
        "## Confidence By Class",
    ])
    confidence = result.get("confidence_by_class") or []
    if confidence:
        for item in confidence:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Kali Tools",
    ])
    manual_tooling = result.get("manual_tooling") or []
    if manual_tooling:
        for item in manual_tooling:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Kali Commands",
    ])
    manual_commands = result.get("manual_commands") or []
    if manual_commands:
        for item in manual_commands:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Payload Starter Lists",
    ])
    payload_recommendations = result.get("payload_recommendations") or []
    if payload_recommendations:
        for item in payload_recommendations:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Confirmation Playbooks",
    ])
    confirmation_playbooks = result.get("confirmation_playbooks") or []
    if confirmation_playbooks:
        for item in confirmation_playbooks:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Escalation Guidance",
        f"- Profile: {result.get('escalation_profile') or '<none>'}",
        f"- Baseline confirmation: {result.get('baseline_confirmation') or '<none>'}",
    ])
    for item in result.get("business_impact_expansion_paths") or []:
        lines.append(f"- Impact expansion: {item}")
    for item in result.get("required_evidence_for_upgrade") or []:
        lines.append(f"- Required evidence: {item}")
    for item in result.get("stop_conditions") or []:
        lines.append(f"- Stop condition: {item}")

    lines.extend([
        "",
        "## Suggestion Queue",
    ])
    suggestions = result.get("suggestion_queue") or []
    if suggestions:
        for item in suggestions:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## BCheck Recommendations",
    ])
    bcheck_recommendations = result.get("bcheck_recommendations") or []
    if bcheck_recommendations:
        for item in bcheck_recommendations:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## History Correlation",
    ])
    correlation = result.get("history_correlation") or []
    if correlation:
        for item in correlation:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Suggested Tags and Wordlists",
        f"- Nuclei tags: {result.get('nuclei_tags') or '<none>'}",
        f"- SecLists path: {result.get('seclists_path') or '<none>'}",
        "",
        "## Source Links",
    ])
    source_links = result.get("source_links") or []
    if source_links:
        for link in source_links:
            lines.append(f"- {link}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Operator and Program Context",
        f"- In scope: {record.get('scope_includes_text') or '<none>'}",
        f"- Out of scope: {record.get('scope_excludes_text') or '<none>'}",
        f"- Rate limit: {record.get('rate_limit_text') or '<none>'}",
        f"- Max concurrency: {record.get('max_concurrency_text') or '<none>'}",
        f"- Custom headers: {record.get('custom_headers_text') or '<none>'}",
        f"- Program policy: {record.get('program_policy_text') or '<none>'}",
        f"- Browser verification allowed: {bool(record.get('browser_verification_allowed'))}",
        f"- Browser workflows: {', '.join(record.get('browser_allowed_workflows') or [] or ['<none>'])}",
        "",
        "## Shared Tool Results",
        record.get("tool_results_text") or "None",
        "",
        "## Burp BApp Findings",
        record.get("bapp_findings_text") or "None",
        "",
        "## Collaborator Evidence",
        record.get("collaborator_evidence_text") or "None",
        "",
        "## Evidence Timeline",
    ])
    timeline = record.get("evidence_timeline_entries") or []
    if timeline:
        for entry in timeline:
            lines.append(f"- {entry}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Follow-up Questions",
    ])
    questions = result.get("questions_for_user") or []
    if questions:
        for question in questions:
            lines.append(f"- {question}")
    else:
        lines.append("- None")

    return "\n".join(lines) + "\n"


def _prune_history_jsonl(path: Path, max_records: int) -> None:
    if max_records <= 0 or not path.exists():
        return

    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) <= max_records:
        return

    retained = lines[-max_records:]
    path.write_text(("\n".join(retained) + "\n") if retained else "", encoding="utf-8")
