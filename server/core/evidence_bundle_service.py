from __future__ import annotations

from typing import Any

from server.core.submission_report_service import build_bug_bounty_submission
from server.history_store import get_job_record
from server.local_guidance_db import query_guidance_packs
from server.memory_partition import partition_from_payload
from server.state.store import get_issue_workflow_state


def build_evidence_bundle(job_id: str, *, platform: str = "", snapshot_id: str = "") -> dict[str, Any]:
    record = get_job_record(job_id)
    if not record:
        raise ValueError(f"History record '{job_id}' was not found.")
    submission = build_bug_bounty_submission(job_id, platform=platform, snapshot_id=snapshot_id)
    snapshot = submission.get("burp_session_snapshot") or {}
    workflow = get_issue_workflow_state(
        issue_id=((snapshot.get("issue_context") or {}).get("issue_id") or ""),
        snapshot_id=submission.get("snapshot_id", ""),
    ) or {}
    vuln_classes = [
        item.get("vuln_class", "")
        for item in ((record.get("analysis_run") or {}).get("hypotheses") or [])
        if isinstance(item, dict)
    ]
    guidance_hits = query_guidance_packs(
        vuln_classes or ["general"],
        partition_key=partition_from_payload(record),
        top_k=4,
    )
    return {
        "job_id": job_id,
        "request_id": submission.get("request_id", ""),
        "snapshot_id": submission.get("snapshot_id", ""),
        "target_url": record.get("target_url", ""),
        "request_response": {
            "raw_request": record.get("raw_request", ""),
            "raw_response": record.get("raw_response", ""),
            "http_method": record.get("http_method", ""),
        },
        "burp_snapshot": snapshot,
        "best_diff": workflow.get("strongest_delta") or {},
        "planner": submission.get("impact_upgrade_planner") or {},
        "report_draft": {
            "title": submission.get("title", ""),
            "summary": submission.get("summary", ""),
            "impact_statement": submission.get("impact_statement", ""),
            "markdown": submission.get("markdown", ""),
        },
        "guidance_hits": guidance_hits.get("hits", [])[:4],
    }


def render_evidence_bundle_markdown(bundle: dict[str, Any]) -> str:
    request_response = bundle.get("request_response") or {}
    best_diff = bundle.get("best_diff") or {}
    planner = bundle.get("planner") or {}
    lines = [
        f"# Evidence Bundle for {bundle.get('job_id') or '<unknown>'}",
        "",
        f"- Request ID: {bundle.get('request_id') or '<unknown>'}",
        f"- Snapshot ID: {bundle.get('snapshot_id') or '<none>'}",
        f"- Target URL: {bundle.get('target_url') or '<unknown>'}",
        "",
        "## Request",
        request_response.get("raw_request") or "<none>",
        "",
        "## Response",
        request_response.get("raw_response") or "<none>",
        "",
        "## Best Diff",
        str(best_diff or "<none>"),
        "",
        "## Planner",
        f"- Current proof level: {planner.get('current_proof_level') or '<unknown>'}",
        f"- Next strongest allowed step: {planner.get('next_strongest_allowed_step') or '<none>'}",
        "",
        "## Guidance Hits",
    ]
    hits = bundle.get("guidance_hits") or []
    if hits:
        for hit in hits:
            lines.append(f"- {hit.get('name') or '<unknown>'}: {hit.get('influence_reason') or ''}")
    else:
        lines.append("- None")
    lines.extend([
        "",
        "## Report Draft",
        (bundle.get("report_draft") or {}).get("markdown") or "<none>",
    ])
    return "\n".join(lines) + "\n"
