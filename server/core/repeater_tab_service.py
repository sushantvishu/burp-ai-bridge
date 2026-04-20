from typing import Any

from server.core.analysis_service import coerce_payload


def build_repeater_tab_specs(payload_like, plan: dict[str, Any]) -> list[dict[str, Any]]:
    payload = coerce_payload(payload_like)
    raw_request = (getattr(payload, "raw_request", "") or "").strip()
    tabs: list[dict[str, Any]] = []
    issue = plan.get("dashboard_issue") or {}
    issue_label = " - ".join(part for part in [issue.get("issue_name", ""), issue.get("issue_id", "")] if part).strip()

    if raw_request:
        tabs.append({
            "tab_name": f"{issue_label} - baseline-control".strip(" -") if issue_label else "baseline-control",
            "request_text": raw_request,
            "summary": "Untouched baseline request for comparison.",
            "expected_signal": "Use this as the control tab before comparing variants.",
            "request_ref": plan.get("preferred_request_ref", ""),
            "issue_id": (issue.get("issue_id") or ""),
        })

    for index, item in enumerate(list(plan.get("repeater_variant_requests") or [])[:6], start=1):
        request_text = str(item.get("request_text") or "").strip()
        if not request_text:
            continue
        variant_label = str(item.get("name") or f"variant-{index}").strip()
        tabs.append({
            "tab_name": f"{issue_label} - {variant_label}".strip(" -") if issue_label else variant_label,
            "request_text": request_text,
            "summary": str(item.get("summary") or item.get("expected_signal") or ""),
            "expected_signal": str(item.get("expected_signal") or ""),
            "request_ref": plan.get("preferred_request_ref", ""),
            "issue_id": (issue.get("issue_id") or ""),
        })
    return tabs
