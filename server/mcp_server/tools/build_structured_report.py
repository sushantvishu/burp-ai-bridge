from server.core.report_service import build_structured_report
from server.mcp_server.tools.common import ToolDefinition, extract_payload, payload_schema


def handle(arguments: dict) -> dict:
    job_id = (arguments.get("job_id") or "").strip()
    if not job_id:
        raise ValueError("job_id is required.")
    payload = None
    if isinstance(arguments.get("payload"), dict):
        payload = extract_payload(arguments)
    advisory = arguments.get("advisory") if isinstance(arguments.get("advisory"), dict) else None
    run = arguments.get("run") if isinstance(arguments.get("run"), dict) else None
    return build_structured_report(job_id, payload_like=payload, advisory=advisory, run=run)


TOOL = ToolDefinition(
    name="build_structured_report",
    description="Build a report object that combines persisted evidence with live validation and impact summaries.",
    input_schema={
        "type": "object",
        "properties": {
            "job_id": {"type": "string"},
            "payload": payload_schema(),
            "advisory": {"type": "object"},
            "run": {"type": "object"},
        },
        "required": ["job_id"],
    },
    handler=handle,
)
