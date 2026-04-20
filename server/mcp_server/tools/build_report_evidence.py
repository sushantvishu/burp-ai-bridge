from server.core.history_service import build_report_evidence
from server.mcp_server.tools.common import ToolDefinition


def handle(arguments: dict) -> dict:
    job_id = (arguments.get("job_id") or "").strip()
    if not job_id:
        raise ValueError("job_id is required.")
    return build_report_evidence(job_id)


TOOL = ToolDefinition(
    name="build_report_evidence",
    description="Build a report-ready evidence bundle from a stored analysis job.",
    input_schema={
        "type": "object",
        "properties": {
            "job_id": {"type": "string"},
        },
        "required": ["job_id"],
    },
    handler=handle,
)
