from server.core.history_service import explain_analysis_run
from server.mcp_server.tools.common import ToolDefinition


def handle(arguments: dict) -> dict:
    job_id = (arguments.get("job_id") or "").strip()
    if not job_id:
        raise ValueError("job_id is required.")
    return explain_analysis_run(job_id)


TOOL = ToolDefinition(
    name="explain_analysis_run",
    description="Summarize why a stored analysis reached its current confidence, validation, and impact state.",
    input_schema={
        "type": "object",
        "properties": {
            "job_id": {"type": "string"},
        },
        "required": ["job_id"],
    },
    handler=handle,
)
