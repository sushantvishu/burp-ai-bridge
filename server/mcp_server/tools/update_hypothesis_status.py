from server.core.history_service import update_hypothesis_status
from server.mcp_server.tools.common import ToolDefinition


def handle(arguments: dict) -> dict:
    return update_hypothesis_status(
        (arguments.get("job_id") or "").strip(),
        (arguments.get("hypothesis_id") or "").strip(),
        (arguments.get("status") or "").strip(),
        (arguments.get("notes") or "").strip(),
    )


TOOL = ToolDefinition(
    name="update_hypothesis_status",
    description="Update the status of a stored hypothesis to suspected, confirmed, discarded, or needs-review.",
    input_schema={
        "type": "object",
        "properties": {
            "job_id": {"type": "string"},
            "hypothesis_id": {"type": "string"},
            "status": {"type": "string"},
            "notes": {"type": "string"},
        },
        "required": ["job_id", "hypothesis_id", "status"],
    },
    handler=handle,
)
