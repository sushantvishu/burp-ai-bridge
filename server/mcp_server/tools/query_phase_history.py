from server.core.history_service import query_phase_history
from server.mcp_server.tools.common import ToolDefinition, parse_int


def handle(arguments: dict) -> dict:
    return query_phase_history(
        job_id=(arguments.get("job_id") or "").strip(),
        phase=(arguments.get("phase") or "").strip(),
        limit=parse_int(arguments.get("limit"), default=20, minimum=1, maximum=100),
    )


TOOL = ToolDefinition(
    name="query_phase_history",
    description="Query persisted phase snapshots by job id and/or phase name for crash recovery and reasoning review.",
    input_schema={
        "type": "object",
        "properties": {
            "job_id": {"type": "string"},
            "phase": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        },
    },
    handler=handle,
)
