from server.core.history_service import list_history_records
from server.mcp_server.tools.common import ToolDefinition, parse_int


def handle(arguments: dict) -> dict:
    return list_history_records(
        cursor=parse_int(arguments.get("cursor"), default=0, minimum=0, maximum=1_000_000),
        limit=parse_int(arguments.get("limit"), default=20, minimum=1, maximum=50),
    )


TOOL = ToolDefinition(
    name="list_history_records",
    description="List stored Burp-derived analysis history using cursor-based pagination.",
    input_schema={
        "type": "object",
        "properties": {
            "cursor": {"type": "integer", "minimum": 0},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        },
    },
    handler=handle,
)
