from server.core.history_service import query_similar_history
from server.mcp_server.tools.common import ToolDefinition, extract_payload, parse_int, payload_schema


def handle(arguments: dict) -> dict:
    return query_similar_history(
        extract_payload(arguments),
        limit=parse_int(arguments.get("limit"), default=5, minimum=1, maximum=12),
    )


TOOL = ToolDefinition(
    name="query_similar_history",
    description="Query stored history for similar exchanges and return prior hypotheses and evidence counts.",
    input_schema={
        "type": "object",
        "properties": {
            "payload": payload_schema(),
            "limit": {"type": "integer", "minimum": 1, "maximum": 12},
        },
        "required": ["payload"],
    },
    handler=handle,
)
