from server.core.burp_context_service import get_recent_proxy_history
from server.mcp_server.tools.common import ToolDefinition, extract_payload, parse_int, payload_schema


def handle(arguments: dict) -> dict:
    return get_recent_proxy_history(
        extract_payload(arguments),
        limit=parse_int(arguments.get("limit"), default=8, minimum=1, maximum=12),
    )


TOOL = ToolDefinition(
    name="get_recent_proxy_history",
    description="Return a bounded view of recent Proxy history entries for the supplied payload.",
    input_schema={
        "type": "object",
        "properties": {
            "payload": payload_schema(required=False),
            "limit": {"type": "integer", "minimum": 1, "maximum": 12},
        },
        "required": ["payload"],
    },
    handler=handle,
)
