from server.core.burp_context_service import get_repeater_request
from server.mcp_server.tools.common import ToolDefinition, extract_payload, parse_int, payload_schema


def handle(arguments: dict) -> dict:
    return get_repeater_request(
        extract_payload(arguments),
        limit=parse_int(arguments.get("limit"), default=3, minimum=1, maximum=6),
    )


TOOL = ToolDefinition(
    name="get_repeater_request",
    description="Return bounded Repeater request context for the supplied payload.",
    input_schema={
        "type": "object",
        "properties": {
            "payload": payload_schema(required=False),
            "limit": {"type": "integer", "minimum": 1, "maximum": 6},
        },
        "required": ["payload"],
    },
    handler=handle,
)
