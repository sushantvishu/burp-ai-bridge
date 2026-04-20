from server.core.burp_action_service import next_burp_action
from server.mcp_server.tools.common import ToolDefinition, extract_payload, payload_schema


def handle(arguments: dict) -> dict:
    payload = extract_payload(arguments)
    advisory = arguments.get("advisory") if isinstance(arguments.get("advisory"), dict) else None
    return next_burp_action(payload, advisory=advisory)


TOOL = ToolDefinition(
    name="next_burp_action",
    description="Return the next Burp-native action sequence for the current hypothesis.",
    input_schema={
        "type": "object",
        "properties": {
            "payload": payload_schema(),
            "advisory": {"type": "object"},
        },
        "required": ["payload"],
    },
    handler=handle,
)
