from server.api.handlers import normalize_burp_payload
from server.mcp_server.tools.common import ToolDefinition


def handle(arguments: dict) -> dict:
    payload = arguments.get("payload")
    if not isinstance(payload, dict):
        payload = dict(arguments)
    return normalize_burp_payload(payload)


TOOL = ToolDefinition(
    name="normalize_burp_payload",
    description="Normalize Burp Dashboard, Proxy, Logger, Repeater, and project-config exports into the internal payload contract.",
    input_schema={
        "type": "object",
        "properties": {
            "payload": {"type": "object"},
        },
        "required": ["payload"],
    },
    handler=handle,
)
