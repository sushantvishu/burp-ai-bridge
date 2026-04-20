from server.api.handlers import prepare_burp_export
from server.mcp_server.tools.common import ToolDefinition


def handle(arguments: dict) -> dict:
    payload = arguments.get("payload")
    if not isinstance(payload, dict):
        payload = dict(arguments)
    return prepare_burp_export(payload)


TOOL = ToolDefinition(
    name="prepare_burp_export_payload",
    description="Normalize and package a Burp-side export so it can be posted directly to the analysis API or MCP reasoning tools.",
    input_schema={
        "type": "object",
        "properties": {
            "payload": {"type": "object"},
        },
        "required": ["payload"],
    },
    handler=handle,
)
