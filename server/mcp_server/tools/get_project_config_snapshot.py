from server.core.burp_context_service import get_project_config_snapshot
from server.mcp_server.tools.common import ToolDefinition, extract_payload, payload_schema


def handle(arguments: dict) -> dict:
    return get_project_config_snapshot(extract_payload(arguments))


TOOL = ToolDefinition(
    name="get_project_config_snapshot",
    description="Return a bounded Burp project configuration snapshot for the supplied payload.",
    input_schema={
        "type": "object",
        "properties": {
            "payload": payload_schema(required=False),
        },
        "required": ["payload"],
    },
    handler=handle,
)
