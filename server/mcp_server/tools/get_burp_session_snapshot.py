from server.core.burp_snapshot_service import build_burp_session_snapshot
from server.mcp_server.tools.common import ToolDefinition, extract_payload, payload_schema


def handle(arguments: dict) -> dict:
    return build_burp_session_snapshot(extract_payload(arguments))


TOOL = ToolDefinition(
    name="get_burp_session_snapshot",
    description="Capture a bounded Burp session snapshot with issue details, history, repeater context, editor request, and project options.",
    input_schema=payload_schema(required=False),
    handler=handle,
)
