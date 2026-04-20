from server.core.burp_context_service import get_dashboard_issue_context
from server.mcp_server.tools.common import ToolDefinition, extract_payload, payload_schema


def handle(arguments: dict) -> dict:
    return get_dashboard_issue_context(extract_payload(arguments))


TOOL = ToolDefinition(
    name="get_issue_context",
    description="Return bounded Burp Dashboard issue context for the current assessment payload.",
    input_schema=payload_schema(required=False),
    handler=handle,
)
