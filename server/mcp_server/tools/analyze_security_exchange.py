from server.core.analysis_service import analyze_exchange
from server.mcp_server.tools.common import ToolDefinition, extract_payload, payload_schema


def handle(arguments: dict) -> dict:
    return analyze_exchange(extract_payload(arguments))


TOOL = ToolDefinition(
    name="analyze_security_exchange",
    description="Analyze one Burp-captured HTTP or HTTPS exchange and return an advisory plus phased run metadata.",
    input_schema=payload_schema(),
    handler=handle,
)
