from server.capabilities.burp_exporter import build_burp_exporter_config
from server.mcp_server.tools.common import ToolDefinition


def handle(arguments: dict) -> dict:
    return build_burp_exporter_config()


TOOL = ToolDefinition(
    name="get_burp_exporter_config",
    description="Return the recommended Burp-side exporter or macro contract for posting requests into the bridge.",
    input_schema={"type": "object", "properties": {}},
    handler=handle,
)
