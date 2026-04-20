from server.burp_mcp_adapter import inspect_burp_mcp_capabilities
from server.mcp_server.tools.common import ToolDefinition


def handle(arguments: dict) -> dict:
    return inspect_burp_mcp_capabilities()


TOOL = ToolDefinition(
    name="inspect_burp_mcp_capabilities",
    description="Inspect the connected PortSwigger Burp MCP server, including resolved capability mapping and blocked tools.",
    input_schema={"type": "object", "properties": {}},
    handler=handle,
)
