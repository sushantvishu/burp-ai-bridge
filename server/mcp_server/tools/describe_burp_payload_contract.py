from server.api.handlers import build_burp_payload_contract
from server.mcp_server.tools.common import ToolDefinition


def handle(arguments: dict) -> dict:
    return build_burp_payload_contract()


TOOL = ToolDefinition(
    name="describe_burp_payload_contract",
    description="Return the Burp-side payload contract and accepted field aliases for transport into the reasoning pipeline.",
    input_schema={"type": "object", "properties": {}},
    handler=handle,
)
