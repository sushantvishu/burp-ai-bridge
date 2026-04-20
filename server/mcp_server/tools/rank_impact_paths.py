from server.core.impact_service import rank_impact_paths
from server.mcp_server.tools.common import ToolDefinition, extract_payload, payload_schema


def handle(arguments: dict) -> dict:
    payload = extract_payload(arguments)
    advisory = arguments.get("advisory") if isinstance(arguments.get("advisory"), dict) else None
    return rank_impact_paths(payload, advisory=advisory)


TOOL = ToolDefinition(
    name="rank_impact_paths",
    description="Rank likely impact paths and remaining evidence gaps for a confirmed or suspected issue.",
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
