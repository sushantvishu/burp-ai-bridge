from server.burp_mcp_adapter import call_burp_mcp_capability
from server.mcp_server.tools.common import ToolDefinition, extract_payload, parse_int


def handle(arguments: dict) -> dict:
    payload = extract_payload(arguments)
    target_url = (payload.get("target_url") or payload.get("url") or arguments.get("target_url") or "").strip()
    return call_burp_mcp_capability(
        arguments.get("capability") or "",
        count=parse_int(arguments.get("count"), 8, 1, 20),
        offset=parse_int(arguments.get("offset"), 0, 0, 100),
        query=(arguments.get("query") or "").strip(),
        target_url=target_url,
        payload=payload,
    )


TOOL = ToolDefinition(
    name="call_burp_mcp_capability",
    description="Call one resolved Burp MCP capability through the bridge's read-only policy layer.",
    input_schema={
        "type": "object",
        "properties": {
            "capability": {"type": "string"},
            "count": {"type": "integer"},
            "offset": {"type": "integer"},
            "query": {"type": "string"},
            "target_url": {"type": "string"},
            "payload": {"type": "object"},
        },
        "required": ["capability"],
    },
    handler=handle,
)
