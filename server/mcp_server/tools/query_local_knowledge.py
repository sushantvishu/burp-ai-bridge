from server.core.knowledge_service import query_local_knowledge
from server.mcp_server.tools.common import ToolDefinition, parse_int


def handle(arguments: dict) -> dict:
    return query_local_knowledge(
        (arguments.get("query") or "").strip(),
        top_k=parse_int(arguments.get("top_k"), default=5, minimum=1, maximum=10),
    )


TOOL = ToolDefinition(
    name="query_local_knowledge",
    description="Search the local knowledge base notes and return structured hits and context.",
    input_schema={
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "top_k": {"type": "integer", "minimum": 1, "maximum": 10},
        },
        "required": ["query"],
    },
    handler=handle,
)
