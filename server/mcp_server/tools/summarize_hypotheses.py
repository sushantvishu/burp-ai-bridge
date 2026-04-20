from server.core.hypothesis_service import summarize_hypotheses
from server.mcp_server.tools.common import ToolDefinition, extract_payload, payload_schema


def handle(arguments: dict) -> dict:
    payload = extract_payload(arguments)
    advisory = arguments.get("advisory") if isinstance(arguments.get("advisory"), dict) else None
    run = arguments.get("run") if isinstance(arguments.get("run"), dict) else None
    return summarize_hypotheses(payload, advisory=advisory, run=run)


TOOL = ToolDefinition(
    name="summarize_hypotheses",
    description="Summarize and rank current hypotheses from a single exchange or an existing analysis run.",
    input_schema={
        "type": "object",
        "properties": {
            "payload": payload_schema(),
            "advisory": {"type": "object"},
            "run": {"type": "object"},
        },
        "required": ["payload"],
    },
    handler=handle,
)
