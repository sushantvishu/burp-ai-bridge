from server.core.validation_service import validate_hypothesis
from server.mcp_server.tools.common import ToolDefinition, extract_payload, payload_schema


def handle(arguments: dict) -> dict:
    payload = extract_payload(arguments)
    advisory = arguments.get("advisory") if isinstance(arguments.get("advisory"), dict) else None
    run = arguments.get("run") if isinstance(arguments.get("run"), dict) else None
    hypothesis_id = (arguments.get("hypothesis_id") or "").strip() or None
    return validate_hypothesis(payload, hypothesis_id=hypothesis_id, advisory=advisory, run=run)


TOOL = ToolDefinition(
    name="validate_hypothesis",
    description="Validate one hypothesis, highlight missing evidence, and label the next safe confirmation actions.",
    input_schema={
        "type": "object",
        "properties": {
            "payload": payload_schema(),
            "hypothesis_id": {"type": "string"},
            "advisory": {"type": "object"},
            "run": {"type": "object"},
        },
        "required": ["payload"],
    },
    handler=handle,
)
