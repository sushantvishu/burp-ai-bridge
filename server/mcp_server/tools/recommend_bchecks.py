from server.core.recommendation_service import recommend_bchecks_for_exchange
from server.mcp_server.tools.common import ToolDefinition, payload_schema


def handle(arguments: dict) -> dict:
    payload = arguments.get("payload") if isinstance(arguments.get("payload"), dict) else arguments
    return recommend_bchecks_for_exchange(payload)


TOOL = ToolDefinition(
    name="recommend_bchecks",
    description="Recommend upstream BChecks based on current deterministic signals and matched playbooks.",
    input_schema=payload_schema(),
    handler=handle,
)
