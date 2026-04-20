from server.core.recommendation_service import review_project_readiness
from server.mcp_server.tools.common import ToolDefinition, payload_schema


def handle(arguments: dict) -> dict:
    payload = arguments.get("payload") if isinstance(arguments.get("payload"), dict) else arguments
    return review_project_readiness(payload)


TOOL = ToolDefinition(
    name="review_project_readiness",
    description="Review readiness, supporting Burp setup, and recommended supporting checks before wider validation.",
    input_schema=payload_schema(),
    handler=handle,
)
