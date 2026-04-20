from server.core.browser_verification_service import build_browser_verification_plan
from server.mcp_server.tools.common import ToolDefinition, extract_payload, payload_schema


def _handler(arguments: dict) -> dict:
    payload = extract_payload(arguments)
    return build_browser_verification_plan(payload)


TOOL = ToolDefinition(
    name="review_browser_verification",
    description="Build a bounded browser-assisted confirmation plan for explicitly allowed workflows only.",
    input_schema=payload_schema(),
    handler=_handler,
)
