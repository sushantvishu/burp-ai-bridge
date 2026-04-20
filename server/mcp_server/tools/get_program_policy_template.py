from server.core.program_policy_service import get_program_policy_template
from server.mcp_server.tools.common import ToolDefinition


def _handler(arguments: dict) -> dict:
    return get_program_policy_template(arguments.get("template_name") or arguments.get("platform") or "")


TOOL = ToolDefinition(
    name="get_program_policy_template",
    description="Return a bug-bounty policy template with scope, rate-limit, browser-verification, and reporting guidance.",
    input_schema={
        "type": "object",
        "properties": {
            "template_name": {"type": "string"},
            "platform": {"type": "string"},
        },
    },
    handler=_handler,
)
