from server.core.submission_report_service import build_bug_bounty_submission
from server.mcp_server.tools.common import ToolDefinition


def _handler(arguments: dict) -> dict:
    return build_bug_bounty_submission(
        arguments.get("job_id") or "",
        platform=arguments.get("platform") or "",
    )


TOOL = ToolDefinition(
    name="build_bug_bounty_submission",
    description="Build a platform-tuned bug bounty submission package from a stored analysis job.",
    input_schema={
        "type": "object",
        "properties": {
            "job_id": {"type": "string"},
            "platform": {"type": "string"},
        },
        "required": ["job_id"],
    },
    handler=_handler,
)
