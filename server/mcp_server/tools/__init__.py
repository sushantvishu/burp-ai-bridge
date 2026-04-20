from server.mcp_server.tools.analyze_security_exchange import TOOL as ANALYZE_SECURITY_EXCHANGE_TOOL
from server.mcp_server.tools.build_bug_bounty_submission import TOOL as BUILD_BUG_BOUNTY_SUBMISSION_TOOL
from server.mcp_server.tools.build_report_evidence import TOOL as BUILD_REPORT_EVIDENCE_TOOL
from server.mcp_server.tools.build_structured_report import TOOL as BUILD_STRUCTURED_REPORT_TOOL
from server.mcp_server.tools.call_burp_mcp_capability import TOOL as CALL_BURP_MCP_CAPABILITY_TOOL
from server.mcp_server.tools.describe_burp_payload_contract import TOOL as DESCRIBE_BURP_PAYLOAD_CONTRACT_TOOL
from server.mcp_server.tools.explain_analysis_run import TOOL as EXPLAIN_ANALYSIS_RUN_TOOL
from server.mcp_server.tools.get_burp_exporter_config import TOOL as GET_BURP_EXPORTER_CONFIG_TOOL
from server.mcp_server.tools.get_burp_session_snapshot import TOOL as GET_BURP_SESSION_SNAPSHOT_TOOL
from server.mcp_server.tools.get_issue_context import TOOL as GET_ISSUE_CONTEXT_TOOL
from server.mcp_server.tools.get_logger_deltas import TOOL as GET_LOGGER_DELTAS_TOOL
from server.mcp_server.tools.get_program_policy_template import TOOL as GET_PROGRAM_POLICY_TEMPLATE_TOOL
from server.mcp_server.tools.get_project_config_snapshot import TOOL as GET_PROJECT_CONFIG_SNAPSHOT_TOOL
from server.mcp_server.tools.get_recent_proxy_history import TOOL as GET_RECENT_PROXY_HISTORY_TOOL
from server.mcp_server.tools.get_repeater_request import TOOL as GET_REPEATER_REQUEST_TOOL
from server.mcp_server.tools.inspect_burp_mcp_capabilities import TOOL as INSPECT_BURP_MCP_CAPABILITIES_TOOL
from server.mcp_server.tools.list_history_records import TOOL as LIST_HISTORY_RECORDS_TOOL
from server.mcp_server.tools.next_burp_action import TOOL as NEXT_BURP_ACTION_TOOL
from server.mcp_server.tools.normalize_burp_payload import TOOL as NORMALIZE_BURP_PAYLOAD_TOOL
from server.mcp_server.tools.prepare_burp_export_payload import TOOL as PREPARE_BURP_EXPORT_PAYLOAD_TOOL
from server.mcp_server.tools.query_local_knowledge import TOOL as QUERY_LOCAL_KNOWLEDGE_TOOL
from server.mcp_server.tools.query_phase_history import TOOL as QUERY_PHASE_HISTORY_TOOL
from server.mcp_server.tools.query_similar_history import TOOL as QUERY_SIMILAR_HISTORY_TOOL
from server.mcp_server.tools.rank_impact_paths import TOOL as RANK_IMPACT_PATHS_TOOL
from server.mcp_server.tools.recommend_bchecks import TOOL as RECOMMEND_BCHECKS_TOOL
from server.mcp_server.tools.review_project_readiness import TOOL as REVIEW_PROJECT_READINESS_TOOL
from server.mcp_server.tools.review_browser_verification import TOOL as REVIEW_BROWSER_VERIFICATION_TOOL
from server.mcp_server.tools.summarize_hypotheses import TOOL as SUMMARIZE_HYPOTHESES_TOOL
from server.mcp_server.tools.update_hypothesis_status import TOOL as UPDATE_HYPOTHESIS_STATUS_TOOL
from server.mcp_server.tools.validate_hypothesis import TOOL as VALIDATE_HYPOTHESIS_TOOL


REGISTERED_TOOLS = [
    ANALYZE_SECURITY_EXCHANGE_TOOL,
    SUMMARIZE_HYPOTHESES_TOOL,
    VALIDATE_HYPOTHESIS_TOOL,
    RANK_IMPACT_PATHS_TOOL,
    NEXT_BURP_ACTION_TOOL,
    QUERY_LOCAL_KNOWLEDGE_TOOL,
    QUERY_SIMILAR_HISTORY_TOOL,
    RECOMMEND_BCHECKS_TOOL,
    REVIEW_PROJECT_READINESS_TOOL,
    REVIEW_BROWSER_VERIFICATION_TOOL,
    GET_PROGRAM_POLICY_TEMPLATE_TOOL,
    BUILD_REPORT_EVIDENCE_TOOL,
    BUILD_STRUCTURED_REPORT_TOOL,
    BUILD_BUG_BOUNTY_SUBMISSION_TOOL,
    GET_BURP_EXPORTER_CONFIG_TOOL,
    UPDATE_HYPOTHESIS_STATUS_TOOL,
    LIST_HISTORY_RECORDS_TOOL,
    QUERY_PHASE_HISTORY_TOOL,
    EXPLAIN_ANALYSIS_RUN_TOOL,
    INSPECT_BURP_MCP_CAPABILITIES_TOOL,
    CALL_BURP_MCP_CAPABILITY_TOOL,
    GET_BURP_SESSION_SNAPSHOT_TOOL,
    GET_ISSUE_CONTEXT_TOOL,
    GET_RECENT_PROXY_HISTORY_TOOL,
    GET_LOGGER_DELTAS_TOOL,
    GET_REPEATER_REQUEST_TOOL,
    GET_PROJECT_CONFIG_SNAPSHOT_TOOL,
    DESCRIBE_BURP_PAYLOAD_CONTRACT_TOOL,
    NORMALIZE_BURP_PAYLOAD_TOOL,
    PREPARE_BURP_EXPORT_PAYLOAD_TOOL,
]

TOOLS = {tool.name: tool for tool in REGISTERED_TOOLS}
