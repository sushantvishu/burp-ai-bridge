import json
import sys
import traceback
from typing import Any

from server.mcp_server.tools import TOOLS
from server.settings import MCP_PROTOCOL_VERSION


def handle_message(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}

    if method == "initialize":
        if request_id is None:
            return None
        requested_version = params.get("protocolVersion") or MCP_PROTOCOL_VERSION
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": requested_version,
                "serverInfo": {
                    "name": "burp-ai-bridge-mcp",
                    "version": "1.0",
                },
                "capabilities": {
                    "tools": {},
                },
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        if request_id is None:
            return None
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": tool.name,
                        "description": tool.description,
                        "inputSchema": tool.input_schema,
                    }
                    for tool in TOOLS.values()
                ]
            },
        }

    if method == "tools/call":
        if request_id is None:
            return None
        tool_name = (params.get("name") or "").strip()
        tool = TOOLS.get(tool_name)
        if tool is None:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [{"type": "text", "text": f"Unknown tool '{tool_name}'."}],
                    "isError": True,
                },
            }
        try:
            result = tool.handler(params.get("arguments") or {})
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=True)}],
                    "structuredContent": result,
                    "isError": False,
                },
            }
        except Exception as exc:
            detail = f"{exc}\n{traceback.format_exc(limit=6)}"
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [{"type": "text", "text": detail}],
                    "isError": True,
                },
            }

    if request_id is None:
        return None
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32601,
            "message": f"Method '{method}' is not supported.",
        },
    }


def main() -> int:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            error_response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": f"Invalid JSON: {exc}",
                },
            }
            sys.stdout.write(json.dumps(error_response, ensure_ascii=True) + "\n")
            sys.stdout.flush()
            continue

        response = handle_message(message)
        if response is None:
            continue
        sys.stdout.write(json.dumps(response, ensure_ascii=True) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
