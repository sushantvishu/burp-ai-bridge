import json
import os
import queue
import shlex
import subprocess
import threading
import time
from dataclasses import replace
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests


class MCPError(RuntimeError):
    pass


class MCPConfigurationError(MCPError):
    pass


class MCPTimeoutError(MCPError):
    pass


class MCPProtocolError(MCPError):
    pass


class MCPHttpStatusError(MCPProtocolError):
    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code


class MCPToolError(MCPError):
    pass


@dataclass(slots=True)
class MCPServerConfig:
    transport: str
    tool_name: str
    timeout_seconds: int
    protocol_version: str
    command: str = ""
    url: str = ""
    working_directory: str = ""
    client_name: str = "burp-ai-bridge"
    client_version: str = "1.0"


@dataclass(slots=True)
class MCPCallResult:
    tool_name: str
    protocol_version: str
    server_name: str = ""
    server_version: str = ""
    available_tools: list[str] = field(default_factory=list)
    raw_result: dict[str, Any] = field(default_factory=dict)
    structured_content: dict[str, Any] = field(default_factory=dict)
    content_text: str = ""


@dataclass(slots=True)
class MCPServerInspectionResult:
    protocol_version: str
    server_name: str = ""
    server_version: str = ""
    available_tools: list[str] = field(default_factory=list)


def call_mcp_tool(config: MCPServerConfig, arguments: dict[str, Any]) -> MCPCallResult:
    last_error: Exception | None = None
    for session in _candidate_sessions(config):
        try:
            with session:
                return session.call_tool(arguments)
        except MCPError as exc:
            last_error = exc
            continue
    if isinstance(last_error, MCPError):
        raise last_error
    raise MCPConfigurationError("No usable MCP transport candidates were configured.")


def inspect_mcp_server(config: MCPServerConfig) -> MCPServerInspectionResult:
    last_error: Exception | None = None
    for session in _candidate_sessions(config):
        try:
            with session:
                available_tools = session._initialize()
                return MCPServerInspectionResult(
                    protocol_version=session._protocol_version,
                    server_name=session._server_name,
                    server_version=session._server_version,
                    available_tools=available_tools,
                )
        except MCPError as exc:
            last_error = exc
            continue
    if isinstance(last_error, MCPError):
        raise last_error
    raise MCPConfigurationError("No usable MCP transport candidates were configured.")


def candidate_mcp_urls(url: str) -> list[str]:
    configured = (url or "").strip()
    if not configured:
        return []
    trimmed = configured.rstrip("/")
    candidates = [trimmed]
    if trimmed.endswith("/sse"):
        candidates.append(trimmed[:-len("/sse")])
    else:
        candidates.append(trimmed + "/sse")
    deduped: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in deduped:
            deduped.append(candidate)
    return deduped


def _extract_structured_content(result: dict[str, Any]) -> dict[str, Any]:
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return structured

    if isinstance(structured, list):
        for item in structured:
            if isinstance(item, dict):
                return item

    for item in result.get("content") or []:
        if not isinstance(item, dict):
            continue
        text = item.get("text")
        if item.get("type") != "text" or not isinstance(text, str):
            continue
        text = text.strip()
        if not text:
            continue
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed

    return {}


def _extract_content_text(result: dict[str, Any]) -> str:
    blocks: list[str] = []
    for item in result.get("content") or []:
        if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
            text = item["text"].strip()
            if text:
                blocks.append(text)
    return "\n".join(blocks).strip()


def _candidate_sessions(config: MCPServerConfig) -> list["_BaseMcpSession"]:
    transport = (config.transport or "").strip().lower()
    sessions: list[_BaseMcpSession] = []
    if transport == "stdio":
        return [_StdioMcpSession(config)]
    if transport in {"http", "streamable-http", "streamable_http"}:
        return [_HttpMcpSession(replace(config, url=url)) for url in candidate_mcp_urls(config.url)]
    if transport == "auto":
        for url in candidate_mcp_urls(config.url):
            sessions.append(_HttpMcpSession(replace(config, transport="http", url=url)))
        if (config.command or "").strip():
            sessions.append(_StdioMcpSession(replace(config, transport="stdio")))
        return sessions
    raise MCPConfigurationError(f"Unsupported MCP transport '{config.transport}'. Use 'auto', 'stdio', or 'http'.")


class _BaseMcpSession:
    def __init__(self, config: MCPServerConfig):
        self._config = config
        self._request_id = 0
        self._protocol_version = config.protocol_version
        self._server_name = ""
        self._server_version = ""

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def open(self) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    def _send_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def _send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        raise NotImplementedError

    def _initialize(self) -> list[str]:
        initialize_result = self._send_request(
            "initialize",
            {
                "protocolVersion": self._config.protocol_version,
                "capabilities": {},
                "clientInfo": {
                    "name": self._config.client_name,
                    "version": self._config.client_version,
                },
            },
        )
        self._protocol_version = initialize_result.get("protocolVersion") or self._config.protocol_version
        server_info = initialize_result.get("serverInfo") or {}
        self._server_name = server_info.get("name") or ""
        self._server_version = server_info.get("version") or ""
        self._send_notification("notifications/initialized", {})
        return self._list_tools()

    def _list_tools(self) -> list[str]:
        tool_names: list[str] = []
        seen: set[str] = set()
        cursor: str | None = None

        while True:
            params = {"cursor": cursor} if cursor else {}
            result = self._send_request("tools/list", params)
            tools = result.get("tools") or []
            for tool in tools:
                if not isinstance(tool, dict):
                    continue
                name = (tool.get("name") or "").strip()
                if name and name not in seen:
                    seen.add(name)
                    tool_names.append(name)
            cursor = result.get("nextCursor")
            if not cursor:
                return tool_names

    def call_tool(self, arguments: dict[str, Any]) -> MCPCallResult:
        available_tools = self._initialize()
        if available_tools and self._config.tool_name not in available_tools:
            raise MCPConfigurationError(
                f"MCP tool '{self._config.tool_name}' was not advertised by the server. "
                f"Available tools: {', '.join(available_tools[:12]) or '<none>'}."
            )

        result = self._send_request(
            "tools/call",
            {
                "name": self._config.tool_name,
                "arguments": arguments,
            },
        )
        if result.get("isError"):
            detail = _extract_content_text(result) or "The MCP tool reported an error without a text message."
            raise MCPToolError(detail)

        return MCPCallResult(
            tool_name=self._config.tool_name,
            protocol_version=self._protocol_version,
            server_name=self._server_name,
            server_version=self._server_version,
            available_tools=available_tools,
            raw_result=result,
            structured_content=_extract_structured_content(result),
            content_text=_extract_content_text(result),
        )


class _StdioMcpSession(_BaseMcpSession):
    def __init__(self, config: MCPServerConfig):
        super().__init__(config)
        self._process: subprocess.Popen[str] | None = None
        self._stdout_queue: queue.Queue[str] = queue.Queue()
        self._stderr_tail: deque[str] = deque(maxlen=20)
        self._stdout_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None

    def open(self) -> None:
        if not self._config.command:
            raise MCPConfigurationError("MCP is enabled for stdio transport but MCP_SERVER_COMMAND is empty.")

        command = shlex.split(self._config.command, posix=False)
        if not command:
            raise MCPConfigurationError("MCP_SERVER_COMMAND did not contain a runnable command.")

        working_directory = self._config.working_directory.strip() or None
        if working_directory and not Path(working_directory).exists():
            raise MCPConfigurationError(f"MCP working directory does not exist: {working_directory}")

        try:
            child_env = dict(os.environ)
            child_env["BURP_AI_BRIDGE_DISABLE_MCP"] = "true"
            self._process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                bufsize=1,
                cwd=working_directory,
                env=child_env,
            )
        except OSError as exc:
            raise MCPConfigurationError(f"Unable to start MCP server command '{self._config.command}': {exc}") from exc

        if self._process.stdin is None or self._process.stdout is None or self._process.stderr is None:
            raise MCPProtocolError("MCP stdio process did not expose stdin/stdout/stderr pipes.")

        self._stdout_thread = threading.Thread(
            target=self._read_stdout,
            name="mcp-stdio-stdout",
            daemon=True,
        )
        self._stderr_thread = threading.Thread(
            target=self._read_stderr,
            name="mcp-stdio-stderr",
            daemon=True,
        )
        self._stdout_thread.start()
        self._stderr_thread.start()

    def close(self) -> None:
        if self._process is None:
            return
        try:
            if self._process.stdin:
                self._process.stdin.close()
        except OSError:
            pass
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._process.kill()
        self._process = None

    def _read_stdout(self) -> None:
        if self._process is None or self._process.stdout is None:
            return
        for line in self._process.stdout:
            normalized = line.strip()
            if normalized:
                self._stdout_queue.put(normalized)

    def _read_stderr(self) -> None:
        if self._process is None or self._process.stderr is None:
            return
        for line in self._process.stderr:
            normalized = line.strip()
            if normalized:
                self._stderr_tail.append(normalized)

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _stderr_text(self) -> str:
        return " | ".join(self._stderr_tail)

    def _send_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._process is None or self._process.stdin is None:
            raise MCPProtocolError("MCP stdio process is not running.")

        request_id = self._next_id()
        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }
        try:
            self._process.stdin.write(json.dumps(message, ensure_ascii=True) + "\n")
            self._process.stdin.flush()
        except OSError as exc:
            raise MCPProtocolError(f"Failed to write MCP request '{method}' to stdio transport: {exc}") from exc
        return self._await_response(request_id, method)

    def _send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        if self._process is None or self._process.stdin is None:
            raise MCPProtocolError("MCP stdio process is not running.")
        message = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        try:
            self._process.stdin.write(json.dumps(message, ensure_ascii=True) + "\n")
            self._process.stdin.flush()
        except OSError as exc:
            raise MCPProtocolError(f"Failed to write MCP notification '{method}' to stdio transport: {exc}") from exc

    def _await_response(self, request_id: int, method: str) -> dict[str, Any]:
        deadline = time.monotonic() + max(1, self._config.timeout_seconds)
        while time.monotonic() < deadline:
            if self._process is not None and self._process.poll() is not None:
                stderr_text = self._stderr_text()
                raise MCPProtocolError(
                    f"MCP stdio server exited while waiting for '{method}'. "
                    f"Exit code: {self._process.returncode}. {stderr_text}".strip()
                )

            remaining = max(0.05, deadline - time.monotonic())
            try:
                payload = self._stdout_queue.get(timeout=remaining)
            except queue.Empty:
                continue

            try:
                decoded = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise MCPProtocolError(f"MCP stdio server returned invalid JSON: {payload}") from exc

            messages = decoded if isinstance(decoded, list) else [decoded]
            for message in messages:
                if not isinstance(message, dict) or message.get("id") != request_id:
                    continue
                if "error" in message:
                    error = message["error"] or {}
                    raise MCPProtocolError(
                        f"MCP request '{method}' failed with code {error.get('code')}: {error.get('message') or 'unknown error'}"
                    )
                result = message.get("result")
                if not isinstance(result, dict):
                    raise MCPProtocolError(f"MCP request '{method}' returned a non-object result.")
                return result

        stderr_text = self._stderr_text()
        raise MCPTimeoutError(
            f"MCP request '{method}' timed out after {self._config.timeout_seconds} seconds. {stderr_text}".strip()
        )


class _HttpMcpSession(_BaseMcpSession):
    def __init__(self, config: MCPServerConfig):
        super().__init__(config)
        self._session = requests.Session()
        self._session_id = ""
        self._legacy_sse: _LegacySseChannel | None = None

    def open(self) -> None:
        if not self._config.url:
            raise MCPConfigurationError("MCP is enabled for HTTP transport but MCP_SERVER_URL is empty.")

    def close(self) -> None:
        if self._legacy_sse is not None:
            self._legacy_sse.close()
            self._legacy_sse = None
        self._session.close()

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": self._protocol_version,
        }
        if self._session_id:
            headers["MCP-Session-Id"] = self._session_id
        return headers

    def _post_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        try:
            response = self._session.post(
                self._config.url,
                json=message,
                headers=self._headers(),
                timeout=self._config.timeout_seconds,
            )
            response.raise_for_status()
        except requests.exceptions.ReadTimeout as exc:
            raise MCPTimeoutError(
                f"MCP HTTP request timed out after {self._config.timeout_seconds} seconds."
            ) from exc
        except requests.exceptions.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else 0
            raise MCPHttpStatusError(
                f"MCP HTTP request failed with HTTP {status_code}.",
                status_code,
            ) from exc
        except requests.RequestException as exc:
            raise MCPProtocolError(f"MCP HTTP request failed: {exc}") from exc

        self._session_id = response.headers.get("MCP-Session-Id") or response.headers.get("Mcp-Session-Id") or self._session_id
        content_type = (response.headers.get("Content-Type") or "").lower()
        if "text/event-stream" in content_type:
            raise MCPProtocolError("Streamable HTTP SSE responses are not supported by this client yet.")
        if not response.content:
            return None
        try:
            payload = response.json()
        except ValueError as exc:
            raise MCPProtocolError(f"MCP HTTP server returned invalid JSON with content-type '{content_type}'.") from exc

        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict) and "id" in item:
                    return item
            return None
        if isinstance(payload, dict):
            return payload
        raise MCPProtocolError("MCP HTTP server returned a non-object JSON payload.")

    def _send_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request_id = self._next_id()
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }
        try:
            message = self._post_message(payload)
        except MCPHttpStatusError as exc:
            if self._should_try_legacy_sse(exc.status_code, method):
                return self._legacy_send_request(request_id, method, payload)
            raise
        if message is None:
            if self._looks_like_legacy_sse_url():
                return self._legacy_send_request(request_id, method, payload)
            raise MCPProtocolError(f"MCP HTTP server returned no response body for '{method}'.")
        if message.get("id") != request_id:
            raise MCPProtocolError(f"MCP HTTP server returned a mismatched response id for '{method}'.")
        if "error" in message:
            error = message["error"] or {}
            raise MCPProtocolError(
                f"MCP HTTP request '{method}' failed with code {error.get('code')}: {error.get('message') or 'unknown error'}"
            )
        result = message.get("result")
        if not isinstance(result, dict):
            raise MCPProtocolError(f"MCP HTTP request '{method}' returned a non-object result.")
        return result

    def _send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        try:
            self._post_message(payload)
        except MCPHttpStatusError as exc:
            if self._should_try_legacy_sse(exc.status_code, method):
                self._ensure_legacy_sse().send_notification(payload)
                return
            raise

    def _should_try_legacy_sse(self, status_code: int, method: str) -> bool:
        return status_code in {400, 404, 405, 406} and (self._looks_like_legacy_sse_url() or method == "initialize")

    def _looks_like_legacy_sse_url(self) -> bool:
        return self._config.url.rstrip("/").endswith("/sse") or "127.0.0.1:9876" in self._config.url

    def _ensure_legacy_sse(self) -> "_LegacySseChannel":
        if self._legacy_sse is None:
            self._legacy_sse = _LegacySseChannel(self._session, self._config)
            self._legacy_sse.open()
        return self._legacy_sse

    def _legacy_send_request(self, request_id: int, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        message = self._ensure_legacy_sse().send_request(payload, request_id, method)
        if "error" in message:
            error = message["error"] or {}
            raise MCPProtocolError(
                f"MCP HTTP request '{method}' failed with code {error.get('code')}: {error.get('message') or 'unknown error'}"
            )
        result = message.get("result")
        if not isinstance(result, dict):
            raise MCPProtocolError(f"MCP legacy SSE request '{method}' returned a non-object result.")
        return result


class _LegacySseChannel:
    def __init__(self, session: requests.Session, config: MCPServerConfig):
        self._session = session
        self._config = config
        self._response: requests.Response | None = None
        self._message_url = ""
        self._messages: queue.Queue[dict[str, Any]] = queue.Queue()
        self._endpoint_ready = threading.Event()
        self._reader_thread: threading.Thread | None = None
        self._closed = False
        self._last_error: str = ""

    def open(self) -> None:
        try:
            self._response = self._session.get(
                self._config.url,
                headers={"Accept": "text/event-stream"},
                stream=True,
                timeout=self._config.timeout_seconds,
            )
            self._response.raise_for_status()
        except requests.RequestException as exc:
            raise MCPProtocolError(f"MCP SSE connection failed: {exc}") from exc

        self._reader_thread = threading.Thread(
            target=self._read_stream,
            name="mcp-http-sse-reader",
            daemon=True,
        )
        self._reader_thread.start()
        if not self._endpoint_ready.wait(timeout=max(1, self._config.timeout_seconds)):
            raise MCPTimeoutError("Timed out waiting for the MCP SSE endpoint announcement.")
        if not self._message_url:
            raise MCPProtocolError("The MCP SSE server did not announce a message endpoint.")

    def close(self) -> None:
        self._closed = True
        if self._response is not None:
            self._response.close()
            self._response = None

    def send_request(self, payload: dict[str, Any], request_id: int, method: str) -> dict[str, Any]:
        self._post(payload)
        deadline = time.monotonic() + max(1, self._config.timeout_seconds)
        while time.monotonic() < deadline:
            try:
                message = self._messages.get(timeout=max(0.05, deadline - time.monotonic()))
            except queue.Empty:
                if self._last_error:
                    raise MCPProtocolError(f"MCP SSE stream failed while waiting for '{method}': {self._last_error}")
                continue
            if message.get("id") != request_id:
                continue
            return message
        raise MCPTimeoutError(f"MCP SSE request '{method}' timed out after {self._config.timeout_seconds} seconds.")

    def send_notification(self, payload: dict[str, Any]) -> None:
        self._post(payload)

    def _post(self, payload: dict[str, Any]) -> None:
        try:
            response = self._session.post(
                self._message_url,
                json=payload,
                headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
                timeout=self._config.timeout_seconds,
            )
            response.raise_for_status()
            if response.content:
                try:
                    body = response.json()
                except ValueError:
                    body = None
                if isinstance(body, dict) and "id" in body:
                    self._messages.put(body)
        except requests.RequestException as exc:
            raise MCPProtocolError(f"MCP SSE request post failed: {exc}") from exc

    def _read_stream(self) -> None:
        if self._response is None:
            return
        event_name = "message"
        data_lines: list[str] = []
        try:
            for raw_line in self._response.iter_lines(decode_unicode=True):
                if self._closed:
                    return
                line = (raw_line or "").strip("\r")
                if line == "":
                    self._handle_event(event_name, data_lines)
                    event_name = "message"
                    data_lines = []
                    continue
                if line.startswith("event:"):
                    event_name = line[6:].strip() or "message"
                    continue
                if line.startswith("data:"):
                    data_lines.append(line[5:].lstrip())
        except requests.RequestException as exc:
            self._last_error = str(exc)

    def _handle_event(self, event_name: str, data_lines: list[str]) -> None:
        data = "\n".join(data_lines).strip()
        if not data:
            return
        if event_name == "endpoint":
            self._message_url = urljoin(self._config.url, data)
            self._endpoint_ready.set()
            return
        try:
            message = json.loads(data)
        except json.JSONDecodeError:
            return
        if isinstance(message, dict):
            self._messages.put(message)
