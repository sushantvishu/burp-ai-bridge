import argparse
import importlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import requests


DEFAULT_BASE_URL = "http://127.0.0.1:8000"


def load_env_file(path: str = "") -> str:
    env_path = Path(path or ".env")
    if not env_path.exists():
        return str(env_path)

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key:
            os.environ[key] = value
    return str(env_path)


def effective_settings_snapshot() -> dict[str, Any]:
    settings = importlib.import_module("server.settings")
    profiles = importlib.import_module("server.profiles")
    runtime_models = importlib.import_module("server.core.runtime_model_service").get_runtime_model_options()
    provider_order = list(settings.MODEL_PROVIDER_ORDER)
    return {
        "ollama_url": settings.OLLAMA_URL,
        "ollama_model": runtime_models.get("current_model") or settings.OLLAMA_MODEL,
        "configured_ollama_model": settings.OLLAMA_MODEL,
        "configured_ollama_fast_model": settings.OLLAMA_FAST_MODEL,
        "configured_ollama_deep_model": settings.OLLAMA_DEEP_MODEL,
        "configured_ollama_code_model": settings.OLLAMA_CODE_MODEL,
        "ollama_installed_models": runtime_models.get("detected_model_names") or [],
        "ollama_switch_targets": runtime_models.get("switch_targets") or {},
        "runtime_model_override": runtime_models.get("manual_override") or {},
        "mcp_enabled": settings.MCP_ENABLED,
        "mcp_transport": settings.MCP_TRANSPORT,
        "mcp_tool_name": settings.MCP_TOOL_NAME,
        "burp_mcp_context_enabled": settings.BURP_MCP_CONTEXT_ENABLED,
        "burp_mcp_transport": settings.BURP_MCP_TRANSPORT,
        "burp_mcp_server_url": settings.BURP_MCP_SERVER_URL,
        "burp_mcp_read_only_only": settings.BURP_MCP_READ_ONLY_ONLY,
        "provider_order": provider_order,
        "mcp_primary_context_source": bool(settings.MCP_ENABLED and settings.BURP_MCP_CONTEXT_ENABLED and provider_order and provider_order[0] == "mcp"),
        "privacy_mode": settings.PRIVACY_MODE,
        "persistence_replay_protection_mode": settings.PERSISTENCE_REPLAY_PROTECTION_MODE,
        "history_retention": settings.HISTORY_JSONL_MAX_RECORDS,
        "diagnostics_retention": settings.PROVIDER_DIAGNOSTICS_JSONL_MAX_RECORDS,
        "audit_retention": settings.AUDIT_LOG_JSONL_MAX_RECORDS,
        "default_bounty_platform": settings.DEFAULT_BOUNTY_PLATFORM,
        "browser_verification_requires_explicit_allow": settings.BROWSER_VERIFICATION_REQUIRE_EXPLICIT_ALLOW,
        "observability_requires_local_or_auth": settings.OBSERVABILITY_REQUIRE_LOCAL_OR_AUTH,
        "localhost_allowed": settings.OBSERVABILITY_ALLOW_LOCALHOST,
        "policy_templates": [template["name"] for template in importlib.import_module("server.core.program_policy_service").list_program_policy_templates()],
        "profile_picker_exposed": False,
        "default_runtime_strategy": profiles.DEFAULT_PROFILE,
    }


def build_auth_headers(token: str = "", request_id: str = "") -> dict[str, str]:
    headers: dict[str, str] = {}
    if token:
        headers["X-Bridge-Admin-Token"] = token
    if request_id:
        headers["X-Request-ID"] = request_id
    return headers


def build_observability_path(resource: str, output_format: str) -> str:
    normalized_resource = (resource or "").strip().lower()
    normalized_format = (output_format or "json").strip().lower()
    if normalized_resource == "history":
        if normalized_format == "markdown":
            return "/api/history/recent/export.md"
        if normalized_format == "jsonl":
            return "/api/history/recent/export.jsonl"
        return "/api/history/recent/page"
    if normalized_resource == "diagnostics":
        if normalized_format == "markdown":
            return "/api/runtime/provider-diagnostics/export.md"
        if normalized_format == "jsonl":
            return "/api/runtime/provider-diagnostics/export.jsonl"
        return "/api/runtime/provider-diagnostics"
    if normalized_resource == "audit":
        if normalized_format == "markdown":
            return "/api/audit/events/export.md"
        if normalized_format == "jsonl":
            return "/api/audit/events/export.jsonl"
        return "/api/audit/events"
    raise ValueError(f"Unsupported observability resource: {resource}")


def fetch_observability(
    *,
    base_url: str,
    resource: str,
    output_format: str,
    token: str = "",
    request_id: str = "",
    query: dict[str, Any] | None = None,
    timeout: int = 20,
) -> requests.Response:
    base = (base_url or DEFAULT_BASE_URL).rstrip("/")
    path = build_observability_path(resource, output_format)
    params = {key: value for key, value in (query or {}).items() if value not in {"", None}}
    url = f"{base}{path}"
    if params:
        url += "?" + urlencode(params, doseq=True)
    response = requests.get(url, headers=build_auth_headers(token=token, request_id=request_id), timeout=timeout)
    response.raise_for_status()
    return response


def fetch_submission_report(
    *,
    base_url: str,
    job_id: str,
    platform: str = "",
    snapshot_id: str = "",
    output_format: str = "json",
    token: str = "",
    request_id: str = "",
    timeout: int = 20,
) -> requests.Response:
    base = (base_url or DEFAULT_BASE_URL).rstrip("/")
    path = f"/api/history/jobs/{job_id}/submission-report"
    if (output_format or "json").strip().lower() == "markdown":
        path += ".md"
    params = {}
    if platform:
        params["platform"] = platform
    if snapshot_id:
        params["snapshot_id"] = snapshot_id
    url = f"{base}{path}"
    if params:
        url += "?" + urlencode(params, doseq=True)
    response = requests.get(url, headers=build_auth_headers(token=token, request_id=request_id), timeout=timeout)
    response.raise_for_status()
    return response


def fetch_json_endpoint(
    *,
    base_url: str,
    path: str,
    token: str = "",
    request_id: str = "",
    timeout: int = 20,
) -> requests.Response:
    response = requests.get(
        f"{(base_url or DEFAULT_BASE_URL).rstrip('/')}{path}",
        headers=build_auth_headers(token=token, request_id=request_id),
        timeout=timeout,
    )
    response.raise_for_status()
    return response


def bridge_healthcheck(base_url: str = DEFAULT_BASE_URL, timeout: int = 2) -> dict[str, Any] | None:
    try:
        response = requests.get(f"{(base_url or DEFAULT_BASE_URL).rstrip('/')}/api/runtime/health", timeout=timeout)
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, dict) else None
    except (requests.RequestException, ValueError):
        return None


def port_is_listening(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def listening_pids_for_port(port: int) -> list[int]:
    try:
        completed = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if completed.returncode != 0:
        return []

    pids: list[int] = []
    marker = f":{int(port)}"
    for raw_line in completed.stdout.splitlines():
        line = raw_line.strip()
        if marker not in line or "LISTENING" not in line.upper():
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        local_address = parts[1]
        state = parts[3].upper()
        pid_text = parts[4]
        if state != "LISTENING" or not local_address.endswith(marker):
            continue
        try:
            pid = int(pid_text)
        except ValueError:
            continue
        if pid not in pids:
            pids.append(pid)
    return pids


def stop_process_tree(pid: int, timeout_seconds: int = 10) -> None:
    if pid <= 0:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return
    try:
        os.kill(pid, 15)
    except OSError:
        return


def stop_existing_listener(host: str, port: int, timeout_seconds: int = 10) -> list[int]:
    pids = listening_pids_for_port(port)
    for pid in pids:
        stop_process_tree(pid, timeout_seconds=timeout_seconds)
    deadline = time.time() + max(1, timeout_seconds)
    while time.time() < deadline:
        if not port_is_listening(host, port):
            break
        time.sleep(0.25)
    return pids


def serve(args) -> int:
    load_env_file(args.env_file)
    try:
        import uvicorn
    except ImportError as exc:
        raise SystemExit(f"uvicorn is required to serve the API: {exc}")
    base_url = f"http://{args.host}:{args.port}"
    if os.name == "nt" and args.reload and not args.allow_windows_reload:
        print("Windows reload mode is disabled by default because it tends to leave stale child processes after Ctrl+C. Starting without --reload.")
        args.reload = False

    if port_is_listening(args.host, args.port):
        health = bridge_healthcheck(base_url, timeout=2)
        if args.stop_existing:
            stopped = stop_existing_listener(args.host, args.port)
            if port_is_listening(args.host, args.port):
                raise SystemExit(
                    f"Port {args.port} is still busy after trying to stop PID(s): {stopped or ['<unknown>']}. "
                    "Stop the existing listener manually and try again."
                )
            if stopped:
                print(f"Stopped existing listener PID(s): {', '.join(str(pid) for pid in stopped)}")
        elif health:
            print(
                f"Burp AI Bridge is already running on {base_url}. "
                "Reuse the running server or start with `--stop-existing` if you need a fresh process."
            )
            return 0
        else:
            pids = listening_pids_for_port(args.port)
            raise SystemExit(
                f"Port {args.port} is already in use by PID(s): {pids or ['<unknown>']}. "
                "Use `python -m server stop --port 8000` or start with `--stop-existing`."
            )

    config = uvicorn.Config(
        "server.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
        access_log=args.access_log,
    )
    server = uvicorn.Server(config)
    try:
        server.run()
    except KeyboardInterrupt:
        print("Burp AI Bridge shutdown requested.")
        return 0
    return 0


def stop(args) -> int:
    load_env_file(args.env_file)
    base_url = f"http://{args.host}:{args.port}"
    pids = listening_pids_for_port(args.port)
    if not pids and not port_is_listening(args.host, args.port):
        print(f"No listening process found on {base_url}.")
        return 0

    stopped = stop_existing_listener(args.host, args.port, timeout_seconds=args.timeout)
    if port_is_listening(args.host, args.port):
        raise SystemExit(
            f"Failed to stop the listener on {base_url}. "
            f"Remaining PID(s): {listening_pids_for_port(args.port) or stopped or ['<unknown>']}."
        )
    print(f"Stopped listener on {base_url}. PID(s): {stopped or pids or ['<unknown>']}")
    return 0


def doctor(args) -> int:
    load_env_file(args.env_file)
    snapshot = effective_settings_snapshot()
    if args.output == "json":
        print(json.dumps(snapshot, indent=2))
    else:
        print("Burp AI Bridge configuration")
        for key, value in snapshot.items():
            print(f"- {key}: {value}")
    return 0


def observe(args) -> int:
    load_env_file(args.env_file)
    query = {
        "limit": args.limit,
        "cursor": getattr(args, "cursor", 0),
        "request_id": args.filter_request_id,
        "status": getattr(args, "status", ""),
        "provider": getattr(args, "provider", ""),
        "final_status": getattr(args, "final_status", ""),
        "job_id": getattr(args, "job_id", ""),
        "event_type": getattr(args, "event_type", ""),
    }
    response = fetch_observability(
        base_url=args.base_url,
        resource=args.resource,
        output_format=args.output,
        token=args.token,
        request_id=args.request_id,
        query=query,
        timeout=args.timeout,
    )
    print(response.text if args.output in {"markdown", "jsonl"} else json.dumps(response.json(), indent=2))
    return 0


def policy(args) -> int:
    load_env_file(args.env_file)
    policy_service = importlib.import_module("server.core.program_policy_service")
    if args.template_name:
        template = policy_service.get_program_policy_template(args.template_name)
        if args.output == "json":
            print(json.dumps(template, indent=2))
        else:
            print(f"{template['name']} ({template['platform']})")
            print(template["summary"])
            for key in ("scope_prompts", "rate_limit_guidance", "safe_testing_notes", "browser_verification_rules", "out_of_scope_risks", "report_expectations"):
                values = template.get(key) or []
                if not values:
                    continue
                print(f"- {key}:")
                for item in values:
                    print(f"  - {item}")
        return 0

    templates = policy_service.list_program_policy_templates()
    if args.output == "json":
        print(json.dumps(templates, indent=2))
    else:
        for template in templates:
            print(f"- {template['name']}: {template['summary']}")
    return 0


def report(args) -> int:
    load_env_file(args.env_file)
    response = fetch_submission_report(
        base_url=args.base_url,
        job_id=args.job_id,
        platform=args.platform,
        snapshot_id=args.snapshot_id,
        output_format=args.output,
        token=args.token,
        request_id=args.request_id,
        timeout=args.timeout,
    )
    print(response.text if args.output == "markdown" else json.dumps(response.json(), indent=2))
    return 0


def review(args) -> int:
    load_env_file(args.env_file)
    params = {}
    if args.platform:
        params["platform"] = args.platform
    if args.snapshot_id:
        params["snapshot_id"] = args.snapshot_id
    path = f"/api/history/jobs/{args.job_id}/operator-review"
    if params:
        path += "?" + urlencode(params, doseq=True)
    response = fetch_json_endpoint(
        base_url=args.base_url,
        path=path,
        token=args.token,
        request_id=args.request_id,
        timeout=args.timeout,
    )
    print(json.dumps(response.json(), indent=2))
    return 0


def benchmark(args) -> int:
    load_env_file(args.env_file)
    path = f"/api/runtime/benchmark?limit={max(1, args.limit)}"
    response = fetch_json_endpoint(
        base_url=args.base_url,
        path=path,
        token=args.token,
        request_id=args.request_id,
        timeout=args.timeout,
    )
    print(json.dumps(response.json(), indent=2))
    return 0


def bundle(args) -> int:
    load_env_file(args.env_file)
    params = {}
    if args.platform:
        params["platform"] = args.platform
    if args.snapshot_id:
        params["snapshot_id"] = args.snapshot_id
    path = f"/api/history/jobs/{args.job_id}/evidence-bundle"
    if args.output == "markdown":
        path += ".md"
    if params:
        path += "?" + urlencode(params, doseq=True)
    response = fetch_json_endpoint(
        base_url=args.base_url,
        path=path,
        token=args.token,
        request_id=args.request_id,
        timeout=args.timeout,
    )
    print(response.text if args.output == "markdown" else json.dumps(response.json(), indent=2))
    return 0


def review_import(args) -> int:
    load_env_file(args.env_file)
    importer = importlib.import_module("server.submission_regression")
    result = importer.import_submission_regressions_into_review_dataset(
        vuln_class=args.vuln_class,
        outcome=args.outcome,
        platform=args.platform,
        limit=args.limit,
    )
    if args.output == "json":
        print(json.dumps(result, indent=2))
    else:
        print(result.get("summary", "Import completed."))
    return 0


def asset_feedback(args) -> int:
    load_env_file(args.env_file)
    feedback_module = importlib.import_module("server.burp_asset_feedback")
    result = feedback_module.append_asset_feedback(
        asset_type=args.asset_type,
        asset_id=args.asset_id,
        label=args.label,
        target_url=args.target_url,
        vuln_class=args.vuln_class,
        selected_profile=args.selected_profile,
        program_platform=args.program_platform,
        program_policy_template=args.program_policy_template,
        notes=args.notes,
        job_id=args.job_id,
        request_id=args.request_id,
    )
    if args.output == "json":
        print(json.dumps(result, indent=2))
    else:
        print(
            f"Recorded {result.get('label')} feedback for "
            f"{result.get('asset_type')}:{result.get('asset_id')} "
            f"on {result.get('memory_partition_key') or 'global'}."
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="burp-bridge", description="Operator CLI for Burp AI Bridge.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser("serve", help="Run the FastAPI server with optional env-file loading.")
    serve_parser.add_argument("--env-file", default=".env", help="Path to an env file loaded before startup.")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--reload", action="store_true")
    serve_parser.add_argument("--allow-windows-reload", action="store_true", help="Allow uvicorn reload mode on Windows even though it is less stable with Ctrl+C.")
    serve_parser.add_argument("--stop-existing", action="store_true", help="Stop an existing listener on the same host/port before starting.")
    serve_parser.add_argument("--log-level", default="info")
    serve_parser.add_argument("--access-log", action="store_true", help="Enable Uvicorn access logs. Disabled by default to reduce console spam from Burp polling.")
    serve_parser.set_defaults(handler=serve)

    stop_parser = subparsers.add_parser("stop", help="Stop the local Burp AI Bridge listener on the selected host/port.")
    stop_parser.add_argument("--env-file", default=".env")
    stop_parser.add_argument("--host", default="127.0.0.1")
    stop_parser.add_argument("--port", type=int, default=8000)
    stop_parser.add_argument("--timeout", type=int, default=10)
    stop_parser.set_defaults(handler=stop)

    doctor_parser = subparsers.add_parser("doctor", help="Print the effective local configuration snapshot.")
    doctor_parser.add_argument("--env-file", default=".env")
    doctor_parser.add_argument("--output", choices=("text", "json"), default="text")
    doctor_parser.set_defaults(handler=doctor)

    observe_parser = subparsers.add_parser("observe", help="Query observability endpoints from the local server.")
    observe_parser.add_argument("resource", choices=("history", "diagnostics", "audit"))
    observe_parser.add_argument("--env-file", default=".env")
    observe_parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    observe_parser.add_argument("--output", choices=("json", "jsonl", "markdown"), default="json")
    observe_parser.add_argument("--token", default="")
    observe_parser.add_argument("--request-id", default="", help="CLI request ID sent to the server.")
    observe_parser.add_argument("--filter-request-id", default="", help="Filter stored results by request ID.")
    observe_parser.add_argument("--job-id", default="")
    observe_parser.add_argument("--status", default="")
    observe_parser.add_argument("--provider", default="")
    observe_parser.add_argument("--final-status", default="")
    observe_parser.add_argument("--event-type", default="")
    observe_parser.add_argument("--limit", type=int, default=20)
    observe_parser.add_argument("--cursor", type=int, default=0)
    observe_parser.add_argument("--timeout", type=int, default=20)
    observe_parser.set_defaults(handler=observe)

    policy_parser = subparsers.add_parser("policy", help="List or show bug-bounty policy templates.")
    policy_parser.add_argument("template_name", nargs="?", default="")
    policy_parser.add_argument("--env-file", default=".env")
    policy_parser.add_argument("--output", choices=("text", "json"), default="text")
    policy_parser.set_defaults(handler=policy)

    report_parser = subparsers.add_parser("report", help="Fetch a platform-tuned bug bounty submission report for a stored job.")
    report_parser.add_argument("job_id")
    report_parser.add_argument("--env-file", default=".env")
    report_parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    report_parser.add_argument("--platform", default="")
    report_parser.add_argument("--snapshot-id", default="")
    report_parser.add_argument("--output", choices=("json", "markdown"), default="json")
    report_parser.add_argument("--token", default="")
    report_parser.add_argument("--request-id", default="", help="CLI request ID sent to the server.")
    report_parser.add_argument("--timeout", type=int, default=20)
    report_parser.set_defaults(handler=report)

    review_parser = subparsers.add_parser("review", help="Show the compact operator review for one stored finding.")
    review_parser.add_argument("job_id")
    review_parser.add_argument("--env-file", default=".env")
    review_parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    review_parser.add_argument("--platform", default="")
    review_parser.add_argument("--snapshot-id", default="")
    review_parser.add_argument("--token", default="")
    review_parser.add_argument("--request-id", default="", help="CLI request ID sent to the server.")
    review_parser.add_argument("--timeout", type=int, default=20)
    review_parser.set_defaults(handler=review)

    benchmark_parser = subparsers.add_parser("benchmark", help="Show lightweight local runtime benchmark data.")
    benchmark_parser.add_argument("--env-file", default=".env")
    benchmark_parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    benchmark_parser.add_argument("--token", default="")
    benchmark_parser.add_argument("--request-id", default="", help="CLI request ID sent to the server.")
    benchmark_parser.add_argument("--limit", type=int, default=100)
    benchmark_parser.add_argument("--timeout", type=int, default=20)
    benchmark_parser.set_defaults(handler=benchmark)

    bundle_parser = subparsers.add_parser("bundle", help="Export one-click evidence bundle for a stored job.")
    bundle_parser.add_argument("job_id")
    bundle_parser.add_argument("--env-file", default=".env")
    bundle_parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    bundle_parser.add_argument("--platform", default="")
    bundle_parser.add_argument("--snapshot-id", default="")
    bundle_parser.add_argument("--output", choices=("json", "markdown"), default="json")
    bundle_parser.add_argument("--token", default="")
    bundle_parser.add_argument("--request-id", default="", help="CLI request ID sent to the server.")
    bundle_parser.add_argument("--timeout", type=int, default=20)
    bundle_parser.set_defaults(handler=bundle)

    review_import_parser = subparsers.add_parser("review-import", help="Import curated accepted/downgraded submission regressions into the local review dataset.")
    review_import_parser.add_argument("--env-file", default=".env")
    review_import_parser.add_argument("--vuln-class", default="")
    review_import_parser.add_argument("--outcome", default="")
    review_import_parser.add_argument("--platform", default="")
    review_import_parser.add_argument("--limit", type=int, default=100)
    review_import_parser.add_argument("--output", choices=("text", "json"), default="text")
    review_import_parser.set_defaults(handler=review_import)

    asset_feedback_parser = subparsers.add_parser("asset-feedback", help="Record signal or false-positive feedback for a Burp custom check or Bambda pack.")
    asset_feedback_parser.add_argument("--env-file", default=".env")
    asset_feedback_parser.add_argument("--asset-type", required=True, choices=("custom_scan_check", "bambda"))
    asset_feedback_parser.add_argument("--asset-id", required=True)
    asset_feedback_parser.add_argument("--label", required=True)
    asset_feedback_parser.add_argument("--target-url", default="")
    asset_feedback_parser.add_argument("--vuln-class", default="")
    asset_feedback_parser.add_argument("--selected-profile", default="")
    asset_feedback_parser.add_argument("--program-platform", default="")
    asset_feedback_parser.add_argument("--program-policy-template", default="")
    asset_feedback_parser.add_argument("--notes", default="")
    asset_feedback_parser.add_argument("--job-id", default="")
    asset_feedback_parser.add_argument("--request-id", default="")
    asset_feedback_parser.add_argument("--output", choices=("text", "json"), default="text")
    asset_feedback_parser.set_defaults(handler=asset_feedback)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
