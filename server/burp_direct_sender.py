import argparse
import json

import requests


def submit_selected_request(
    *,
    base_url: str,
    raw_request: str,
    raw_response: str = "",
    target_url: str = "",
    http_method: str = "",
    source_tool: str = "repeater",
    timeout: int = 20,
) -> dict:
    payload = {
        "raw_request": raw_request,
        "raw_response": raw_response,
        "target_url": target_url,
        "http_method": http_method,
        "source_tool": source_tool,
        "use_burp_mcp_context": True,
    }
    response = requests.post(
        f"{(base_url or 'http://127.0.0.1:8000').rstrip('/')}/api/burp/submit-job",
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def open_plan_in_repeater(
    *,
    base_url: str,
    raw_request: str,
    raw_response: str = "",
    target_url: str = "",
    http_method: str = "",
    source_tool: str = "scanner",
    timeout: int = 20,
    dispatch: bool = True,
) -> dict:
    payload = {
        "raw_request": raw_request,
        "raw_response": raw_response,
        "target_url": target_url,
        "http_method": http_method,
        "source_tool": source_tool,
        "use_burp_mcp_context": True,
    }
    response = requests.post(
        f"{(base_url or 'http://127.0.0.1:8000').rstrip('/')}/api/burp/open-repeater-plan",
        params={"dispatch": "true" if dispatch else "false"},
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def sync_selected_repeater_tabs(
    *,
    base_url: str,
    raw_request: str,
    baseline_response_text: str = "",
    target_url: str = "",
    http_method: str = "",
    source_tool: str = "repeater",
    timeout: int = 20,
    repeater_variant_observations: list[dict] | None = None,
    include_plan: bool = True,
) -> dict:
    payload = {
        "raw_request": raw_request,
        "baseline_response_text": baseline_response_text,
        "target_url": target_url,
        "http_method": http_method,
        "source_tool": source_tool,
        "use_burp_mcp_context": True,
        "repeater_variant_observations": repeater_variant_observations or [],
    }
    response = requests.post(
        f"{(base_url or 'http://127.0.0.1:8000').rstrip('/')}/api/burp/repeater-sync",
        params={"include_plan": "true" if include_plan else "false"},
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def refresh_panel_state(
    *,
    base_url: str,
    raw_request: str = "",
    target_url: str = "",
    issue_id: str = "",
    snapshot_id: str = "",
    workflow_id: str = "",
    timeout: int = 20,
    include_plan: bool = True,
    include_companion_actions: bool = True,
) -> dict:
    payload = {
        "raw_request": raw_request,
        "target_url": target_url,
        "use_burp_mcp_context": True,
    }
    response = requests.post(
        f"{(base_url or 'http://127.0.0.1:8000').rstrip('/')}/api/burp/panel-state",
        params={
            "issue_id": issue_id,
            "snapshot_id": snapshot_id,
            "workflow_id": workflow_id,
            "include_plan": "true" if include_plan else "false",
            "include_companion_actions": "true" if include_companion_actions else "false",
        },
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="burp-direct-sender", description="Submit one Burp-originated request to Burp AI Bridge.")
    parser.add_argument("--mode", choices=("submit-job", "open-repeater-plan", "repeater-sync", "panel-state"), default="submit-job")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--raw-request", default="")
    parser.add_argument("--raw-response", default="")
    parser.add_argument("--baseline-response-text", default="")
    parser.add_argument("--target-url", default="")
    parser.add_argument("--http-method", default="")
    parser.add_argument("--source-tool", default="repeater")
    parser.add_argument("--issue-id", default="")
    parser.add_argument("--snapshot-id", default="")
    parser.add_argument("--workflow-id", default="")
    parser.add_argument("--repeater-variant-observations-json", default="[]")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--dispatch", action="store_true", default=False)
    parser.add_argument("--include-plan", action="store_true", default=False)
    parser.add_argument("--include-companion-actions", action="store_true", default=False)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.mode != "panel-state" and not args.raw_request:
        raise SystemExit("--raw-request is required for this mode.")
    if args.mode == "open-repeater-plan":
        result = open_plan_in_repeater(
            base_url=args.base_url,
            raw_request=args.raw_request,
            raw_response=args.raw_response,
            target_url=args.target_url,
            http_method=args.http_method,
            source_tool=args.source_tool,
            timeout=args.timeout,
            dispatch=args.dispatch,
        )
    elif args.mode == "repeater-sync":
        observations = json.loads(args.repeater_variant_observations_json or "[]")
        result = sync_selected_repeater_tabs(
            base_url=args.base_url,
            raw_request=args.raw_request,
            baseline_response_text=args.baseline_response_text,
            target_url=args.target_url,
            http_method=args.http_method,
            source_tool=args.source_tool,
            timeout=args.timeout,
            repeater_variant_observations=observations if isinstance(observations, list) else [],
            include_plan=args.include_plan,
        )
    elif args.mode == "panel-state":
        result = refresh_panel_state(
            base_url=args.base_url,
            raw_request=args.raw_request,
            target_url=args.target_url,
            issue_id=args.issue_id,
            snapshot_id=args.snapshot_id,
            workflow_id=args.workflow_id,
            timeout=args.timeout,
            include_plan=args.include_plan,
            include_companion_actions=args.include_companion_actions,
        )
    else:
        result = submit_selected_request(
            base_url=args.base_url,
            raw_request=args.raw_request,
            raw_response=args.raw_response,
            target_url=args.target_url,
            http_method=args.http_method,
            source_tool=args.source_tool,
            timeout=args.timeout,
        )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
