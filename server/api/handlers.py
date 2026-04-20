from server.capabilities.burp import burp_payload_contract, normalize_burp_payload_contract
from server.capabilities.burp_export_adapter import prepare_burp_export_payload
from server.core.analysis_service import analyze_advisory
from server.core.report_service import build_structured_report


def analyze_payload(payload_like) -> dict:
    return analyze_advisory(payload_like)


def normalize_burp_payload(payload_like) -> dict:
    return normalize_burp_payload_contract(payload_like)


def build_burp_payload_contract() -> dict:
    return burp_payload_contract()


def prepare_burp_export(payload_like) -> dict:
    return prepare_burp_export_payload(payload_like)


def build_structured_report_for_job(job_id: str, payload_like=None, advisory: dict | None = None, run: dict | None = None, snapshot_id: str = "") -> dict:
    return build_structured_report(job_id, payload_like=payload_like, advisory=advisory, run=run, snapshot_id=snapshot_id)
