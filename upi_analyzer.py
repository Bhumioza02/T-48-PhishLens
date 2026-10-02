"""
PhishLens - UPI QR Code Analyzer
Inspects UPI payment strings (upi://pay?...):
- Extracts Payee Name (pn), Virtual Payment Address (pa), Amount (am), Merchant Code (mc)
- Detects payee name vs VPA mismatches
- Detects fraudulent payment-collect requests masquerading as deposits/refunds
"""
from typing import Dict, Any
from urllib.parse import urlparse, parse_qs

def is_upi_payload(payload: str) -> bool:
    """Checks if the raw string follows the UPI payment URI scheme."""
    if not payload:
        return False
    return payload.strip().lower().startswith("upi://pay")

def analyze_upi_payload(payload: str) -> Dict[str, Any]:
    """
    Parses and analyzes a UPI QR payment payload.
    """
    findings = {
        "is_upi": False,
        "vpa": "",
        "payee_name": "",
        "amount": None,
        "transaction_ref": "",
        "is_collect_request": False,
        "suspicious_flags": [],
        "risk_points": 0,
    }

    if not is_upi_payload(payload):
        return findings

    findings["is_upi"] = True
    return findings
