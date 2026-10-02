"""
PhishLens - Primary Security Orchestrator
Coordinates URL intelligence and Domain threat analysis (lookalikes, homoglyphs, typosquatting).
"""
from typing import Dict, Any
from privacy import sanitize_url_for_storage
import url_analyzer
import domain_analyzer

def analyze_target(target_input: str, target_type: str = "URL") -> Dict[str, Any]:
    """
    Main entry point for analyzing a URL or QR payload.
    In Step 3, URLs are analyzed through both URL Intelligence and Domain Intelligence.
    """
    target_clean = (target_input or "").strip()

    if target_type == "URL":
        analysis_result = url_analyzer.parse_and_analyze_url(target_clean)
        analysis_result["target_display"] = sanitize_url_for_storage(target_clean)

        if analysis_result.get("status") == "success":
            intel = analysis_result["url_intelligence"]
            hostname = intel.get("normalized_hostname", "")

            # Perform deep Domain Security Intelligence
            domain_result = domain_analyzer.analyze_domain(hostname)
            analysis_result["domain_intelligence"] = domain_result

            # Combine URL signals and Domain signals
            combined_signals = list(analysis_result.get("signals", []))

            # If this is a verified official brand domain, suppress false-positive generic keyword signals
            if domain_result.get("is_official_brand"):
                combined_signals = [
                    s for s in combined_signals
                    if s.get("name") != "Suspicious Verification / Banking Keyword"
                ]

            # Append domain signals (impersonation, typosquatting, homoglyphs, punycode)
            for d_sig in domain_result.get("signals", []):
                combined_signals.append(d_sig)

            analysis_result["signals"] = combined_signals

            # Recalculate signal severity tallies
            severities = {"high": 0, "medium": 0, "low": 0}
            for s in combined_signals:
                sev = s.get("severity", "low").lower()
                if sev in severities:
                    severities[sev] += 1
            severities["total"] = len(combined_signals)
            analysis_result["signals_count"] = severities

        return analysis_result
    else:
        # Placeholder for QR/UPI (Step 4/5)
        return {
            "status": "initializing",
            "message": "QR Analysis engine initializing...",
            "target_type": "QR",
            "target_display": target_clean,
            "url_intelligence": None,
            "domain_intelligence": None,
            "signals": [],
            "signals_count": {"high": 0, "medium": 0, "low": 0, "total": 0},
        }
