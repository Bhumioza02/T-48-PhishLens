"""
PhishLens - AI / Plain-English Explainer
Generates a simple, non-technical, one-sentence explanation of why a link or QR is Safe, Caution, or Danger.
"""
from typing import Dict, Any, List
from config import VERDICT_SAFE, VERDICT_CAUTION, VERDICT_DANGER

def generate_explanation(verdict: str, flags: List[str], target_type: str = "URL") -> str:
    """
    Generates a crisp, one-sentence plain English explanation for non-technical users.
    Rule-based template used for zero-latency, with optional LLM polish in Step 6.
    """
    if verdict == VERDICT_SAFE:
        return "This destination verified clean with no known impersonation patterns or suspicious structures."
    elif verdict == VERDICT_CAUTION:
        if flags:
            return f"Exercise caution: {flags[0]} Proceed only if you trust the sender."
        return "Exercise caution: This destination displays uncommon characteristics. Verify the sender before continuing."
    else: # DANGER
        if flags:
            return f"High risk detected: {flags[0]} Do not enter credentials or approve payments."
        return "High risk detected: This destination imitates a trusted service or displays strong phishing indicators."
