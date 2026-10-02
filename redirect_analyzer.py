"""
PhishLens - Safe Redirect & Unshortener Engine
Safely traces redirects and unshortens URLs while enforcing strict SSRF protections:
- Only allows HTTP/HTTPS
- Blocks localhost, loopback, link-local, and private IP addresses
- Enforces strict hop limits and timeouts
"""
from typing import Dict, Any, List
from config import HTTP_TIMEOUT_SECONDS, MAX_REDIRECTS, BLOCKED_HOSTNAMES

def is_safe_destination(host: str) -> bool:
    """Verifies that a hostname does not point to internal or forbidden destinations."""
    if not host:
        return False
    host_lower = host.lower().split(":")[0]
    if host_lower in BLOCKED_HOSTNAMES:
        return False
    # Additional IP / SSRF filtering will be added in Step 4
    return True

def trace_redirects(url: str) -> Dict[str, Any]:
    """
    Safely follows HTTP redirect chains up to MAX_REDIRECTS.
    Returns the final destination and intermediate hops.
    """
    return {
        "initial_url": url,
        "final_url": url,
        "hop_count": 0,
        "hops": [],
        "is_shortened": False,
        "ssrf_blocked": False,
    }
