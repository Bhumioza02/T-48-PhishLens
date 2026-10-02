"""
PhishLens - URL Security Analysis Engine
Validates, normalizes, inspects URL structure, detects IP hostnames,
and extracts deterministic security signals without exposing query parameter values.
"""
import re
import ipaddress
from urllib.parse import urlsplit, parse_qs
from typing import Dict, Any, List, Optional, Tuple

# Suspicious keywords frequently used in phishing, credential harvesting, and scam URLs
SUSPICIOUS_KEYWORDS = (
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "kyc",
    "password",
    "wallet",
    "bank",
    "payment",
    "refund",
    "reward",
    "claim",
)

# Open redirect query parameters commonly exploited
REDIRECT_PARAMS = (
    "redirect",
    "redirect_to",
    "url",
    "dest",
    "destination",
    "return",
    "return_to",
    "next",
    "target",
    "r",
    "u",
)

# Potentially risky direct executable / script extensions
SUSPICIOUS_EXTENSIONS = (
    ".exe",
    ".apk",
    ".scr",
    ".bat",
    ".cmd",
    ".vbs",
    ".ps1",
    ".zip",
    ".rar",
    ".iso",
    ".dmg",
)

# Common multi-part top-level domains for basic registrable domain extraction
COMMON_SECOND_LEVEL_DOMAINS = {
    "co.in", "gov.in", "nic.in", "ac.in", "edu.in", "net.in", "org.in",
    "co.uk", "gov.uk", "ac.uk", "org.uk",
    "com.au", "gov.au", "edu.au",
    "com.br", "gov.br",
    "co.jp", "ne.jp",
}


def normalize_url_and_hostname(raw_url: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Safely cleans and normalizes URL and hostname.
    Handles:
    - Trimming whitespace
    - Prepending http:// if scheme is missing for parsing
    - Lowercasing hostname
    - Removing trailing dot from hostname
    - Handling punycode / IDN domains
    Returns: (normalized_url_for_parsing, normalized_hostname, error_message)
    """
    if not raw_url or not raw_url.strip():
        return None, None, "URL input is empty."

    cleaned_url = raw_url.strip()

    # Check if URL starts with an explicit scheme (e.g. 'http:', 'https:', 'javascript:', 'file:')
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", cleaned_url)
    if scheme_match:
        scheme_found = scheme_match.group(1).lower()
        if scheme_found not in ("http", "https"):
            return None, None, f"Unsupported protocol '{scheme_found}://'. PhishLens analyzes web links (HTTP/HTTPS)."
        url_to_parse = cleaned_url
        inferred_scheme = False
    elif cleaned_url.startswith("//"):
        url_to_parse = "https:" + cleaned_url
        inferred_scheme = True
    else:
        # Missing scheme: default to https://
        url_to_parse = "https://" + cleaned_url
        inferred_scheme = True

    try:
        split_result = urlsplit(url_to_parse)
    except Exception as e:
        return None, None, f"Malformed URL structure: {str(e)}"

    # Check scheme first before accessing hostname/port
    scheme = split_result.scheme.lower()
    if not inferred_scheme and scheme not in ("http", "https"):
        return None, None, f"Unsupported protocol '{scheme}://'. PhishLens analyzes web links (HTTP/HTTPS)."

    try:
        raw_host = split_result.hostname
    except Exception as e:
        return None, None, f"Invalid URL authority structure: {str(e)}"

    if not raw_host:
        return None, None, "Invalid URL: Unable to identify destination hostname."

    # Normalize hostname: lowercase & strip trailing dot
    norm_host = raw_host.lower().rstrip(".")

    # Punycode / IDN normalization
    try:
        # Check if already punycode (starts with xn--) or convert unicode to ascii
        punycode_host = norm_host.encode("idna").decode("ascii")
        norm_host = punycode_host
    except Exception:
        # Keep original if standard idna conversion fails
        pass

    return url_to_parse, norm_host, None


def extract_registrable_domain(hostname: str) -> str:
    """
    Extracts the base registrable domain from a hostname.
    E.g., 'sub.example.co.in' -> 'example.co.in'
          'login.verify.sbi.com' -> 'sbi.com'
    """
    if not hostname:
        return ""
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname

    # Check for known 2-level TLDs (e.g., co.in, gov.uk)
    suffix_candidate = f"{parts[-2]}.{parts[-1]}"
    if suffix_candidate in COMMON_SECOND_LEVEL_DOMAINS and len(parts) >= 3:
        return f"{parts[-3]}.{suffix_candidate}"

    return f"{parts[-2]}.{parts[-1]}"


def detect_ip_address(hostname: str) -> Tuple[bool, Optional[str]]:
    """
    Detects whether the hostname is an IPv4 or IPv6 address.
    Returns: (is_ip, ip_version_string)
    """
    if not hostname:
        return False, None

    # Strip IPv6 enclosing brackets if present
    clean_host = hostname.strip("[]")

    try:
        ip_obj = ipaddress.ip_address(clean_host)
        version = f"IPv{ip_obj.version}"
        return True, version
    except ValueError:
        return False, None


def extract_safe_query_parameters(query_string: str) -> Tuple[int, List[str]]:
    """
    Extracts query parameter NAMES only for privacy.
    Values are NEVER extracted or stored.
    """
    if not query_string:
        return 0, []

    try:
        parsed_qs = parse_qs(query_string, keep_blank_values=True)
        param_names = sorted(list(parsed_qs.keys()))
        return len(param_names), param_names
    except Exception:
        return 0, []


def inspect_security_signals(
    original_url: str,
    scheme: str,
    hostname: str,
    path: str,
    query_string: str,
    param_names: List[str],
    port: Optional[int],
    is_ip: bool,
    ip_version: Optional[str],
) -> List[Dict[str, str]]:
    """
    Analyzes URL attributes and generates structured security signals.
    Each signal has: name, severity ('low' | 'medium' | 'high'), description.
    """
    signals = []

    # 1. Insecure Protocol (HTTP instead of HTTPS)
    if scheme == "http":
        signals.append({
            "name": "Insecure HTTP Protocol",
            "severity": "medium",
            "description": "The website uses plain unencrypted HTTP instead of secure HTTPS, exposing traffic to interception."
        })

    # 2. Hostname is a Raw IP Address
    if is_ip:
        signals.append({
            "name": f"Raw {ip_version or 'IP'} Address Hostname",
            "severity": "medium",
            "description": f"The URL points directly to an IP address ({hostname}) rather than a registered domain name."
        })

    # 3. @ Symbol in Authority
    if "@" in original_url:
        signals.append({
            "name": "Embedded '@' Symbol in URL",
            "severity": "high",
            "description": "The URL contains an '@' symbol. Browsers treat text before '@' as user credentials, often tricking victims regarding the true host."
        })

    # 4. Unusually Long URL (> 75 characters)
    if len(original_url) > 75:
        signals.append({
            "name": "Unusually Long URL",
            "severity": "low",
            "description": f"The URL is {len(original_url)} characters long. Excessive length is often used to conceal malicious subdomains or tokens."
        })

    # 5. Unusually Long Hostname (> 30 characters)
    if len(hostname) > 30:
        signals.append({
            "name": "Unusually Long Hostname",
            "severity": "low",
            "description": f"The hostname is {len(hostname)} characters long, which is abnormal for reputable web portals."
        })

    # 6. Excessive Subdomains (more than 3 dot-separated labels)
    subdomain_parts = hostname.split(".")
    if len(subdomain_parts) > 3 and not is_ip:
        signals.append({
            "name": "Excessive Subdomains",
            "severity": "medium",
            "description": f"The hostname has {len(subdomain_parts)} domain levels. Cybercriminals frequently chain subdomains to impersonate legitimate brands."
        })

    # 7. Suspicious Percent Encoding
    percent_count = original_url.count("%")
    if percent_count >= 3 or "%20" in original_url.lower() or "%2f" in original_url.lower():
        signals.append({
            "name": "Suspicious Character Percent-Encoding",
            "severity": "low",
            "description": f"Detected {percent_count} percent-encoded tokens in the URL, a technique frequently used to bypass simple text filters."
        })

    # 8. Non-Standard Port
    if port is not None and port not in (80, 443):
        signals.append({
            "name": f"Non-Standard Port ({port})",
            "severity": "medium",
            "description": f"The URL specifies custom port :{port}, which is uncommon for standard consumer services."
        })

    # 9. Multiple Slashes in Path (e.g., //login)
    if "//" in path:
        signals.append({
            "name": "Consecutive Slashes in Path",
            "severity": "low",
            "description": "Path contains consecutive slashes ('//'), which can be used to bypass path validation or trigger open redirects."
        })

    # 10. Multiple Hyphens in Domain
    hyphen_count = hostname.count("-")
    if hyphen_count >= 2:
        signals.append({
            "name": "Multiple Hyphens in Hostname",
            "severity": "low",
            "description": f"The hostname contains {hyphen_count} hyphens, a common pattern in typosquatting and fake brand registrations."
        })

    # 11. Direct Executable / Dangerous File Extension
    path_lower = path.lower()
    for ext in SUSPICIOUS_EXTENSIONS:
        if path_lower.endswith(ext):
            signals.append({
                "name": f"Direct File Download ({ext})",
                "severity": "high",
                "description": f"The URL points directly to an executable or archive file download ({ext}), posing immediate malware delivery risks."
            })
            break

    # 12. Potential Open Redirect Parameter
    found_redirect_params = [p for p in param_names if p.lower() in REDIRECT_PARAMS]
    if found_redirect_params:
        signals.append({
            "name": "Potential Open Redirect Parameter",
            "severity": "medium",
            "description": f"Detected query parameter(s) '{', '.join(found_redirect_params)}' frequently manipulated to route victims to external scam pages."
        })

    # 13. Suspicious Phishing / Verification Keywords
    # Check hostname, path, and parameter names
    search_space = f"{hostname.lower()} {path.lower()} {' '.join(param_names).lower()}"
    found_keywords = []
    for kw in SUSPICIOUS_KEYWORDS:
        # Match whole word or separated by hyphen/slash/dot/underscore
        pattern = rf"(^|[._\-/]){re.escape(kw)}([._\-/]|$)"
        if re.search(pattern, search_space) or kw in hostname.lower():
            if kw not in found_keywords:
                found_keywords.append(kw)

    if found_keywords:
        signals.append({
            "name": "Suspicious Verification / Banking Keyword",
            "severity": "medium",
            "description": f"The URL contains security-sensitive keywords ({', '.join(found_keywords)}) commonly exploited in phishing and KYC scams."
        })

    return signals


def parse_and_analyze_url(user_input_url: str) -> Dict[str, Any]:
    """
    Main entry point for URL inspection.
    Validates, normalizes, extracts metadata, and compiles security signals.
    """
    if not user_input_url or not user_input_url.strip():
        return {
            "status": "error",
            "error_message": "Please enter a valid URL to analyze.",
            "target_type": "URL",
            "original_url": user_input_url or "",
        }

    url_to_parse, norm_host, error_msg = normalize_url_and_hostname(user_input_url)
    if error_msg:
        return {
            "status": "error",
            "error_message": error_msg,
            "target_type": "URL",
            "original_url": user_input_url,
        }

    try:
        split_result = urlsplit(url_to_parse)
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"URL parsing failed: {str(e)}",
            "target_type": "URL",
            "original_url": user_input_url,
        }

    scheme = split_result.scheme.lower() or "http"
    hostname = norm_host
    try:
        port = split_result.port
    except ValueError:
        port = None
    path = split_result.path or "/"
    query_string = split_result.query or ""
    fragment = split_result.fragment or ""

    # Registrable domain and IP detection
    reg_domain = extract_registrable_domain(hostname)
    is_ip, ip_version = detect_ip_address(hostname)

    # Privacy-conscious query parameter extraction (KEYS ONLY, NO VALUES)
    param_count, param_names = extract_safe_query_parameters(query_string)

    # Security signal inspection
    signals = inspect_security_signals(
        original_url=user_input_url.strip(),
        scheme=scheme,
        hostname=hostname,
        path=path,
        query_string=query_string,
        param_names=param_names,
        port=port,
        is_ip=is_ip,
        ip_version=ip_version,
    )

    # Count signal severities
    severities = {"high": 0, "medium": 0, "low": 0}
    for s in signals:
        sev = s.get("severity", "low")
        if sev in severities:
            severities[sev] += 1

    return {
        "status": "success",
        "target_type": "URL",
        "original_url": user_input_url.strip(),
        "url_intelligence": {
            "scheme": scheme.upper(),
            "hostname": split_result.hostname or hostname,
            "normalized_hostname": hostname,
            "registrable_domain": reg_domain,
            "port": port if port else ("443" if scheme == "https" else "80"),
            "path": path,
            "query_param_count": param_count,
            "query_param_names": param_names,
            "fragment": fragment,
            "is_ip": is_ip,
            "ip_version": ip_version,
        },
        "signals": signals,
        "signals_count": {
            **severities,
            "total": len(signals),
        },
    }
