"""
PhishLens - Privacy & Data Sanitization Engine
Ensures zero leaks: raw query parameter values are NEVER stored in plain text.
Query parameter values are hashed using SHA-256 before database storage.
"""
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def hash_value(value: str) -> str:
    """Returns a SHA-256 hex digest of the input string."""
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]

def sanitize_url_for_storage(url: str) -> str:
    """
    Sanitizes a URL by replacing sensitive query parameter values with their SHA-256 hash.
    For example:
      https://example.com/login?token=secret123 -> https://example.com/login?token=[sha256:abcd1234...]
    """
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return url
        
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        sanitized_params = []
        
        for key, values in query_dict.items():
            for v in values:
                hashed = hash_value(v)
                sanitized_params.append((key, f"[hashed:{hashed}]"))
                
        new_query = urlencode(sanitized_params)
        sanitized_parsed = parsed._replace(query=new_query)
        return urlunparse(sanitized_parsed)
    except Exception:
        # Fallback safe truncation if parsing fails
        return url.split("?")[0] + "?[query_sanitized]"
