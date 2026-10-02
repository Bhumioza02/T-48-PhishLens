"""
PhishLens - Basic & URL Security Sanity Tests
Verifies module imports, URL parsing, security signal extraction,
privacy guarantees, and error handling for Step 2.
"""
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import config
import privacy
import database
import detector
import url_analyzer


def test_config_constants():
    """Verify configuration settings and verdicts."""
    assert config.APP_NAME == "PHISHLENS"
    assert config.VERDICT_SAFE == "SAFE"
    assert config.VERDICT_DANGER == "DANGER"
    print("[PASS] test_config_constants passed")


def test_privacy_sanitizer():
    """Verify parameter values are hashed and never leaked."""
    raw_url = "https://example.com/login?user=alice&token=supersecret123"
    sanitized = privacy.sanitize_url_for_storage(raw_url)
    assert "supersecret123" not in sanitized
    assert "alice" not in sanitized
    assert "token=" in sanitized
    assert "user=" in sanitized
    print("[PASS] test_privacy_sanitizer passed")


def test_1_normal_https_url():
    """Test 1: Normal HTTPS URL - should succeed with clean structure and no keyword alerts."""
    url = "https://example.com/about"
    result = detector.analyze_target(url, target_type="URL")
    assert result["status"] == "success"
    intel = result["url_intelligence"]
    assert intel["scheme"] == "HTTPS"
    assert intel["normalized_hostname"] == "example.com"
    assert intel["is_ip"] is False
    # Standard example.com/about should not trigger suspicious keyword or protocol signals
    signal_names = [s["name"] for s in result["signals"]]
    assert "Insecure HTTP Protocol" not in signal_names
    assert "Raw IPv4 Address Hostname" not in signal_names
    print("[PASS] test_1_normal_https_url passed")


def test_2_http_url():
    """Test 2: HTTP URL - should detect unencrypted protocol."""
    url = "http://example.com/page"
    result = detector.analyze_target(url, target_type="URL")
    assert result["status"] == "success"
    intel = result["url_intelligence"]
    assert intel["scheme"] == "HTTP"
    signal_names = [s["name"] for s in result["signals"]]
    assert "Insecure HTTP Protocol" in signal_names
    http_sig = next(s for s in result["signals"] if s["name"] == "Insecure HTTP Protocol")
    assert http_sig["severity"] == "medium"
    print("[PASS] test_2_http_url passed")


def test_3_ip_address_url():
    """Test 3: IP address URL - should detect IPv4/IPv6 hostname."""
    url = "http://192.168.1.1/admin"
    result = detector.analyze_target(url, target_type="URL")
    assert result["status"] == "success"
    intel = result["url_intelligence"]
    assert intel["is_ip"] is True
    assert intel["ip_version"] == "IPv4"
    signal_names = [s["name"] for s in result["signals"]]
    assert any("Raw IPv4 Address Hostname" in name for name in signal_names)
    print("[PASS] test_3_ip_address_url passed")


def test_4_suspicious_keyword_url():
    """Test 4: URL with suspicious keyword (kyc, update) - should flag verification keyword."""
    url = "https://example.com/kyc-update"
    result = detector.analyze_target(url, target_type="URL")
    assert result["status"] == "success"
    signal_names = [s["name"] for s in result["signals"]]
    assert "Suspicious Verification / Banking Keyword" in signal_names
    sig = next(s for s in result["signals"] if s["name"] == "Suspicious Verification / Banking Keyword")
    assert "kyc" in sig["description"].lower()
    print("[PASS] test_4_suspicious_keyword_url passed")


def test_5_query_parameters_privacy():
    """Test 5: URL with query parameters - parameter names extracted, values NEVER present."""
    url = "https://example.com/login?user=abc&token=123"
    result = detector.analyze_target(url, target_type="URL")
    assert result["status"] == "success"
    intel = result["url_intelligence"]
    assert intel["query_param_count"] == 2
    assert "user" in intel["query_param_names"]
    assert "token" in intel["query_param_names"]
    # Ensure parameter values 'abc' and '123' are NOT in intel query_param_names
    assert "abc" not in intel["query_param_names"]
    assert "123" not in intel["query_param_names"]
    print("[PASS] test_5_query_parameters_privacy passed")


def test_6_invalid_url():
    """Test 6: Invalid/malformed URL - handles gracefully without crashing."""
    # Test empty
    res_empty = detector.analyze_target("", target_type="URL")
    assert res_empty["status"] == "error"
    assert "error_message" in res_empty

    # Test unsupported protocol
    res_unsupported = detector.analyze_target("javascript:alert(1)", target_type="URL")
    assert res_unsupported["status"] == "error"
    assert "Unsupported protocol" in res_unsupported["error_message"]

    # Test missing hostname
    res_no_host = detector.analyze_target("https://", target_type="URL")
    assert res_no_host["status"] == "error"
    print("[PASS] test_6_invalid_url passed")


def test_7_structural_signals_synthetic():
    """Test 7: Synthetic adversarial URL with @ symbol, excessive subdomains, custom port, and file extension."""
    synthetic_url = "http://legit.com@phish.fake.service.bank.co.in:8080/secure/update.apk?redirect_to=external.site"
    result = detector.analyze_target(synthetic_url, target_type="URL")
    assert result["status"] == "success"
    signals = result["signals"]
    sig_names = [s["name"] for s in signals]
    assert "Insecure HTTP Protocol" in sig_names
    assert "Embedded '@' Symbol in URL" in sig_names
    assert "Excessive Subdomains" in sig_names
    assert "Non-Standard Port (8080)" in sig_names
    assert "Direct File Download (.apk)" in sig_names
    assert "Potential Open Redirect Parameter" in sig_names
    assert "Suspicious Verification / Banking Keyword" in sig_names
    print("[PASS] test_7_structural_signals_synthetic passed")


def test_8_official_brand_match():
    """Test 8: Official domain should match trusted brand and NOT trigger impersonation signals."""
    url = "https://sbi.co.in/portal"
    result = detector.analyze_target(url, target_type="URL")
    assert result["status"] == "success"
    dom = result["domain_intelligence"]
    assert dom["is_official_brand"] is True
    assert "State Bank of India" in dom["official_brand_name"]
    sig_names = [s["name"] for s in result["signals"]]
    assert "Brand impersonation" not in sig_names
    assert "Typosquatting detected" not in sig_names
    print("[PASS] test_8_official_brand_match passed")


def test_9_synthetic_typosquatting():
    """Test 9: Synthetic typo domain paytmm.example should trigger typosquatting targeting Paytm."""
    url = "https://paytmm.example"
    result = detector.analyze_target(url, target_type="URL")
    assert result["status"] == "success"
    dom = result["domain_intelligence"]
    assert dom["is_official_brand"] is False
    sig_names = [s["name"] for s in result["signals"]]
    assert "Typosquatting detected" in sig_names
    typo_sig = next(s for s in result["signals"] if s["name"] == "Typosquatting detected")
    assert typo_sig["severity"] == "high"
    assert "Paytm" in typo_sig["brand"]
    print("[PASS] test_9_synthetic_typosquatting passed")


def test_10_synthetic_brand_impersonation():
    """Test 10: Synthetic lookalike sbi-secure-login.example should trigger brand impersonation."""
    url = "https://sbi-secure-login.example"
    result = detector.analyze_target(url, target_type="URL")
    assert result["status"] == "success"
    sig_names = [s["name"] for s in result["signals"]]
    assert "Brand impersonation" in sig_names
    imp_sig = next(s for s in result["signals"] if s["name"] == "Brand impersonation")
    assert imp_sig["severity"] == "high"
    assert "State Bank of India" in imp_sig["brand"]
    print("[PASS] test_10_synthetic_brand_impersonation passed")


def test_11_subdomain_impersonation():
    """Test 11: Subdomain impersonation sbi-login.attacker.example on untrusted domain."""
    url = "https://sbi-login.attacker.example"
    result = detector.analyze_target(url, target_type="URL")
    assert result["status"] == "success"
    dom = result["domain_intelligence"]
    assert dom["registrable_domain"] == "attacker.example"
    assert dom["subdomain"] == "sbi-login"
    sig_names = [s["name"] for s in result["signals"]]
    assert "Brand impersonation" in sig_names
    imp_sig = next(s for s in result["signals"] if s["name"] == "Brand impersonation")
    assert imp_sig["severity"] == "high"
    print("[PASS] test_11_subdomain_impersonation passed")


def test_12_unicode_homoglyph_detection():
    """Test 12: Unicode confusable homoglyph in domain (Cyrillic \u0430 in paytm)."""
    # Using unicode escape for Cyrillic small letter a (\u0430)
    cyrillic_a = "\u0430"
    url = f"https://p{cyrillic_a}ytm.example"
    result = detector.analyze_target(url, target_type="URL")
    assert result["status"] == "success"
    dom = result["domain_intelligence"]
    assert dom["has_homoglyphs"] is True
    sig_names = [s["name"] for s in result["signals"]]
    assert "Unicode homoglyph detected" in sig_names
    homo_sig = next(s for s in result["signals"] if s["name"] == "Unicode homoglyph detected")
    assert homo_sig["severity"] == "high"
    print("[PASS] test_12_unicode_homoglyph_detection passed")


def test_13_brand_in_path_not_impersonation():
    """Test 13: Brand name in path (example.com/sbi/login) must NOT be flagged as brand impersonation."""
    url = "https://example.com/sbi/login"
    result = detector.analyze_target(url, target_type="URL")
    assert result["status"] == "success"
    dom = result["domain_intelligence"]
    assert dom["registrable_domain"] == "example.com"
    assert dom["impersonated_brand"] is None
    sig_names = [s["name"] for s in result["signals"]]
    assert "Brand impersonation" not in sig_names
    assert "Typosquatting detected" not in sig_names
    print("[PASS] test_13_brand_in_path_not_impersonation passed")


if __name__ == "__main__":
    print("\n--- Running PhishLens Test Suite (Steps 1-3) ---")
    test_config_constants()
    test_privacy_sanitizer()
    test_1_normal_https_url()
    test_2_http_url()
    test_3_ip_address_url()
    test_4_suspicious_keyword_url()
    test_5_query_parameters_privacy()
    test_6_invalid_url()
    test_7_structural_signals_synthetic()
    test_8_official_brand_match()
    test_9_synthetic_typosquatting()
    test_10_synthetic_brand_impersonation()
    test_11_subdomain_impersonation()
    test_12_unicode_homoglyph_detection()
    test_13_brand_in_path_not_impersonation()
    print("--- All 15 tests passed successfully! ---\n")
