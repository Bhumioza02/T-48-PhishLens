"""
PhishLens - Domain & Brand Lookalike Analyzer
Identifies:
- Registrable domain, subdomain, and TLD breakdown
- Verified official domains of protected brands
- Brand impersonation (lookalikes, combosquatting, unauthorized subdomains)
- Typosquatting (omission, duplication, transposition, substitution, visual leetspeak)
- Unicode homoglyph attacks (Cyrillic, Greek, mixed-script confusables)
- Punycode IDN (xn--) domains
"""
import re
import json
import idna
from difflib import SequenceMatcher
from typing import Dict, Any, List, Optional, Tuple
from config import (
    TRUSTED_BRANDS_PATH,
    TYPOSQUAT_SIMILARITY_THRESHOLD,
    MAX_LEVENSHTEIN_DISTANCE,
    MIN_BRAND_LENGTH_FOR_FUZZY,
)

# Common multi-part top-level domains for precise registrable domain extraction
KNOWN_MULTI_PART_TLDS = {
    "co.in", "gov.in", "nic.in", "ac.in", "edu.in", "net.in", "org.in", "res.in",
    "co.uk", "gov.uk", "ac.uk", "org.uk", "net.uk",
    "com.au", "gov.au", "edu.au", "org.au",
    "com.br", "gov.br", "org.br",
    "co.jp", "ne.jp", "or.jp",
    "co.nz", "govt.nz",
}

# Unicode confusable character map (Cyrillic, Greek, and Fullwidth to Latin equivalent)
CONFUSABLE_MAP = {
    # Cyrillic lowercase to Latin
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "ѕ": "s", "і": "i", "ј": "j",
    "у": "y", "х": "x", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ո": "n", "һ": "h",
    # Cyrillic uppercase to Latin
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J", "К": "K",
    "М": "M", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X",
    # Greek to Latin
    "ο": "o", "ν": "v", "α": "a", "ρ": "p", "τ": "t", "ι": "i", "κ": "k",
    # Common fullwidth/special confusables
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4", "５": "5", "６": "6",
    "７": "7", "８": "8", "９": "9",
}

# Visual ASCII Leetspeak mappings
LEET_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "8": "b",
    "@": "a",
    "$": "s",
}


def load_trusted_brands() -> List[Dict[str, Any]]:
    """Loads trusted brand registry from JSON."""
    try:
        if TRUSTED_BRANDS_PATH.exists():
            with open(TRUSTED_BRANDS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("brands", [])
    except Exception:
        pass
    return []


def split_domain_components(hostname: str) -> Tuple[str, str, str, str]:
    """
    Deconstructs a hostname into (subdomain, registrable_domain, tld, domain_name_part).
    Example:
      'sbi-login.attacker.example' -> ('sbi-login', 'attacker.example', 'example', 'attacker')
      'netbanking.hdfcbank.com'   -> ('netbanking', 'hdfcbank.com', 'com', 'hdfcbank')
      'onlinesbi.sbi.co.in'        -> ('onlinesbi', 'sbi.co.in', 'co.in', 'sbi')
    """
    if not hostname:
        return "", "", "", ""

    clean_host = hostname.lower().rstrip(".")
    labels = clean_host.split(".")

    if len(labels) == 1:
        return "", clean_host, "", clean_host

    # Check for known 2-part TLDs (e.g. co.in, gov.in)
    if len(labels) >= 3:
        two_part_candidate = f"{labels[-2]}.{labels[-1]}"
        if two_part_candidate in KNOWN_MULTI_PART_TLDS:
            tld = two_part_candidate
            domain_name_part = labels[-3]
            registrable_domain = f"{domain_name_part}.{tld}"
            subdomain = ".".join(labels[:-3])
            return subdomain, registrable_domain, tld, domain_name_part

    # Standard single-part TLD (e.g. .com, .org, .example, .sbi)
    tld = labels[-1]
    domain_name_part = labels[-2]
    registrable_domain = f"{domain_name_part}.{tld}"
    subdomain = ".".join(labels[:-2])
    return subdomain, registrable_domain, tld, domain_name_part


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_unicode_homoglyphs(domain_str: str) -> Tuple[bool, str, List[Dict[str, str]]]:
    """
    Detects if a domain contains Unicode characters that visually imitate Latin characters.
    Returns: (has_homoglyphs, canonical_latin_domain, details_list)
    """
    has_homoglyphs = False
    details = []
    canonical_chars = []

    for char in domain_str:
        if char in CONFUSABLE_MAP:
            has_homoglyphs = True
            canonical_char = CONFUSABLE_MAP[char]
            details.append({
                "char": char,
                "unicode_point": f"U+{ord(char):04X}",
                "resembles": canonical_char,
            })
            canonical_chars.append(canonical_char)
        else:
            canonical_chars.append(char)

    return has_homoglyphs, "".join(canonical_chars), details


def decode_punycode_safely(hostname: str) -> Tuple[bool, str]:
    """
    Checks for punycode ('xn--') in the hostname and decodes it to Unicode.
    Returns: (is_punycode, decoded_representation)
    """
    if "xn--" in hostname.lower():
        try:
            decoded = idna.decode(hostname.encode("ascii"))
            return True, decoded
        except Exception:
            return True, hostname
    return False, hostname


def is_official_brand_domain(hostname: str, brand_entry: Dict[str, Any]) -> bool:
    """
    Checks if the hostname or its registrable domain matches an official domain of the brand.
    Example:
      'sbi.co.in' or 'netbanking.sbi.co.in' matches official domain 'sbi.co.in'.
    """
    official_domains = [d.lower().strip() for d in brand_entry.get("official_domains", [])]
    clean_host = hostname.lower().rstrip(".")

    for off_d in official_domains:
        if clean_host == off_d or clean_host.endswith(f".{off_d}"):
            return True
    return False


def normalize_leetspeak(s: str) -> str:
    """Replaces common leetspeak substitutions with Latin equivalents (e.g. payt1m -> paytlm/paytim)."""
    res = []
    for c in s.lower():
        res.append(LEET_MAP.get(c, c))
    return "".join(res)


def analyze_brand_impersonation_and_typos(
    hostname: str,
    subdomain: str,
    registrable_domain: str,
    domain_name_part: str,
    canonical_name_part: str,
    brands: List[Dict[str, Any]],
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Evaluates domain and subdomain against the trusted brand registry.
    Returns: (official_brand_match, lookalike_match, signals)
    """
    signals = []

    # 1. First, check if this is a verified official brand domain
    for brand in brands:
        if is_official_brand_domain(hostname, brand):
            return brand, None, []

    # 2. Check for Brand Impersonation (Combosquatting / Lookalikes)
    # Check if a protected brand name/alias appears in the registrable domain or subdomain
    # while NOT being an official domain of that brand.
    for brand in brands:
        aliases = [a.lower() for a in brand.get("aliases", [])]
        brand_name = brand.get("brand", "Protected Brand")
        category = brand.get("category", "institution")
        official_domains = brand.get("official_domains", [])

        for alias in aliases:
            # Check A: Combosquatting in registrable domain (e.g., 'sbi-secure-login', 'paytm-kyc')
            # Look for alias bounded by hyphen, number, or exact string
            pattern_combo = rf"(^|[-0-9]){re.escape(alias)}([-0-9]|$)"
            if re.search(pattern_combo, domain_name_part) or re.search(pattern_combo, canonical_name_part):
                # Ensure it's not a mere accidental tiny substring of an unrelated long word
                if len(domain_name_part) != len(alias) or domain_name_part != alias:
                    impersonation_signal = {
                        "name": "Brand impersonation",
                        "severity": "high",
                        "brand": brand_name,
                        "description": f"The domain '{registrable_domain}' appears to imitate {brand_name} ({category}) but is not an official {brand_name} domain.",
                        "evidence": {
                            "brand": brand_name,
                            "category": category,
                            "matched_alias": alias,
                            "detected_in": "registrable_domain",
                            "domain": registrable_domain,
                            "official_domains": official_domains,
                        }
                    }
                    signals.append(impersonation_signal)
                    return None, brand, signals

            # Check B: Subdomain Impersonation on an untrusted third-party domain
            # (e.g. 'sbi-login.attacker.example' or 'paytm.attacker.example')
            if subdomain:
                sub_pattern = rf"(^|[.-]){re.escape(alias)}([.-]|$)"
                if re.search(sub_pattern, subdomain) or alias in subdomain.split("."):
                    sub_impersonation_signal = {
                        "name": "Brand impersonation",
                        "severity": "high",
                        "brand": brand_name,
                        "description": f"The subdomain '{subdomain}' on '{registrable_domain}' attempts to impersonate {brand_name} ({category}).",
                        "evidence": {
                            "brand": brand_name,
                            "category": category,
                            "matched_alias": alias,
                            "detected_in": "subdomain",
                            "subdomain": subdomain,
                            "registrable_domain": registrable_domain,
                            "official_domains": official_domains,
                        }
                    }
                    signals.append(sub_impersonation_signal)
                    return None, brand, signals

    # 3. Check for Typosquatting (Edit Distance, Visual Substitution, Leetspeak)
    for brand in brands:
        aliases = [a.lower() for a in brand.get("aliases", [])]
        brand_name = brand.get("brand", "Protected Brand")
        category = brand.get("category", "institution")
        official_domains = brand.get("official_domains", [])

        for alias in aliases:
            # Target candidate: the base SLD (e.g. 'paytmm', 'payt1m')
            target_str = domain_name_part.lower()
            canonical_target = canonical_name_part.lower()
            leet_target = normalize_leetspeak(target_str)

            # Skip if target is exact match (handled in official/impersonation checks)
            if target_str == alias:
                continue

            # Check Leetspeak visual substitution (e.g., payt1m -> paytlm/paytim)
            if leet_target != target_str:
                leet_dist = levenshtein_distance(leet_target, alias)
                if leet_dist <= 1:
                    typo_signal = {
                        "name": "Typosquatting detected",
                        "severity": "high",
                        "brand": brand_name,
                        "description": f"The domain '{registrable_domain}' uses visual character substitution mimicking {brand_name} ({category}).",
                        "evidence": {
                            "brand": brand_name,
                            "category": category,
                            "detected_technique": "visual_substitution_leetspeak",
                            "target_domain_part": domain_name_part,
                            "matched_alias": alias,
                            "official_domains": official_domains,
                        }
                    }
                    signals.append(typo_signal)
                    return None, brand, signals

            # Calculate Levenshtein distance & similarity ratio
            dist = min(
                levenshtein_distance(target_str, alias),
                levenshtein_distance(canonical_target, alias)
            )
            ratio = max(
                SequenceMatcher(None, target_str, alias).ratio(),
                SequenceMatcher(None, canonical_target, alias).ratio()
            )

            # Qualification rules for Typosquatting:
            # For short brands (len < 4 like 'sbi'), require edit distance == 1 and character duplication/omission
            # For longer brands (len >= 4 like 'paytm', 'hdfc'), require edit distance <= MAX_LEVENSHTEIN_DISTANCE
            # and ratio >= TYPOSQUAT_SIMILARITY_THRESHOLD
            is_typo = False
            technique = "character_alteration"

            if len(alias) >= MIN_BRAND_LENGTH_FOR_FUZZY:
                if dist <= MAX_LEVENSHTEIN_DISTANCE and ratio >= TYPOSQUAT_SIMILARITY_THRESHOLD:
                    is_typo = True
                    if len(target_str) > len(alias):
                        technique = "character_duplication_or_insertion"
                    elif len(target_str) < len(alias):
                        technique = "character_omission"
                    else:
                        technique = "character_substitution_or_transposition"
            else:
                # Short brand safeguard (e.g. 'sbi' -> 'sbbii', 'sbbi')
                if dist == 1 and (target_str.startswith(alias) or target_str.endswith(alias)):
                    is_typo = True
                    technique = "short_brand_duplication"

            if is_typo:
                typo_signal = {
                    "name": "Typosquatting detected",
                    "severity": "high",
                    "brand": brand_name,
                    "description": f"The domain '{registrable_domain}' closely resembles protected brand '{brand_name}' ({technique}).",
                    "evidence": {
                        "brand": brand_name,
                        "category": category,
                        "detected_technique": technique,
                        "target_domain_part": domain_name_part,
                        "matched_alias": alias,
                        "similarity_score": round(ratio, 2),
                        "edit_distance": dist,
                        "official_domains": official_domains,
                    }
                }
                signals.append(typo_signal)
                return None, brand, signals

    return None, None, signals


def analyze_domain(hostname: str) -> Dict[str, Any]:
    """
    Performs comprehensive domain security intelligence:
    - Punycode IDN check
    - Unicode homoglyph analysis
    - Registrable domain & subdomain extraction
    - Official brand verification vs Lookalike/Typosquat detection
    """
    if not hostname:
        return {
            "domain": "",
            "normalized_domain": "",
            "subdomain": "",
            "registrable_domain": "",
            "tld": "",
            "is_punycode": False,
            "decoded_punycode": "",
            "has_homoglyphs": False,
            "homoglyph_details": [],
            "is_official_brand": False,
            "official_brand_name": None,
            "impersonated_brand": None,
            "signals": [],
        }

    clean_host = hostname.lower().strip().rstrip(".")

    # 1. Punycode (xn--) detection and decoding
    is_punycode, decoded_punycode = decode_punycode_safely(clean_host)

    # 2. Unicode Homoglyph detection on both raw host and decoded punycode
    target_for_homoglyph = decoded_punycode if is_punycode else clean_host
    has_homoglyphs, canonical_host, homoglyph_details = detect_unicode_homoglyphs(target_for_homoglyph)

    # 3. Domain components breakdown (subdomain, registrable domain, tld, name)
    subdomain, registrable_domain, tld, domain_name_part = split_domain_components(target_for_homoglyph)
    _, _, _, canonical_name_part = split_domain_components(canonical_host)

    # 4. Load trusted brand registry
    brands = load_trusted_brands()

    # 5. Evaluate Brand Impersonation and Typosquatting
    official_brand, lookalike_brand, brand_signals = analyze_brand_impersonation_and_typos(
        hostname=target_for_homoglyph,
        subdomain=subdomain,
        registrable_domain=registrable_domain,
        domain_name_part=domain_name_part,
        canonical_name_part=canonical_name_part,
        brands=brands,
    )

    all_signals = list(brand_signals)

    # 6. Evaluate Homoglyph and Punycode signals
    if has_homoglyphs:
        # Check if the transliterated host targets a protected brand
        matched_confusable_brand = None
        for brand in brands:
            for alias in brand.get("aliases", []):
                if alias in canonical_name_part:
                    matched_confusable_brand = brand.get("brand")
                    break

        homoglyph_desc = (
            f"The domain contains confusable Unicode characters visually imitating {matched_confusable_brand}."
            if matched_confusable_brand
            else "The domain contains characters that visually resemble Latin letters or a protected brand."
        )
        all_signals.append({
            "name": "Unicode homoglyph detected",
            "severity": "high",
            "description": homoglyph_desc,
            "evidence": {
                "original_hostname": clean_host,
                "decoded_representation": target_for_homoglyph,
                "canonical_latin": canonical_host,
                "confusables_found": homoglyph_details,
                "impersonated_brand": matched_confusable_brand,
            }
        })
    elif is_punycode:
        # Punycode without explicit homoglyphs is an informative low/medium signal
        all_signals.append({
            "name": "Punycode (IDN) Domain",
            "severity": "low",
            "description": f"Domain is encoded in Punycode (IDN: '{decoded_punycode}'). While legitimate for localized scripts, Punycode is frequently abused in spoofing.",
            "evidence": {
                "punycode_host": clean_host,
                "decoded_host": decoded_punycode,
            }
        })

    is_official = official_brand is not None
    official_name = official_brand.get("brand") if official_brand else None
    impersonated_name = lookalike_brand.get("brand") if lookalike_brand else None

    return {
        "domain": clean_host,
        "normalized_domain": target_for_homoglyph,
        "subdomain": subdomain,
        "registrable_domain": registrable_domain,
        "tld": tld,
        "is_punycode": is_punycode,
        "decoded_punycode": decoded_punycode,
        "has_homoglyphs": has_homoglyphs,
        "homoglyph_details": homoglyph_details,
        "is_official_brand": is_official,
        "official_brand_name": official_name,
        "impersonated_brand": impersonated_name,
        "signals": all_signals,
    }
