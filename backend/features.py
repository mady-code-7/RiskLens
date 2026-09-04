"""
features.py — Feature Extraction Layer (Layer 2)

Converts a raw URL string into a fixed-length list of numeric features.
No network requests are made here — everything is derived purely from
the URL text itself.

IMPORTANT: This exact function is imported by both train_model.py and
main.py. The feature list produced here must stay 100% consistent
between training and live inference, or the model's predictions will
be meaningless. Never duplicate this logic elsewhere — always import
from this file.
"""

import re
from urllib.parse import urlparse

# Keywords commonly seen in phishing URLs, used to bait users into
# thinking a link relates to account security/verification.
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account",
    "banking", "confirm", "signin", "webscr", "password",
]

# A short, non-exhaustive list of known URL-shortening services.
# This is only used as a weak signal, not a definitive check.
SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "shorte.st", "cutt.ly",
]

# Feature names, in the exact order extract_features() returns them.
# Keeping this list alongside the function makes it easy for main.py
# to label which feature fired when building the explanation list.
FEATURE_NAMES = [
    "url_length",
    "num_dots",
    "has_at_symbol",
    "has_hyphen_in_domain",
    "is_ip_address",
    "is_https",
    "num_subdomains",
    "has_suspicious_keyword",
    "num_digits",
    "is_shortened_url",
]


def _get_domain(url: str) -> str:
    """Best-effort extraction of the netloc/domain from a URL string."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.netloc or parsed.path.split("/")[0]


def _is_ip_address(domain: str) -> bool:
    """Checks if the domain is a raw IPv4 address instead of a hostname."""
    # Strip a port if present, e.g. "192.168.0.1:8080" -> "192.168.0.1"
    host = domain.split(":")[0]
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, host):
        # Confirm each octet is a valid 0-255 value.
        return all(0 <= int(octet) <= 255 for octet in host.split("."))
    return False


def extract_features(url: str) -> list:
    """
    Extract a fixed-length list of numeric features from a URL string.

    Args:
        url: The raw URL as typed/submitted by the user.

    Returns:
        A list of numbers (ints/floats), in the order defined by
        FEATURE_NAMES. Every feature is either a count or a 0/1 flag.
    """
    url = url.strip()
    domain = _get_domain(url)

    url_length = len(url)
    num_dots = url.count(".")
    has_at_symbol = 1 if "@" in url else 0
    has_hyphen_in_domain = 1 if "-" in domain else 0
    is_ip_address = 1 if _is_ip_address(domain) else 0
    is_https = 1 if url.lower().startswith("https://") else 0

    # Rough subdomain count: number of dot-separated labels in the domain
    # minus 2 (for the base domain + TLD), floored at 0.
    domain_labels = domain.split(".") if domain else []
    num_subdomains = max(len(domain_labels) - 2, 0)

    lowered_url = url.lower()
    has_suspicious_keyword = 1 if any(
        keyword in lowered_url for keyword in SUSPICIOUS_KEYWORDS
    ) else 0

    num_digits = sum(char.isdigit() for char in url)

    is_shortened_url = 1 if any(
        shortener in domain.lower() for shortener in SHORTENER_DOMAINS
    ) else 0

    return [
        url_length,
        num_dots,
        has_at_symbol,
        has_hyphen_in_domain,
        is_ip_address,
        is_https,
        num_subdomains,
        has_suspicious_keyword,
        num_digits,
        is_shortened_url,
    ]


if __name__ == "__main__":
    # Quick manual sanity check when running this file directly:
    # python features.py
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login",
        "http://secure-bank-verify.com/update-account?user=1234",
        "https://bit.ly/3xyzAbc",
    ]
    for test_url in test_urls:
        feats = extract_features(test_url)
        print(f"\nURL: {test_url}")
        for name, value in zip(FEATURE_NAMES, feats):
            print(f"  {name}: {value}")

            