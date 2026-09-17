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

# Characters that should never legitimately appear in a URL a user is
# submitting for a check. Their presence almost always means the input
# isn't a bare URL at all — e.g. markdown link syntax
# "[text](https://real-url.com)", HTML <a> tags, or other wrapped/embedded
# text where the "URL" is actually markup containing a URL somewhere
# inside it. Feeding that raw string into feature extraction produces
# meaningless features (wrong length, wrong dot count, scheme buried
# mid-string so is_https misses it, etc).
_DISALLOWED_RAW_CHARS = re.compile(r"[\[\]<>\s\"'`]")

# A single, deliberately permissive check for "does this look like one
# bare URL/hostname". It is NOT a full RFC validator — it just rejects
# the obvious non-URL cases (markdown, HTML, multiple URLs pasted
# together, plain prose) so the feature extractor never has to guess
# what a malformed string "meant".
#
# Note: '@' is deliberately allowed in the authority segment. The
# "user@host" / "fakedomain.com@real-ip" trick (used to disguise the
# real destination behind what looks like a trusted domain) is a real,
# important phishing signal that has_at_symbol is specifically meant to
# catch — rejecting it here would strip that signal out of training
# data and block real reports at inference time.
_BARE_URL_PATTERN = re.compile(
    r"^(?:[a-zA-Z][a-zA-Z0-9+.\-]*://)?"   # optional scheme
    r"[^\s/:]+(?::\d+)?"                    # authority (+ optional port)
    r"(?:/[^\s]*)?$"                        # optional path/query/fragment
)


class InvalidURLError(ValueError):
    """Raised when the input doesn't look like a single bare URL/hostname."""


def normalize_and_validate_url(raw: str) -> str:
    """
    Validates that `raw` looks like one bare URL (optionally missing its
    scheme), and returns it stripped of surrounding whitespace.

    Rejects things like markdown links ("[text](url)"), HTML anchor tags,
    strings containing embedded whitespace/quotes, and multiple URLs
    pasted together — these are not "a URL", they're text that happens to
    contain one, and scoring them directly produces meaningless features.

    Raises:
        InvalidURLError: if the input doesn't look like a single bare URL.
    """
    candidate = raw.strip()
    if not candidate:
        raise InvalidURLError("URL must not be empty.")

    if _DISALLOWED_RAW_CHARS.search(candidate):
        raise InvalidURLError(
            "Input contains characters that shouldn't appear in a bare "
            "URL (e.g. markdown/HTML markup or whitespace). Submit just "
            "the URL itself, not a link label or formatted text."
        )

    if not _BARE_URL_PATTERN.match(candidate):
        raise InvalidURLError("Input doesn't look like a valid URL.")

    return candidate

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


def _has_https_scheme(url: str) -> bool:
    """
    Checks whether the URL's scheme is https, using the parsed scheme
    rather than a raw `startswith("https://")` string check.

    A raw prefix check is fragile: if extract_features() is ever called
    on a URL missing its scheme (e.g. "www.google.com"), or on malformed
    input where "https://" appears somewhere other than the very start,
    a naive prefix check silently reports False for both "no https" and
    "malformed input" — collapsing two very different situations into
    one signal. Parsing the scheme explicitly makes the check correct
    for schemeless input and keeps it from being fooled by garbage
    elsewhere in the string (validation of that garbage happens earlier,
    in normalize_and_validate_url).

    Schemeless input (e.g. "www.google.com") is treated as https rather
    than flagged as "not https". This matches how browsers and most
    real-world URL sharing actually behaves — users routinely drop the
    scheme, and modern browsers silently upgrade to https by default.
    Absence of a scheme isn't itself a signal that a link is unsafe, so
    it shouldn't be scored as one; only an explicit "http://" should
    count against a URL here.
    """
    if "://" not in url:
        return True
    parsed = urlparse(url)
    return parsed.scheme.lower() == "https"


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

    Raises:
        InvalidURLError: if `url` doesn't look like a single bare URL
            (e.g. it's markdown/HTML, contains embedded whitespace, or
            has multiple URLs pasted together). Callers (main.py) should
            catch this and return a 400 rather than letting garbage
            reach the model.
    """
    url = normalize_and_validate_url(url)
    domain = _get_domain(url)

    url_length = len(url)
    num_dots = url.count(".")
    has_at_symbol = 1 if "@" in url else 0
    has_hyphen_in_domain = 1 if "-" in domain else 0
    is_ip_address = 1 if _is_ip_address(domain) else 0
    is_https = 1 if _has_https_scheme(url) else 0

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
        "www.google.com",
        "http://192.168.1.1/login",
        "http://secure-bank-verify.com/update-account?user=1234",
        "https://bit.ly/3xyzAbc",
        "[www.google.com](https://www.google.com)",  # should be rejected
    ]
    for test_url in test_urls:
        print(f"\nURL: {test_url}")
        try:
            feats = extract_features(test_url)
        except InvalidURLError as e:
            print(f"  REJECTED: {e}")
            continue
        for name, value in zip(FEATURE_NAMES, feats):
            print(f"  {name}: {value}")

            