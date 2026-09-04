"""
generate_dataset.py — one-time helper script (NOT part of the app).

Generates a synthetic dataset.csv of phishing/legitimate URLs, structured
exactly like a real Kaggle phishing dataset (columns: url, label), so
train_model.py has something concrete to train on.

This is a placeholder for development/demo purposes. Swap dataset.csv
with a real Kaggle dataset later (same two columns) and nothing else
in the project needs to change.

Run manually with: python generate_dataset.py
"""

import random
import csv

random.seed(42)

LEGIT_DOMAINS = [
    "google.com", "wikipedia.org", "github.com", "amazon.com", "nytimes.com",
    "bbc.co.uk", "python.org", "stackoverflow.com", "reddit.com", "spotify.com",
    "linkedin.com", "microsoft.com", "apple.com", "netflix.com", "dropbox.com",
    "notion.so", "figma.com", "cloudflare.com", "mozilla.org", "wordpress.org",
    "harvard.edu", "who.int", "un.org", "nasa.gov", "irs.gov",
]

LEGIT_PATHS = [
    "", "/about", "/contact", "/products", "/blog/2024/updates",
    "/docs/getting-started", "/search?q=news", "/en/home", "/pricing",
    "/support/help-center", "/careers", "/news/latest",
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account",
    "banking", "confirm", "signin", "webscr", "password",
]

BRAND_LOOKALIKES = [
    "paypal", "amazon", "apple", "netflix", "microsoft", "bankofamerica",
    "chase", "wellsfargo", "google", "facebook", "instagram", "dhl", "usps",
]

SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club"]


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def make_legit_url():
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    scheme = "https://"
    sub = random.choice(["", "www.", "www.", "www."])  # mostly www or bare
    return f"{scheme}{sub}{domain}{path}"


def make_phishing_url():
    """
    Builds a synthetic phishing-style URL using a mix of common real-world
    phishing patterns: brand lookalikes, hyphenated fake domains, raw IPs,
    suspicious keywords, shorteners, and sketchy TLDs.
    """
    pattern = random.choice(
        ["ip_login", "hyphen_brand", "shortener", "suspicious_tld", "at_symbol", "long_query"]
    )
    keyword = random.choice(SUSPICIOUS_KEYWORDS)
    brand = random.choice(BRAND_LOOKALIKES)

    if pattern == "ip_login":
        return f"http://{random_ip()}/{keyword}/{brand}-account.php"

    if pattern == "hyphen_brand":
        tld = random.choice(SUSPICIOUS_TLDS)
        return f"http://{brand}-{keyword}-support{tld}/{keyword}.html"

    if pattern == "shortener":
        shortener = random.choice(SHORTENERS)
        code = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=7))
        return f"https://{shortener}/{code}"

    if pattern == "suspicious_tld":
        tld = random.choice(SUSPICIOUS_TLDS)
        return f"http://{brand}{random.randint(1, 999)}{tld}/{keyword}"

    if pattern == "at_symbol":
        return f"http://{brand}.com@{random_ip()}/{keyword}"

    # long_query
    junk = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=20))
    return f"http://secure-{brand}-{keyword}.com/{keyword}?ref={junk}&id={random.randint(1000,9999)}"


def generate_dataset(n_per_class=600):
    rows = []
    for _ in range(n_per_class):
        rows.append((make_legit_url(), 0))
    for _ in range(n_per_class):
        rows.append((make_phishing_url(), 1))
    random.shuffle(rows)
    return rows


if __name__ == "__main__":
    rows = generate_dataset(n_per_class=600)
    with open("dataset.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])  # label: 0 = legitimate, 1 = phishing
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to dataset.csv")

    