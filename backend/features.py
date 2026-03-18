"""
features.py — LinkLens Feature Extractor
Pulls ~25 numerical signals from a raw URL string.
No network calls. Runs in <1 ms.
"""

import re
import math
from urllib.parse import urlparse


# Known trustworthy domains — scored immediately as low-risk
TRUSTED = {
    "google.com", "github.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "youtube.com", "wikipedia.org", "reddit.com",
    "twitter.com", "instagram.com", "linkedin.com", "netflix.com", "bbc.com",
}

# TLDs heavily associated with free/spam domains
RISKY_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".loan", ".club"}

# Phishing keyword list
PHISH_WORDS = {
    "login", "secure", "account", "update", "verify", "confirm",
    "banking", "signin", "webscr", "paypal", "apple", "microsoft",
    "google", "amazon", "ebay",
}

# URL shorteners
SHORTENERS = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|ow\.ly|t\.co|tinyurl|go2l\.ink"
)


def _entropy(text: str) -> float:
    """Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {c: text.count(c) / len(text) for c in set(text)}
    return -sum(p * math.log2(p) for p in freq.values())


def extract(url: str) -> dict:
    """Return a flat dict of numerical features for the given URL."""
    if not re.match(r"^https?://", url):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path   = parsed.path

    # Normalise domain (strip www.)
    bare_domain = domain.replace("www.", "")

    f = {}

    # ── Trust signal ──────────────────────────────────────────────────────────
    f["is_trusted"]     = 1 if bare_domain in TRUSTED else 0
    f["risky_tld"]      = 1 if any(domain.endswith(t) for t in RISKY_TLDS) else 0
    f["uses_ip"]        = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain) else 0
    f["is_shortened"]   = 1 if SHORTENERS.search(url) else 0

    # ── Length signals ────────────────────────────────────────────────────────
    f["url_len"]        = len(url)
    f["domain_len"]     = len(domain)
    f["path_len"]       = len(path)

    # ── Character counts ──────────────────────────────────────────────────────
    f["n_dots"]         = url.count(".")
    f["n_hyphens"]      = url.count("-")
    f["n_at"]           = url.count("@")
    f["n_question"]     = url.count("?")
    f["n_equals"]       = url.count("=")
    f["n_percent"]      = url.count("%")
    f["n_slashes"]      = path.count("/")
    f["n_digits"]       = sum(c.isdigit() for c in url)
    f["n_letters"]      = sum(c.isalpha() for c in url)
    f["http_count"]     = url.count("http")   # >1 means embedded URL

    # ── Ratios ────────────────────────────────────────────────────────────────
    f["digit_ratio"]    = f["n_digits"]  / len(url) if url else 0
    f["letter_ratio"]   = f["n_letters"] / len(url) if url else 0
    f["path_ratio"]     = len(path)      / len(url) if url else 0

    # ── Keyword signals ───────────────────────────────────────────────────────
    lower = url.lower()
    f["phish_keywords"] = sum(1 for w in PHISH_WORDS if w in lower)
    brand_words = ["paypal", "apple", "microsoft", "google", "amazon", "bank"]
    f["has_brand"]      = 1 if any(b in lower for b in brand_words) else 0
    # Brand in URL but NOT in the registered domain → impersonation signal
    f["brand_spoof"]    = 1 if (
        f["has_brand"] and not any(b in bare_domain for b in brand_words)
    ) else 0

    # ── Entropy ───────────────────────────────────────────────────────────────
    f["url_entropy"]    = round(_entropy(url), 3)
    f["domain_entropy"] = round(_entropy(domain), 3)

    return f
