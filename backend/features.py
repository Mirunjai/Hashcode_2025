"""
features.py — LinkLens Feature Extractor
Pulls 26 numerical signals from a raw URL string.
No network calls. Runs in <1 ms.
"""

import re
import math
from urllib.parse import urlparse


TRUSTED = {
    # Core Google
    "google.com", "drive.google.com", "docs.google.com", "mail.google.com",
    "sheets.google.com", "calendar.google.com", "meet.google.com",
    "maps.google.com", "photos.google.com",
    # Big tech
    "github.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "youtube.com", "wikipedia.org",
    "reddit.com", "twitter.com", "instagram.com", "linkedin.com",
    "netflix.com", "bbc.com", "discord.com", "twitch.tv",
    # AI tools
    "claude.ai", "chatgpt.com", "chat.openai.com", "openai.com",
    "gemini.google.com", "copilot.microsoft.com",
    # Dev tools
    "nodejs.org", "npmjs.com", "pypi.org", "docs.python.org",
    "developer.mozilla.org", "stackoverflow.com", "cloudflare.com",
    "fastapi.tiangolo.com", "reactjs.org", "vitejs.dev",
    "docs.github.com", "learn.microsoft.com", "support.apple.com",
    "vercel.app", "netlify.app", "figma.com", "notion.so",
}

RISKY_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".loan", ".club"}

PHISH_WORDS = {
    "login", "secure", "account", "update", "verify", "confirm",
    "banking", "signin", "webscr", "paypal", "apple", "microsoft",
    "google", "amazon", "ebay",
}

BRAND_CANONICAL = {"google", "amazon", "paypal", "apple", "microsoft", "facebook", "netflix"}

# Single-char substitutions (0→o, 1→i, 4→a, 5→s, 6→b, 8→g, 9→i, |→i, l→i)
_CHAR_MAP = str.maketrans("0145689|l", "oiasebgii")

SHORTENERS = re.compile(r"bit\.ly|goo\.gl|shorte\.st|ow\.ly|t\.co|tinyurl|go2l\.ink")


def _normalise(domain: str) -> str:
    """Apply single-char and multi-char lookalike substitutions."""
    d = domain.translate(_CHAR_MAP)
    d = d.replace("rn", "m").replace("vv", "w").replace("cl", "d")
    # Also try i→l substitution (capital I lowercases to i, fooling google→googie)
    d2 = d.replace("i", "l")
    # Return whichever variant matches a brand
    for brand in BRAND_CANONICAL:
        if brand in d or brand in d2:
            return brand  # signals a match
    return d


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {c: text.count(c) / len(text) for c in set(text)}
    return -sum(p * math.log2(p) for p in freq.values())


def extract(url: str) -> dict:
    if not re.match(r"^https?://", url):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path   = parsed.path
    bare   = domain.replace("www.", "")

    f = {}

    # ── Trust ─────────────────────────────────────────────────────────────────
    f["is_trusted"]      = 1 if bare in TRUSTED else 0
    f["risky_tld"]       = 1 if any(domain.endswith(t) for t in RISKY_TLDS) else 0
    f["uses_ip"]         = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain) else 0
    f["is_shortened"]    = 1 if SHORTENERS.search(url) else 0

    # ── Lengths ───────────────────────────────────────────────────────────────
    f["url_len"]         = len(url)
    f["domain_len"]      = len(domain)
    f["path_len"]        = len(path)

    # ── Character counts ──────────────────────────────────────────────────────
    f["n_dots"]          = url.count(".")
    f["n_hyphens"]       = url.count("-")
    f["n_at"]            = url.count("@")
    f["n_question"]      = url.count("?")
    f["n_equals"]        = url.count("=")
    f["n_percent"]       = url.count("%")
    f["n_slashes"]       = path.count("/")
    f["n_digits"]        = sum(c.isdigit() for c in url)
    f["n_letters"]       = sum(c.isalpha() for c in url)
    f["http_count"]      = url.count("http")

    # ── Ratios ────────────────────────────────────────────────────────────────
    n = len(url) or 1
    f["digit_ratio"]     = f["n_digits"]  / n
    f["letter_ratio"]    = f["n_letters"] / n
    f["path_ratio"]      = len(path)      / n

    # ── Keywords & brand ─────────────────────────────────────────────────────
    lower       = url.lower()
    brand_words = ["paypal", "apple", "microsoft", "google", "amazon", "bank"]
    normalised  = _normalise(bare)

    f["phish_keywords"]  = sum(1 for w in PHISH_WORDS if w in lower)
    f["has_brand"]       = 1 if any(b in lower        for b in brand_words) else 0
    f["brand_spoof"]     = 1 if (
        f["has_brand"] and not any(b in bare for b in brand_words)
    ) else 0
    f["homoglyph_spoof"] = 1 if (
        any(b == normalised for b in BRAND_CANONICAL)
        and not any(b in bare for b in BRAND_CANONICAL)
    ) else 0

    # ── Entropy ───────────────────────────────────────────────────────────────
    f["url_entropy"]     = round(_entropy(url), 3)
    f["domain_entropy"]  = round(_entropy(domain), 3)

    return f
