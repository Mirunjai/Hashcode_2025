"""
features.py — LinkLens Feature Extractor
Pulls 27 numerical signals from a raw URL string.
Includes async WHOIS domain age with 5-second timeout and in-memory cache.
"""
import os
import re
import math
import threading
from datetime import datetime, timezone
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

# Single-char homoglyph map
_CHAR_MAP = str.maketrans("0145689|l", "oiasebgii")

SHORTENERS = re.compile(r"bit\.ly|goo\.gl|shorte\.st|ow\.ly|t\.co|tinyurl|go2l\.ink")


# ── WHOIS domain age ──────────────────────────────────────────────────────────
_whois_cache: dict = {}
_whois_lock  = threading.Lock()


def _whois_age_days(domain: str) -> int:
    """
    Returns domain age in days, or -1 if lookup fails or times out.
    Results cached in-memory. Thread runs with 5-second hard timeout.
    """
    bare = domain.replace("www.", "").split(":")[0]

    with _whois_lock:
        if bare in _whois_cache:
            return _whois_cache[bare]

    result = [-1]

    def _lookup():
        try:
            import whois
            w    = whois.whois(bare)
            date = w.creation_date
            if isinstance(date, list):
                date = date[0]
            if isinstance(date, datetime):
                if date.tzinfo is None:
                    date = date.replace(tzinfo=timezone.utc)
                age       = (datetime.now(timezone.utc) - date).days
                result[0] = max(0, age)
        except Exception:
            pass

    t = threading.Thread(target=_lookup, daemon=True)
    t.start()
    t.join(timeout=5)

    with _whois_lock:
        _whois_cache[bare] = result[0]

    return result[0]


# ── Text helpers ──────────────────────────────────────────────────────────────

def _normalise(domain: str) -> str:
    """Apply single-char and multi-char lookalike substitutions."""
    d  = domain.translate(_CHAR_MAP)
    d  = d.replace("rn", "m").replace("vv", "w").replace("cl", "d")
    d2 = d.replace("i", "l")
    for brand in BRAND_CANONICAL:
        if brand in d or brand in d2:
            return brand
    return d


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {c: text.count(c) / len(text) for c in set(text)}
    return -sum(p * math.log2(p) for p in freq.values())


# ── Main extractor ────────────────────────────────────────────────────────────

def extract(url: str) -> dict:
    """Return a flat dict of numerical features for the given URL."""
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

    # ── WHOIS domain age ──────────────────────────────────────────────────────
    # Trusted domains skip the lookup (saves time, they're safe by definition)
    if f["is_trusted"]:
        f["domain_age_days"] = 3650
    elif os.environ.get("LINKLENS_NO_WHOIS"):
        f["domain_age_days"] = -1    # skip during training
    else:
        f["domain_age_days"] = _whois_age_days(bare)
    return f