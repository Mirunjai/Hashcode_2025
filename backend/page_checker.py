"""
page_checker.py — LinkLens Live Page Content Checker

Fetches the actual webpage and analyses its DOM structure for
high-confidence phishing indicators that the URL model cannot detect.

Checks:
  1. Forms posting to external domains (credential harvesting)
  2. Password input fields (login page detection)
  3. Hidden iframes (clickjacking / invisible redirects)
  4. Fake login structures (PayPal/Google/Microsoft lookalikes)
  5. Suspicious redirect meta tags
  6. Mismatched page title vs domain

Returns a structured result with found indicators and a 0-100 risk score
that is combined with the URL score in analyzer.py.
"""

import re
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup


# ── HTTP session with browser-like headers ────────────────────────────────────
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
})

# Brand keywords that phishing pages commonly impersonate
BRAND_KEYWORDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "instagram", "netflix", "bank", "chase", "wellsfargo", "citibank",
    "twitter", "linkedin", "dropbox", "adobe", "ebay",
]

# Phishing-style page title patterns
PHISHING_TITLE_PATTERNS = [
    r"verify\s+your",
    r"confirm\s+your",
    r"update\s+your",
    r"account\s+(suspended|locked|limited|restricted)",
    r"urgent\s+action",
    r"security\s+(alert|warning|notice)",
    r"login\s+required",
    r"sign\s+in\s+to",
]


# ── Fetch page ────────────────────────────────────────────────────────────────

def fetch_page(url: str, timeout: int = 8) -> BeautifulSoup | None:
    """Fetch a URL and return parsed BeautifulSoup, or None on failure."""
    try:
        resp = SESSION.get(url, timeout=timeout, allow_redirects=True)
        resp.raise_for_status()
        return BeautifulSoup(resp.text, "html.parser")
    except Exception:
        return None


# ── Individual checks ─────────────────────────────────────────────────────────

def check_external_form_actions(soup: BeautifulSoup, base_url: str) -> list[str]:
    """
    Check if any form submits data to a different domain.
    Classic credential harvesting — page looks like PayPal but form
    POSTs to attacker-controlled server.
    """
    findings = []
    base_domain = urlparse(base_url).netloc.lower().replace("www.", "")

    for form in soup.find_all("form"):
        action = form.get("action", "")
        if not action:
            continue
        # Resolve relative URLs
        full_action = urljoin(base_url, action)
        action_domain = urlparse(full_action).netloc.lower().replace("www.", "")
        if action_domain and action_domain != base_domain:
            findings.append(
                f"Form submits data to external domain: {action_domain}"
            )
    return findings


def check_password_fields(soup: BeautifulSoup) -> list[str]:
    """Detect password input fields — indicates a login/credential page."""
    findings = []
    pw_fields = soup.find_all("input", {"type": "password"})
    if pw_fields:
        findings.append(
            f"Page contains {len(pw_fields)} password field(s) — "
            f"credential collection detected."
        )
    return findings


def check_hidden_iframes(soup: BeautifulSoup) -> list[str]:
    """
    Detect hidden iframes — used for clickjacking and invisible redirects.
    Legitimate sites rarely use zero-size hidden iframes.
    """
    findings = []
    for iframe in soup.find_all("iframe"):
        style  = iframe.get("style", "")
        width  = iframe.get("width", "")
        height = iframe.get("height", "")
        hidden = (
            "display:none"     in style.replace(" ", "") or
            "visibility:hidden" in style.replace(" ", "") or
            width  in ("0", "1") or
            height in ("0", "1")
        )
        if hidden:
            src = iframe.get("src", "unknown")
            findings.append(f"Hidden iframe detected (src: {src[:60]})")
    return findings


def check_brand_impersonation(soup: BeautifulSoup, base_url: str) -> list[str]:
    """
    Check if page content mentions a brand that doesn't match the domain.
    e.g. page title says 'PayPal Security Center' but domain is random123.xyz
    """
    findings = []
    base_domain = urlparse(base_url).netloc.lower()

    # Check title
    title = soup.find("title")
    title_text = title.get_text().lower() if title else ""

    for brand in BRAND_KEYWORDS:
        if brand in title_text and brand not in base_domain:
            findings.append(
                f"Page title mentions '{brand}' but domain is {base_domain} "
                f"— possible brand impersonation."
            )
            break

    # Check for phishing title patterns
    for pattern in PHISHING_TITLE_PATTERNS:
        if re.search(pattern, title_text, re.IGNORECASE):
            findings.append(
                f"Suspicious page title pattern: \"{title_text[:60]}\""
            )
            break

    return findings


def check_meta_redirects(soup: BeautifulSoup) -> list[str]:
    """Detect meta refresh redirects — used to quickly redirect after credential capture."""
    findings = []
    for meta in soup.find_all("meta"):
        http_equiv = meta.get("http-equiv", "").lower()
        if http_equiv == "refresh":
            content = meta.get("content", "")
            # Short delay redirects (under 5 seconds) are suspicious
            match = re.match(r"(\d+)\s*;?\s*url=(.+)", content, re.IGNORECASE)
            if match:
                delay = int(match.group(1))
                target = match.group(2).strip().strip("'\"")
                if delay < 5:
                    findings.append(
                        f"Fast meta redirect ({delay}s) to: {target[:60]}"
                    )
    return findings


def check_favicon_mismatch(soup: BeautifulSoup, base_url: str) -> list[str]:
    """
    Check if favicon is loaded from a different domain.
    Phishing pages sometimes load the real brand's favicon to look authentic.
    """
    findings = []
    base_domain = urlparse(base_url).netloc.lower().replace("www.", "")

    for link in soup.find_all("link", rel=lambda r: r and "icon" in " ".join(r).lower()):
        href = link.get("href", "")
        if href.startswith("http"):
            favicon_domain = urlparse(href).netloc.lower().replace("www.", "")
            if favicon_domain and favicon_domain != base_domain:
                for brand in BRAND_KEYWORDS:
                    if brand in favicon_domain:
                        findings.append(
                            f"Favicon loaded from brand domain '{favicon_domain}' "
                            f"— impersonation indicator."
                        )
                        break
    return findings


# ── Score calculator ──────────────────────────────────────────────────────────

def page_risk_score(findings: dict) -> int:
    """Convert findings dict into a 0-100 risk score."""
    score = 0
    score += len(findings.get("external_forms",    [])) * 40
    score += len(findings.get("password_fields",   [])) * 20
    score += len(findings.get("hidden_iframes",    [])) * 25
    score += len(findings.get("brand_impersonation",[])) * 30
    score += len(findings.get("meta_redirects",    [])) * 20
    score += len(findings.get("favicon_mismatch",  [])) * 15
    return min(score, 100)


def page_highlights(findings: dict, score: int) -> list[str]:
    """Flatten all findings into plain-English bullets."""
    all_findings = []
    for key in ["external_forms", "brand_impersonation", "hidden_iframes",
                "meta_redirects", "password_fields", "favicon_mismatch"]:
        all_findings.extend(findings.get(key, []))
    if not all_findings:
        return ["No suspicious page structure detected."]
    return all_findings


# ── Public function ───────────────────────────────────────────────────────────

def check_page(url: str) -> dict:
    """
    Full live page check pipeline.
    Fetches the URL, runs all DOM checks, returns structured result.
    """
    soup = fetch_page(url)

    if soup is None:
        return {
            "success":          False,
            "error":            "Could not fetch page — may be offline or blocking bots.",
            "page_score":       0,
            "page_verdict":     "UNKNOWN",
            "page_highlights":  [],
            "page_findings":    {},
        }

    findings = {
        "external_forms":     check_external_form_actions(soup, url),
        "password_fields":    check_password_fields(soup),
        "hidden_iframes":     check_hidden_iframes(soup),
        "brand_impersonation":check_brand_impersonation(soup, url),
        "meta_redirects":     check_meta_redirects(soup),
        "favicon_mismatch":   check_favicon_mismatch(soup, url),
    }

    score   = page_risk_score(findings)
    verdict = (
        "MALICIOUS"  if score >= 70 else
        "SUSPICIOUS" if score >= 30 else
        "SAFE"
    )

    return {
        "success":         True,
        "page_score":      score,
        "page_verdict":    verdict,
        "page_highlights": page_highlights(findings, score),
        "page_findings":   findings,
    }