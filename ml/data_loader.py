"""
data_loader.py — LinkLens Training Data Loader

Sources (in priority order):
  1. phishing_site_urls.csv  — 1,662 labelled URLs (safe + phishing), local
  2. online.csv              — 49,597 PhishTank phishing URLs, local
  3. OpenPhish feed          — live feed, ~5,000 fresh phishing URLs, fetched on demand
  4. Tranco top-1M list      — live feed, top legitimate domains, fetched on demand

Final balance target: safe:phishing = 1:2
(slightly imbalanced toward phishing — better to over-warn than miss a threat)

Usage:
    python data_loader.py              # uses local data only
    python data_loader.py --live       # fetches OpenPhish + Tranco too
"""

import sys
import time
import pandas as pd
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
LIVE     = "--live" in sys.argv


# ── Live fetchers ─────────────────────────────────────────────────────────────

def fetch_openphish(limit: int = 10_000) -> list[str]:
    """
    Fetch phishing URLs from OpenPhish free feed.
    Returns up to `limit` URLs. Returns [] on any error.
    """
    import urllib.request
    url = "https://openphish.com/feed.txt"
    print(f"  [OpenPhish] Fetching {url} …")
    try:
        req = urllib.request.urlopen(url, timeout=15)
        lines = req.read().decode(errors="ignore").strip().split("\n")
        urls  = [l.strip() for l in lines if l.strip().startswith("http")][:limit]
        print(f"  [OpenPhish] Got {len(urls):,} phishing URLs")
        return urls
    except Exception as e:
        print(f"  [OpenPhish] Failed ({e}) — skipping")
        return []


def fetch_tranco(limit: int = 10_000) -> list[str]:
    """
    Fetch top legitimate domains from the Tranco list.
    Converts domain → https://domain/ for feature extraction.
    Returns up to `limit` URLs. Returns [] on any error.
    """
    import urllib.request
    url = "https://tranco-list.eu/download/latest/1M"
    print(f"  [Tranco] Fetching top-{limit:,} domains from {url} …")
    try:
        req   = urllib.request.urlopen(url, timeout=30)
        lines = req.read().decode(errors="ignore").strip().split("\n")
        urls  = []
        for line in lines:
            parts = line.strip().split(",")
            if len(parts) >= 2:
                domain = parts[1].strip()
                if domain:
                    urls.append(f"https://{domain}/")
            if len(urls) >= limit:
                break
        print(f"  [Tranco] Got {len(urls):,} safe domain URLs")
        return urls
    except Exception as e:
        print(f"  [Tranco] Failed ({e}) — skipping")
        return []


def fetch_phishtank(limit: int = 10_000) -> list[str]:
    """
    Fetch verified phishing URLs from PhishTank open data.
    Returns up to `limit` URLs. Returns [] on any error.
    """
    import urllib.request
    import io
    url = "http://data.phishtank.com/data/online-valid.csv"
    print(f"  [PhishTank] Fetching {url} …")
    try:
        req  = urllib.request.urlopen(url, timeout=30)
        data = req.read().decode(errors="ignore")
        df   = pd.read_csv(io.StringIO(data))
        urls = df["url"].dropna().tolist()[:limit]
        print(f"  [PhishTank] Got {len(urls):,} phishing URLs")
        return urls
    except Exception as e:
        print(f"  [PhishTank] Failed ({e}) — skipping")
        return []


# ── Local loaders ─────────────────────────────────────────────────────────────

def load_local_labelled() -> tuple[list[str], list[str]]:
    """Load phishing_site_urls.csv — returns (safe_urls, phish_urls)."""
    path = DATA_DIR / "phishing_site_urls.csv"
    if not path.exists():
        print(f"  [Local] {path.name} not found — skipping")
        return [], []
    df = pd.read_csv(path).rename(columns={"URL": "url", "Label": "label"})
    df["label"] = df["label"].map({"good": 0, "bad": 1})
    df = df.dropna(subset=["url", "label"])
    safe  = df[df["label"] == 0]["url"].tolist()
    phish = df[df["label"] == 1]["url"].tolist()
    print(f"  [Local] phishing_site_urls.csv → {len(safe):,} safe, {len(phish):,} phishing")
    return safe, phish


def load_local_phishtank() -> list[str]:
    """Load online.csv (PhishTank export) — returns phish_urls."""
    path = DATA_DIR / "online.csv"
    if not path.exists():
        print(f"  [Local] {path.name} not found — skipping")
        return []
    df   = pd.read_csv(path)
    urls = df["url"].dropna().tolist()
    print(f"  [Local] online.csv → {len(urls):,} phishing URLs")
    return urls


# ── Main public function ──────────────────────────────────────────────────────

def load(live: bool = LIVE) -> tuple[list[str], list[int]]:
    """
    Build the full training dataset.

    Args:
        live: if True, also fetch OpenPhish, Tranco, and PhishTank live feeds.

    Returns:
        urls   — list of URL strings
        labels — list of ints (0 = safe, 1 = phishing)
    """
    print(f"\n[Data] Loading {'local + live' if live else 'local only'} sources …")

    # ── Gather safe URLs ──────────────────────────────────────────────────────
    local_safe, local_phish = load_local_labelled()
    safe_urls = list(local_safe)

    if live:
        tranco_safe = fetch_tranco(limit=10_000)
        safe_urls  += tranco_safe

    # De-duplicate
    safe_urls = list(dict.fromkeys(safe_urls))

    # ── Gather phishing URLs ──────────────────────────────────────────────────
    phish_urls = list(local_phish)
    phish_urls += load_local_phishtank()

    if live:
        phish_urls += fetch_openphish(limit=10_000)
        phish_urls += fetch_phishtank(limit=10_000)

    # De-duplicate
    phish_urls = list(dict.fromkeys(phish_urls))

    # ── Balance: cap phishing at 2× safe ─────────────────────────────────────
    max_phish  = len(safe_urls) * 2
    if len(phish_urls) > max_phish:
        print(f"  [Balance] Capping phishing at {max_phish:,} (2× safe count)")
        phish_urls = phish_urls[:max_phish]

    # ── Final dataset ─────────────────────────────────────────────────────────
    urls   = safe_urls + phish_urls
    labels = [0] * len(safe_urls) + [1] * len(phish_urls)

    print(f"\n[Data] ── Final dataset ──────────────────────────────")
    print(f"[Data]   Safe     : {len(safe_urls):>8,}")
    print(f"[Data]   Phishing : {len(phish_urls):>8,}")
    print(f"[Data]   Total    : {len(urls):>8,}")
    print(f"[Data]   Ratio    : 1 : {len(phish_urls)/max(len(safe_urls),1):.1f}")
    print(f"[Data] ─────────────────────────────────────────────\n")

    return urls, labels


if __name__ == "__main__":
    t0    = time.time()
    urls, labels = load()
    safe  = labels.count(0)
    phish = labels.count(1)
    print(f"Done in {time.time()-t0:.1f}s")
    print(f"Sample safe    : {urls[0]}")
    print(f"Sample phishing: {urls[safe]}")