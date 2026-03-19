"""
data_loader.py — LinkLens Training Data Loader

Sources:
  Safe URLs:
    1. phishing_site_urls.csv  — 831 labelled safe URLs, local
    2. Majestic Million        — top 10,000 legitimate domains, live
    3. Cisco Umbrella          — fallback if Majestic fails, live

  Phishing URLs:
    1. phishing_site_urls.csv  — 831 labelled phishing URLs, local
    2. online.csv              — 49,597 PhishTank URLs, local
    3. OpenPhish feed          — ~300 fresh phishing URLs, live
    4. PhishTank open data     — up to 10,000 verified URLs, live

Balance target: safe : phishing = 1 : 2

Usage:
    python data_loader.py           # local data only
    python data_loader.py --live    # also fetch live feeds
"""

import sys
import io
import time
import zipfile
import urllib.request
import pandas as pd
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
LIVE     = "--live" in sys.argv


# ── Safe URL fetchers ─────────────────────────────────────────────────────────

def fetch_safe_domains(limit: int = 10_000) -> list[str]:
    """
    Fetch top legitimate domains from Majestic Million (free, no auth).
    Falls back to Cisco Umbrella if Majestic fails.
    Converts bare domain → https://domain/ for feature extraction.
    """
    sources = [
        {
            "name":       "Majestic Million",
            "url":        "https://downloads.majestic.com/majestic_million.csv",
            "zipped":     False,
            "has_header": True,
            "domain_col": "Domain",
        },
        {
            "name":       "Cisco Umbrella",
            "url":        "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
            "zipped":     True,
            "has_header": False,
            "domain_col": 1,       # second column (index 1)
        },
    ]

    for src in sources:
        print(f"  [{src['name']}] Fetching {src['url']} …")
        try:
            req  = urllib.request.urlopen(src["url"], timeout=30)
            data = req.read()

            if src["zipped"]:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    data = z.read(z.namelist()[0])

            df = pd.read_csv(
                io.BytesIO(data),
                header=0 if src["has_header"] else None,
            )

            col     = src["domain_col"]
            domains = df[col].dropna().astype(str).tolist()
            urls    = [
                f"https://{d.strip()}/"
                for d in domains
                if d.strip() and "." in d.strip()
            ][:limit]

            print(f"  [{src['name']}] Got {len(urls):,} safe domain URLs")
            return urls

        except Exception as e:
            print(f"  [{src['name']}] Failed ({e}) — trying next source")

    print("  [Safe domains] All live sources failed — using local data only")
    return []


# ── Phishing URL fetchers ─────────────────────────────────────────────────────

def fetch_openphish(limit: int = 10_000) -> list[str]:
    """Fetch phishing URLs from OpenPhish free feed (plain text, one per line)."""
    url = "https://openphish.com/feed.txt"
    print(f"  [OpenPhish] Fetching {url} …")
    try:
        req   = urllib.request.urlopen(url, timeout=15)
        lines = req.read().decode(errors="ignore").strip().split("\n")
        urls  = [l.strip() for l in lines if l.strip().startswith("http")][:limit]
        print(f"  [OpenPhish] Got {len(urls):,} phishing URLs")
        return urls
    except Exception as e:
        print(f"  [OpenPhish] Failed ({e}) — skipping")
        return []


def fetch_phishtank(limit: int = 10_000) -> list[str]:
    """Fetch verified phishing URLs from PhishTank open data CSV."""
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
    """Load phishing_site_urls.csv → (safe_urls, phish_urls)."""
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
    """Load online.csv (PhishTank export) → phish_urls."""
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
        live: if True, fetch Majestic/Umbrella safe domains + OpenPhish/PhishTank.

    Returns:
        urls   — list of URL strings
        labels — list of ints (0 = safe, 1 = phishing)
    """
    print(f"\n[Data] Loading {'local + live' if live else 'local only'} sources …")

    # ── Safe URLs ─────────────────────────────────────────────────────────────
    local_safe, local_phish = load_local_labelled()
    safe_urls = list(local_safe)

    if live:
        safe_urls += fetch_safe_domains(limit=10_000)

    safe_urls = list(dict.fromkeys(safe_urls))   # de-duplicate, preserve order

    # ── Phishing URLs ─────────────────────────────────────────────────────────
    phish_urls = list(local_phish)
    phish_urls += load_local_phishtank()

    if live:
        phish_urls += fetch_openphish(limit=10_000)
        phish_urls += fetch_phishtank(limit=10_000)

    phish_urls = list(dict.fromkeys(phish_urls))  # de-duplicate

    # ── Balance ───────────────────────────────────────────────────────────────
    # Target: safe : phishing = 1 : 2
    # Never discard safe data — cap phishing to 2× safe instead.
    # If phishing is scarce, cap safe to match available phishing.
    max_phish = len(safe_urls) * 2
    if len(phish_urls) > max_phish:
        print(f"  [Balance] Capping phishing at {max_phish:,} (2× safe count)")
        phish_urls = phish_urls[:max_phish]
    elif len(phish_urls) < len(safe_urls):
        print(f"  [Balance] Phishing scarce — capping safe at {len(phish_urls):,}")
        safe_urls = safe_urls[:len(phish_urls)]

    # ── Final dataset ─────────────────────────────────────────────────────────
    urls   = safe_urls + phish_urls
    labels = [0] * len(safe_urls) + [1] * len(phish_urls)

    ratio = len(phish_urls) / max(len(safe_urls), 1)
    print(f"\n[Data] ── Final dataset ──────────────────────────────")
    print(f"[Data]   Safe     : {len(safe_urls):>8,}")
    print(f"[Data]   Phishing : {len(phish_urls):>8,}")
    print(f"[Data]   Total    : {len(urls):>8,}")
    print(f"[Data]   Ratio    : 1 : {ratio:.1f}")
    print(f"[Data] ─────────────────────────────────────────────\n")

    return urls, labels


if __name__ == "__main__":
    t0           = time.time()
    urls, labels = load()
    safe_count   = labels.count(0)
    print(f"Done in {time.time() - t0:.1f}s")
    print(f"Sample safe    : {urls[0]}")
    print(f"Sample phishing: {urls[safe_count]}")