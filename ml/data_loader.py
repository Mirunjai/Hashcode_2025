"""
data_loader.py — LinkLens Training Data Loader

Combines two sources into a single balanced (urls, labels) pair:

  phishing_site_urls.csv  — 1662 rows, columns: URL | Label (good/bad)
                            Already balanced 50/50.

  online.csv              — 49 597 verified phishing URLs from PhishTank.
                            All rows are phishing (label = 1).
                            We sample from this to add volume without
                            swamping the safe class.

Final dataset: all 831 safe URLs + 831 original phishing + up to N
extra PhishTank URLs, then downsampled so safe:phishing stays 1:2
(intentional slight imbalance — better to over-warn than under-warn).
"""

import pandas as pd
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"


def load() -> tuple[list[str], list[int]]:
    """
    Returns:
        urls   — list of URL strings
        labels — list of ints (0 = safe, 1 = phishing)
    """
    # ── Source 1: phishing_site_urls.csv ─────────────────────────────────────
    df1 = pd.read_csv(DATA_DIR / "phishing_site_urls.csv")
    df1 = df1.rename(columns={"URL": "url", "Label": "label"})
    df1["label"] = df1["label"].map({"good": 0, "bad": 1})
    df1 = df1.dropna(subset=["url", "label"])

    safe_urls  = df1[df1["label"] == 0]["url"].tolist()
    phish_urls = df1[df1["label"] == 1]["url"].tolist()

    # ── Source 2: online.csv (PhishTank — all phishing) ───────────────────────
    df2 = pd.read_csv(DATA_DIR / "online.csv")
    extra_phish = df2["url"].dropna().tolist()

    # Add extra phishing URLs up to 3× the safe count (1:3 safe:phish ratio cap)
    budget     = len(safe_urls) * 3 - len(phish_urls)
    extra_take = min(budget, len(extra_phish))
    phish_urls += extra_phish[:extra_take]

    # ── Combine ───────────────────────────────────────────────────────────────
    urls   = safe_urls + phish_urls
    labels = [0] * len(safe_urls) + [1] * len(phish_urls)

    print(f"[Data] Safe: {len(safe_urls):,}  |  Phishing: {len(phish_urls):,}  "
          f"|  Total: {len(urls):,}")
    return urls, labels


if __name__ == "__main__":
    urls, labels = load()
    print(f"Sample safe:    {urls[0]}")
    print(f"Sample phishing:{urls[-1]}")
