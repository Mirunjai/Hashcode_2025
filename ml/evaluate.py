"""
evaluate.py — LinkLens Model Evaluator

Tests the full analyze() pipeline (model + overrides) against a
hand-picked list of URLs. Run this after every retrain to confirm
the model is behaving correctly before restarting the backend.

Usage:
    cd ml
    python evaluate.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from analyzer import analyze, load_model  # noqa: E402

# ── Test cases ────────────────────────────────────────────────────────────────
# Format: (url, expected_verdict, note)
TEST_URLS = [
    # Should be SAFE
    ("https://www.google.com",                "SAFE",       "trusted domain"),
    ("https://github.com/torvalds/linux",     "SAFE",       "trusted + long path"),
    ("https://nodejs.org/en/download",        "SAFE",       "was false-positive before fix"),
    ("https://www.bbc.com/news",              "SAFE",       "news site"),

    # Should be MALICIOUS
    ("http://googIe.com",                     "MALICIOUS",  "homoglyph — capital I"),
    ("http://arnazon.com",                    "MALICIOUS",  "typosquat — rn looks like m"),
    ("http://paypa1.com/login",               "MALICIOUS",  "homoglyph — 1 for l"),
    ("http://yourbank.xyz",                   "MALICIOUS",  "risky TLD + keyword"),
    ("http://192.168.1.1/login",              "MALICIOUS",  "raw IP + login path"),
    ("http://login.microsoft.com.secure.net", "MALICIOUS",  "brand in subdomain spoof"),
    ("http://secure-paypal-verify.com",       "MALICIOUS",  "phishing keywords"),
    ("http://apple-id-confirm.tk",            "MALICIOUS",  "brand + risky TLD"),
]


def main():
    print("=" * 70)
    print("LinkLens Evaluator")
    print("=" * 70)

    load_model()

    passed = 0
    failed = 0

    for url, expected, note in TEST_URLS:
        result  = analyze(url)
        score   = result.get("score", -1)
        verdict = result.get("verdict", "ERROR")

        ok     = verdict == expected
        status = "PASS" if ok else "FAIL"
        passed += ok
        failed += not ok

        flag = "" if ok else f"  ← expected {expected}"
        print(f"  [{status}] {score:>3}  {verdict:<11}  "
              f"{url[:46]:<46}  # {note}{flag}")

    print("-" * 70)
    print(f"  {passed}/{passed + failed} passed")
    if failed == 0:
        print("  All tests passed — model is ready.")
    else:
        print(f"  {failed} test(s) failed — review before deploying.")
    print("=" * 70)


if __name__ == "__main__":
    main()
