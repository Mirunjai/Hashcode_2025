# 🔍 LinkLens

> Instant, ML-powered phishing detection as a Chrome extension.

LinkLens scans every URL you visit — or any URL you paste — and gives you a threat score in under a second. It runs a trained Random Forest model on 26 URL-level signals with no external dependencies and no data leaving your machine.

---

## Project Structure

```
linklens/
├── backend/
│   ├── main.py              — FastAPI app, single endpoint: POST /analyze
│   ├── analyzer.py          — Loads model, scores URLs, builds result
│   ├── features.py          — 26 URL signals (no network, <1 ms)
│   ├── requirements.txt
│   └── models/
│       └── phishing_model.joblib   — trained by ml/train.py
│
├── ml/
│   ├── train.py             — trains the Random Forest, saves new model
│   ├── evaluate.py          — sanity-checks model against known URLs
│   ├── data_loader.py       — combines both CSV sources into one dataset
│   └── data/
│       ├── phishing_site_urls.csv  — 1 662 labelled URLs (safe + phishing)
│       └── online.csv              — 49 597 verified PhishTank URLs
│
└── extension/
    ├── public/
    │   ├── manifest.json    — Chrome MV3 manifest
    │   ├── background.js    — service worker: auto-scan every tab, notifications
    │   └── icon.svg
    ├── src/
    │   ├── Popup.jsx        — full UI: gauge, bars, history, offline fallback
    │   └── main.jsx         — React entry point
    ├── index.html
    ├── package.json
    └── vite.config.js
```

---

## Quick Start

### 1 — Backend

```bash
cd backend
pip install -r requirements.txt
python main.py
# API live at http://localhost:8000
```

### 2 — Extension

```bash
cd extension
npm install
npm run build
```

Open `chrome://extensions/` → enable **Developer Mode** → **Load unpacked** → select `extension/dist/`

### 3 — Retrain (optional)

Run this whenever you update `features.py` to rebuild the model:

```bash
cd ml
python train.py      # trains + saves new model to backend/models/
python evaluate.py   # sanity-checks 12 known URLs — should be 12/12
```

Then restart the backend so it loads the new model.

---

## API

### `POST /analyze`

**Request**
```json
{ "url": "https://paypal-secure-login.com" }
```

**Response**
```json
{
  "url":        "https://paypal-secure-login.com",
  "score":      97,
  "verdict":    "MALICIOUS",
  "confidence": 0.971,
  "highlights": [
    "A brand name appears in the URL but not in the actual domain.",
    "3 phishing-related keywords detected in URL."
  ],
  "bars": [
    { "label": "URL Length",         "value": 44 },
    { "label": "Special Characters", "value": 20 },
    { "label": "Phish Keywords",     "value": 75 },
    { "label": "URL Entropy",        "value": 61 },
    { "label": "Brand Spoofing",     "value": 100 },
    { "label": "ML Confidence",      "value": 97 }
  ]
}
```

| Score  | Verdict      |
|--------|--------------|
| 0–29   | ✅ SAFE      |
| 30–69  | ⚠️ SUSPICIOUS |
| 70–100 | 🚨 MALICIOUS |

---

## How the Model Works

The backend extracts **26 numerical features** from the URL string alone — no DNS, no WHOIS, no page fetching. This keeps every scan under 50 ms.

Feature groups:

- **Trust signals** — known-safe domains, risky TLDs, raw IP usage, URL shorteners
- **Structure** — URL/domain/path length, slash count, dot count
- **Characters** — hyphens, `@`, `%`, `=`, digit ratio, letter ratio, entropy
- **Keywords** — count of phishing words (login, verify, secure…)
- **Brand spoofing** — brand name in URL but not in domain
- **Homoglyph spoofing** — character substitution (`0→o`, `1→i`, `rn→m`, `vv→w`)

The Random Forest was trained on ~3 300 labelled URLs (safe + phishing) and achieves **98.5% test accuracy** with only 2 missed phishing URLs out of 499 in the test set.

---

## Test Results (evaluate.py)

```
[PASS]   0  SAFE      https://www.google.com
[PASS]   0  SAFE      https://nodejs.org/en/download
[PASS]  76  MALICIOUS http://googIe.com          ← homoglyph
[PASS]  80  MALICIOUS http://arnazon.com          ← rn→m typosquat
[PASS]  96  MALICIOUS http://login.microsoft.com.secure.net
[PASS]  97  MALICIOUS http://secure-paypal-verify.com
12/12 passed
```

---

## License

MIT
