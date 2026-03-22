<div align="center">

<img src="extension/public/icon.svg" width="64" height="64" alt="LinkLens logo" />

# LinkLens

**ML-powered phishing detection for every URL you visit**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)](https://python.org)
[![XGBoost](https://img.shields.io/badge/Model-XGBoost-orange)](https://xgboost.readthedocs.io)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-4285F4?logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> Originally built at **Hashcode 2025** hackathon. Rebuilt from the ground up as a complete, production-quality phishing detection system.

</div>

---

## What it does

LinkLens is a Chrome extension backed by a local ML API. Every URL you visit is analysed in real time across **four detection layers**:

| Layer | What it checks |
|---|---|
| **ML URL Analysis** | 27 structural URL signals — entropy, homoglyphs, brand spoofing, domain age |
| **QR Decoding** | Decodes QR codes from uploaded images or live page `<img>` tags |
| **OCR Content** | Screenshots the page and scans visible text for phishing phrases |
| **DOM Structure** | Fetches the live page and checks for external form targets, hidden iframes, credential fields |

If a threat is detected, a full-screen block page intercepts navigation before the page renders.

---

## Demo

> *(Screen recording coming soon)*

**Test cases from live usage:**

| URL | Score | Verdict | Why |
|---|---|---|---|
| `googIe.com` | 80 | MALICIOUS | Capital I homoglyph |
| `arnazon.com` | 80 | MALICIOUS | `rn→m` typosquat |
| `secure-paypal-verify.com` | 98 | MALICIOUS | Phishing keywords |
| `login.microsoft.com.secure.net` | 66 | SUSPICIOUS | Brand in subdomain |
| `drive.google.com` | 0 | SAFE | Trusted domain |
| `claude.ai` | 0 | SAFE | Trusted domain |

---

## Model Performance

Trained with **XGBoost** on 32,433 URLs from PhishTank, OpenPhish, and Majestic Million.

```
Test accuracy       97.4%
False positives     77 / 6,487 test URLs
False negatives     90 / 6,487 test URLs
Training time       13.5 seconds
Features            27 URL signals
```

**Top features by importance:**
```
domain_age_days     0.2317  ██████████████████████████
path_len            0.1628  ██████████████████
is_trusted          0.1330  ███████████████
url_len             0.1084  ████████████
n_digits            0.0564  ██████
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Chrome Extension                    │
│  ┌──────────┐  ┌────────────┐  ┌─────────────────┐  │
│  │ Popup.jsx│  │background  │  │  content.js     │  │
│  │ (React)  │  │.js (SW)    │  │  (block page)   │  │
│  └────┬─────┘  └─────┬──────┘  └─────────────────┘  │
└───────┼──────────────┼─────────────────────────────-─┘
        │              │  HTTP (localhost:8000)
        ▼              ▼
┌─────────────────────────────────────────────────────┐
│               FastAPI Backend                        │
│  /analyze    /decode-qr    /analyze-page             │
│  /check-page                                         │
│  ┌────────────┐  ┌───────────────┐  ┌─────────────┐ │
│  │ analyzer   │  │ ocr_analyzer  │  │page_checker │ │
│  │ (XGBoost)  │  │ (pytesseract) │  │(BeautifulS.)│ │
│  └────────────┘  └───────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────┘
```

---

## Installation

### Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Python | 3.10+ | Backend runtime |
| Node.js | 18+ | Extension build |
| Tesseract OCR | 5.x | Page text extraction |
| Chrome | Any | Extension host |

### 1. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/linklens.git
cd linklens
```

### 2. Install backend dependencies

```bash
cd backend
pip install -r requirements.txt
```

**Install Tesseract OCR** (Windows):
Download from [UB Mannheim](https://github.com/UB-Mannheim/tesseract/wiki) and add to PATH, or set in `ocr_analyzer.py`:
```python
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
```

**Install ZBar** (for QR decoding):
```bash
pip install pyzbar[zbar-wheel]
```

### 3. Train the model

```bash
cd ../ml
python train.py           # local data only (~30 seconds)
python train.py --live    # fetch live feeds (~2 minutes, recommended)
```

### 4. Start the backend

```bash
cd ../backend
python main.py
```

Backend runs on `http://localhost:8000`. Visit it to confirm:
```json
{"status": "ok", "service": "LinkLens", "version": "1.5.0"}
```

### 5. Build and load the extension

```bash
cd ../extension
npm install
npm run build
```

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked** → select the `extension/dist/` folder
4. The LinkLens icon appears in your toolbar

### 6. Optional — Auto-start backend on Windows login

Double-click `start_linklens_silent.vbs` to test, then create a shortcut to it in your Windows Startup folder:
```
Win + R → shell:startup → paste shortcut here
```

---

## Project Structure

```
linklens/
├── backend/
│   ├── main.py              # FastAPI app — all endpoints
│   ├── analyzer.py          # ML model loader + combined scoring
│   ├── features.py          # 27 URL feature extractors
│   ├── ocr_analyzer.py      # Screenshot OCR + phrase matching
│   ├── page_checker.py      # Live DOM structure analysis
│   ├── requirements.txt
│   └── models/
│       └── phishing_model.joblib
├── ml/
│   ├── train.py             # XGBoost training pipeline
│   ├── data_loader.py       # Multi-source data loader
│   ├── evaluate.py          # 12-URL sanity check
│   └── data/
│       ├── phishing_site_urls.csv
│       └── online.csv
├── extension/
│   ├── public/
│   │   ├── manifest.json
│   │   ├── background.js    # Service worker
│   │   ├── content.js       # Block page injector
│   │   ├── qr_detector.js   # Auto QR scanner
│   │   └── jsqr.min.js
│   └── src/
│       ├── Popup.jsx        # React popup UI
│       └── main.jsx
├── start_linklens.bat       # Manual backend start
└── start_linklens_silent.vbs # Silent auto-start
```

---

## Data Sources

| Source | Type | Size | URL |
|---|---|---|---|
| PhishTank `online.csv` | Phishing | 49,597 URLs | [phishtank.com](https://phishtank.com) |
| `phishing_site_urls.csv` | Safe + Phishing | 1,662 URLs | Kaggle |
| OpenPhish feed | Phishing (live) | ~300 URLs | [openphish.com](https://openphish.com/feed.txt) |
| Majestic Million | Safe (live) | 10,000 domains | [majestic.com](https://downloads.majestic.com/majestic_million.csv) |

---

## API Reference

### `POST /analyze`
```json
{ "url": "https://example.com", "ocr_score": -1 }
```
Returns: `score`, `verdict`, `confidence`, `highlights`, `bars`, `url_score`, `ocr_applied`

### `POST /decode-qr`
```json
{ "image_base64": "..." }
```
Returns: full analyze result + `qr_url`

### `POST /analyze-page`
```json
{ "url": "https://example.com", "image_base64": "..." }
```
Returns: `ocr_score`, `ocr_verdict`, `ocr_highlights`

### `POST /check-page`
```json
{ "url": "https://example.com" }
```
Returns: `page_score`, `page_verdict`, `page_highlights`, `page_findings`

---

## Roadmap

- [x] XGBoost ML model (27 features, 97.4% accuracy)
- [x] Live phishing data feeds (OpenPhish, PhishTank, Majestic)
- [x] WHOIS domain age feature
- [x] QR code scanner (upload + auto-detect on pages)
- [x] OCR page content analysis
- [x] Live DOM structure checker
- [x] Block page on MALICIOUS sites
- [x] Windows auto-start
- [ ] SHAP explainability engine (in progress — [@Sudarshan](https://github.com/))
- [ ] Docker one-command setup
- [ ] Chrome Web Store publication

---

## Team

Built at **Hashcode 2025** by a 4-person team. Rebuilt and extended by:

- **ML pipeline** — feature extraction, model training, data loading
- **Backend API** — FastAPI endpoints, combined scoring logic
- **Chrome Extension** — popup UI, service worker, content scripts

---

## License

[MIT](LICENSE) — free to use, modify, and distribute with attribution.