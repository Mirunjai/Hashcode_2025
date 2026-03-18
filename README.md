# 🔍 LinkLens

> Instant, ML-powered phishing detection as a Chrome extension.

LinkLens scans every URL you visit — or any URL you paste — and gives you a threat score in under a second. It runs a trained Random Forest model on 25 URL-level signals with no external dependencies and no data ever leaving your machine (except to your local backend).

---

## Features

- **One-click scan** — paste any URL and hit Scan
- **Auto-scan** — background worker scores every tab you open automatically
- **Offline fallback** — pattern-based local scoring when the backend is off
- **Threat history** — last 15 scans saved locally in Chrome storage
- **Desktop notifications** — instant alert when a MALICIOUS page is detected
- **Clean, minimal UI** — 580 px popup, no clutter

---

## Tech Stack

| Layer | Tech |
|---|---|
| Extension UI | React 18 + Vite |
| Service Worker | Chrome MV3 background.js |
| API | FastAPI + Uvicorn |
| ML | scikit-learn Random Forest |
| Feature extraction | Pure Python (no WHOIS, no network) |

---

## Project Structure

```
linklens/
├── backend/
│   ├── main.py          # FastAPI app — one endpoint: POST /analyze
│   ├── analyzer.py      # Loads model, runs features, builds result
│   ├── features.py      # 25 URL signals, pure Python, <1 ms
│   ├── requirements.txt
│   └── models/
│       └── phishing_model.joblib
│
└── extension/
    ├── public/
    │   ├── manifest.json   # Chrome MV3 manifest
    │   ├── background.js   # Service worker — auto-scan & notifications
    │   └── icon.svg
    ├── src/
    │   ├── main.jsx        # React entry point
    │   └── Popup.jsx       # Entire UI (gauge, bars, history)
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

1. Open `chrome://extensions/`
2. Enable **Developer Mode**
3. Click **Load unpacked** → select `extension/dist/`

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
  "score":      87,
  "verdict":    "MALICIOUS",
  "confidence": 0.874,
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
    { "label": "ML Confidence",      "value": 87 }
  ]
}
```

### Score → Verdict

| Range | Verdict |
|---|---|
| 0 – 29 | ✅ SAFE |
| 30 – 69 | ⚠️ SUSPICIOUS |
| 70 – 100 | 🚨 MALICIOUS |

---

## How the ML Model Works

The backend extracts **25 numerical features** from the URL string alone — no live DNS, no WHOIS, no page fetching. This keeps every scan under 50 ms.

Key feature groups:

- **Structure** — URL / domain / path length, slash count
- **Characters** — hyphens, `@`, `%`, `=`, digit ratio, letter ratio
- **Entropy** — Shannon entropy of full URL and domain
- **Keywords** — count of phishing words (login, verify, secure…)
- **Trust signals** — known TLDs, IP address usage, URL shorteners
- **Brand spoofing** — brand name present in URL but absent in domain

The Random Forest was trained on ~500 000 labelled URLs (safe + phishing).

---

## License

MIT
