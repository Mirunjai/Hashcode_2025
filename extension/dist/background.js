/**
 * background.js — LinkLens Service Worker v1.4
 *
 * Changes from v1.3:
 *  - Injects jsQR library + qr_detector.js into every page after load
 *  - Handles SCAN_QR_URL message — scans a URL decoded from a QR on a page
 *  - Handles QR_THREAT_FOUND — fires notification when malicious QR detected
 *  - Handles QR_BADGE_CLICK — stores URL so popup pre-fills it on open
 *  - scripting permission used to inject jsQR dynamically
 */

const API     = "http://localhost:8000/analyze";
const OCR_API = "http://localhost:8000/analyze-page";
const JSQR_CDN = "https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js";
const CACHE_TTL = 5 * 60 * 1000;

const urlCache   = new Map();
const tabResults = new Map();
const ocrResults = new Map();


// ── Badge helpers ─────────────────────────────────────────────────────────────
function setBadge(tabId, text, color) {
  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
}
function clearBadge(tabId) {
  chrome.action.setBadgeText({ text: "", tabId });
}
function applyBadge(tabId, result) {
  if (!result) { clearBadge(tabId); return; }
  if (result.verdict === "MALICIOUS")       setBadge(tabId, "!", "#f43f5e");
  else if (result.verdict === "SUSPICIOUS") setBadge(tabId, "?", "#f59e0b");
  else {
    setBadge(tabId, "✓", "#22d3a4");
    setTimeout(() => clearBadge(tabId), 3000);
  }
}


// ── Block page ────────────────────────────────────────────────────────────────
function sendBlockPage(tabId, result, url) {
  if (result?.verdict !== "MALICIOUS") return;
  const msg = {
    type:       "BLOCK_PAGE",
    score:      result.score,
    url:        url,
    highlights: result.highlights || [],
  };
  chrome.tabs.sendMessage(tabId, msg).catch(() => {
    chrome.scripting.executeScript({
      target: { tabId },
      files:  ["content.js"],
    }).then(() => {
      setTimeout(() => chrome.tabs.sendMessage(tabId, msg).catch(() => {}), 100);
    }).catch(() => {});
  });
}


// ── QR detector injection ─────────────────────────────────────────────────────
async function injectQrDetector(tabId) {
  try {
    // Inject jsQR library first, then the detector script
    await chrome.scripting.executeScript({
      target: { tabId },
      files:  ["jsqr.min.js"],
    });
    await chrome.scripting.executeScript({
      target: { tabId },
      files:  ["qr_detector.js"],
    });
  } catch {
    // Page may not allow script injection — skip silently
  }
}


// ── Filters ───────────────────────────────────────────────────────────────────
function shouldScan(url) {
  if (!url || !url.startsWith("http")) return false;
  if (url.includes("localhost") || url.includes("127.0.0.1")) return false;
  return true;
}


// ── Cache ─────────────────────────────────────────────────────────────────────
function fromCache(url) {
  const entry = urlCache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL) { urlCache.delete(url); return null; }
  return entry.result;
}


// ── OCR ───────────────────────────────────────────────────────────────────────
async function runOcr(tabId, url) {
  try {
    const dataUrl   = await chrome.tabs.captureVisibleTab(null, { format: "png" });
    const base64    = dataUrl.split(",")[1];
    const res       = await fetch(OCR_API, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url, image_base64: base64 }),
      signal:  AbortSignal.timeout(20000),
    });
    if (!res.ok) return null;
    const ocrResult = await res.json();
    ocrResults.set(tabId, ocrResult);
    chrome.storage.local.set({ lastOcrResult: ocrResult });
    if (ocrResult.success && ocrResult.ocr_verdict === "MALICIOUS") {
      setBadge(tabId, "!", "#f43f5e");
      const urlResult = tabResults.get(tabId);
      if (urlResult && urlResult.verdict !== "MALICIOUS") {
        const syntheticResult = {
          verdict:    "MALICIOUS",
          score:      ocrResult.ocr_score,
          highlights: ocrResult.ocr_highlights || [],
        };
        sendBlockPage(tabId, syntheticResult, url);
        maybeNotify(url, syntheticResult, "Phishing phrases detected on this page.");
      }
    }
    return ocrResult;
  } catch { return null; }
}


// ── URL scan ──────────────────────────────────────────────────────────────────
async function scan(url) {
  const hit = fromCache(url);
  if (hit) return hit;
  try {
    const res = await fetch(API, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url }),
      signal:  AbortSignal.timeout(8000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const result = await res.json();
    urlCache.set(url, { result, ts: Date.now() });
    return result;
  } catch { return null; }
}


// ── Notification ──────────────────────────────────────────────────────────────
function maybeNotify(url, result, reason) {
  if (result?.verdict !== "MALICIOUS") return;
  const host = new URL(url).hostname;
  chrome.notifications.create(`linklens-${Date.now()}`, {
    type: "basic", iconUrl: "icon.svg",
    title: "LinkLens: Threat Detected",
    message: reason || `${host} scored ${result.score}/100 — appears malicious.`,
    priority: 2,
  });
}


// ── Tab lifecycle ─────────────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (!tab.url || !shouldScan(tab.url)) return;

  if (info.status === "loading") {
    setBadge(tabId, "…", "#64748b");
    tabResults.delete(tabId);
    ocrResults.delete(tabId);
    if (tab.url && shouldScan(tab.url)) {
      scan(tab.url).then(result => {
        if (result) {
          urlCache.set(tab.url, { result, ts: Date.now() });
          if (result.verdict === "MALICIOUS") {
            tabResults.set(tabId, result);
            applyBadge(tabId, result);
            chrome.storage.local.set({ lastURL: tab.url, lastResult: result });
            sendBlockPage(tabId, result, tab.url);
            maybeNotify(tab.url, result);
          }
        }
      });
    }
    return;
  }

  if (info.status !== "complete") return;

  const url    = tab.url;
  const cached = fromCache(url);

  if (cached) {
    tabResults.set(tabId, cached);
    applyBadge(tabId, cached);
    chrome.storage.local.set({ lastURL: url, lastResult: cached });
    if (cached.verdict === "MALICIOUS") sendBlockPage(tabId, cached, url);
  } else {
    const result = await scan(url);
    if (!result) { clearBadge(tabId); return; }
    tabResults.set(tabId, result);
    applyBadge(tabId, result);
    chrome.storage.local.set({ lastURL: url, lastResult: result });
    maybeNotify(url, result);
    if (result.verdict === "MALICIOUS") sendBlockPage(tabId, result, url);
  }

  // OCR for non-safe pages
  const urlResult = tabResults.get(tabId);
  if (urlResult && urlResult.verdict !== "SAFE") {
    setTimeout(() => runOcr(tabId, url), 1500);
  }

  // Inject QR detector into every page
  setTimeout(() => injectQrDetector(tabId), 1000);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId);
  ocrResults.delete(tabId);
  clearBadge(tabId);
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  const result = tabResults.get(tabId);
  if (result) applyBadge(tabId, result);
});


// ── Messages ──────────────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, reply) => {

  if (msg.type === "GET_TAB_RESULT") {
    reply({ result: tabResults.get(msg.tabId) || null });
    return true;
  }

  if (msg.type === "GET_OCR_RESULT") {
    reply({ result: ocrResults.get(msg.tabId) || null });
    return true;
  }

  if (msg.type === "SCAN") {
    scan(msg.url).then((result) => {
      if (result && msg.tabId) {
        tabResults.set(msg.tabId, result);
        applyBadge(msg.tabId, result);
        chrome.storage.local.set({ lastURL: msg.url, lastResult: result });
        if (result.verdict === "MALICIOUS") sendBlockPage(msg.tabId, result, msg.url);
        if (result.verdict !== "SAFE") setTimeout(() => runOcr(msg.tabId, msg.url), 1000);
      }
      reply({ result });
    });
    return true;
  }

  // QR code found on a webpage — scan its URL
  if (msg.type === "SCAN_QR_URL") {
    scan(msg.url).then((result) => {
      reply({ result });
      // If malicious QR on a page, upgrade the tab badge
      if (result?.verdict === "MALICIOUS" && sender.tab?.id) {
        setBadge(sender.tab.id, "!", "#f43f5e");
      }
    });
    return true;
  }

  // Malicious QR found on page — fire notification
  if (msg.type === "QR_THREAT_FOUND") {
    maybeNotify(msg.url, { verdict: "MALICIOUS", score: msg.score },
      `Malicious QR code found on this page — links to ${new URL(msg.url).hostname}`);
    return true;
  }

  // User clicked a QR badge — store URL for popup to pre-fill
  if (msg.type === "QR_BADGE_CLICK") {
    chrome.storage.local.set({ qrClickUrl: msg.url });
    return true;
  }
});