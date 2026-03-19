/**
 * background.js — LinkLens Service Worker v1.2
 *
 * Changes from v1.1:
 *  - After every URL scan completes, captures a screenshot of the tab
 *    using chrome.tabs.captureVisibleTab() and sends it to /analyze-page
 *  - OCR result stored separately in chrome.storage as lastOcrResult
 *  - Only captures screenshot for SUSPICIOUS or MALICIOUS verdicts
 *    (no point running OCR on known-safe trusted domains)
 *  - GET_OCR_RESULT message type added so popup can read OCR findings
 */

const API      = "http://localhost:8000/analyze";
const OCR_API  = "http://localhost:8000/analyze-page";
const CACHE_TTL = 5 * 60 * 1000;

const urlCache  = new Map();
const tabResults = new Map();
const ocrResults = new Map();   // tabId → ocr result


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


// ── Filters ───────────────────────────────────────────────────────────────────
function shouldScan(url) {
  if (!url || !url.startsWith("http")) return false;
  if (url.includes("localhost") || url.includes("127.0.0.1")) return false;
  return true;
}


// ── URL cache ─────────────────────────────────────────────────────────────────
function fromCache(url) {
  const entry = urlCache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL) { urlCache.delete(url); return null; }
  return entry.result;
}


// ── Screenshot + OCR ──────────────────────────────────────────────────────────
async function runOcr(tabId, url) {
  try {
    // Capture the visible tab as a base64 PNG
    const dataUrl    = await chrome.tabs.captureVisibleTab(null, { format: "png" });
    const base64     = dataUrl.split(",")[1];

    const res  = await fetch(OCR_API, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url, image_base64: base64 }),
      signal:  AbortSignal.timeout(20000),
    });

    if (!res.ok) return null;
    const ocrResult = await res.json();

    // Store per-tab and persist to storage
    ocrResults.set(tabId, ocrResult);
    chrome.storage.local.set({ lastOcrResult: ocrResult });

    // If OCR finds something bad on a page that URL analysis rated OK, upgrade badge
    if (ocrResult.success && ocrResult.ocr_verdict === "MALICIOUS") {
      setBadge(tabId, "!", "#f43f5e");
      const urlResult = tabResults.get(tabId);
      if (urlResult && urlResult.verdict !== "MALICIOUS") {
        maybeNotify(url, { verdict: "MALICIOUS", score: ocrResult.ocr_score },
          "Page content contains phishing phrases.");
      }
    }

    return ocrResult;
  } catch {
    return null;
  }
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
  const msg  = reason || `${host} scored ${result.score}/100 — appears malicious.`;
  chrome.notifications.create(`linklens-${Date.now()}`, {
    type: "basic", iconUrl: "icon.svg",
    title: "LinkLens: Threat Detected",
    message: msg, priority: 2,
  });
}


// ── Tab lifecycle ─────────────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (!tab.url || !shouldScan(tab.url)) return;

  if (info.status === "loading") {
    setBadge(tabId, "…", "#64748b");
    tabResults.delete(tabId);
    ocrResults.delete(tabId);
    return;
  }

  if (info.status !== "complete") return;

  const url    = tab.url;
  const cached = fromCache(url);

  if (cached) {
    tabResults.set(tabId, cached);
    applyBadge(tabId, cached);
    chrome.storage.local.set({ lastURL: url, lastResult: cached });
  } else {
    const result = await scan(url);
    if (!result) { clearBadge(tabId); return; }
    tabResults.set(tabId, result);
    applyBadge(tabId, result);
    chrome.storage.local.set({ lastURL: url, lastResult: result });
    maybeNotify(url, result);
  }

  // Run OCR only for non-trusted, non-safe pages
  const urlResult = tabResults.get(tabId);
  if (urlResult && urlResult.verdict !== "SAFE") {
    // Small delay to let the page fully render before screenshotting
    setTimeout(() => runOcr(tabId, url), 1500);
  }
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


// ── Message handler ───────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, _sender, reply) => {

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
        // Manual scans also trigger OCR if suspicious/malicious
        if (result.verdict !== "SAFE") {
          setTimeout(() => runOcr(msg.tabId, msg.url), 1000);
        }
      }
      reply({ result });
    });
    return true;
  }
});