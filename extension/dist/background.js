/**
 * background.js — LinkLens Service Worker v1.6
 *
 * Changes from v1.5:
 *  - After OCR and DOM checks complete, re-calls /analyze with all scores
 *  - Final combined result replaces the initial URL-only result per tab
 *  - Popup gets notified to refresh via RESULT_UPDATED message
 */

const API      = "http://localhost:8000/analyze";
const OCR_API  = "http://localhost:8000/analyze-page";
const PAGE_API = "http://localhost:8000/check-page";
const CACHE_TTL = 5 * 60 * 1000;

const urlCache    = new Map();
const tabResults  = new Map();
const ocrResults  = new Map();
const pageResults = new Map();


// ── Badge ─────────────────────────────────────────────────────────────────────
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
  else { setBadge(tabId, "✓", "#22d3a4"); setTimeout(() => clearBadge(tabId), 3000); }
}


// ── Block page ────────────────────────────────────────────────────────────────
function sendBlockPage(tabId, result, url) {
  if (result?.verdict !== "MALICIOUS") return;
  const msg = {
    type: "BLOCK_PAGE", score: result.score, url,
    highlights: result.highlights || result.page_highlights || [],
  };
  chrome.tabs.sendMessage(tabId, msg).catch(() => {
    chrome.scripting.executeScript({ target: { tabId }, files: ["content.js"] })
      .then(() => setTimeout(() =>
        chrome.tabs.sendMessage(tabId, msg).catch(() => {}), 100))
      .catch(() => {});
  });
}


// ── QR detector ───────────────────────────────────────────────────────────────
async function injectQrDetector(tabId) {
  try {
    await chrome.scripting.executeScript({ target: { tabId }, files: ["jsqr.min.js"] });
    await chrome.scripting.executeScript({ target: { tabId }, files: ["qr_detector.js"] });
  } catch {}
}


// ── Helpers ───────────────────────────────────────────────────────────────────
function shouldScan(url) {
  if (!url || !url.startsWith("http")) return false;
  if (url.includes("localhost") || url.includes("127.0.0.1")) return false;
  return true;
}
function fromCache(url) {
  const entry = urlCache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL) { urlCache.delete(url); return null; }
  return entry.result;
}
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


// ── Re-analyze with all layer scores ─────────────────────────────────────────
async function reAnalyzeWithAllLayers(tabId, url) {
  const ocr  = ocrResults.get(tabId);
  const page = pageResults.get(tabId);

  const ocr_score = (ocr?.success && ocr?.ocr_score  >= 0) ? ocr.ocr_score  : -1;
  const dom_score = (page?.success && page?.page_score >= 0) ? page.page_score : -1;

  if (ocr_score < 0 && dom_score < 0) return;

  try {
    const res = await fetch(API, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url, ocr_score, dom_score }),
      signal:  AbortSignal.timeout(8000),
    });
    if (!res.ok) return;
    const combined = await res.json();

    // Update stored result
    tabResults.set(tabId, combined);
    urlCache.set(url, { result: combined, ts: Date.now() });
    applyBadge(tabId, combined);
    chrome.storage.local.set({ lastResult: combined });

    // If combined verdict is MALICIOUS and initial wasn't — block now
    const initial = tabResults.get(tabId);
    if (combined.verdict === "MALICIOUS") {
      sendBlockPage(tabId, combined, url);
      if (initial?.verdict !== "MALICIOUS") {
        maybeNotify(url, combined, `Combined analysis flagged ${new URL(url).hostname}`);
      }
    }

    // Notify popup to refresh its display
    chrome.tabs.sendMessage(tabId, {
      type: "RESULT_UPDATED", result: combined
    }).catch(() => {});

  } catch {}
}


// ── OCR ───────────────────────────────────────────────────────────────────────
async function runOcr(tabId, url) {
  try {
    const dataUrl = await chrome.tabs.captureVisibleTab(null, { format: "png" });
    const base64  = dataUrl.split(",")[1];
    const res     = await fetch(OCR_API, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, image_base64: base64 }),
      signal: AbortSignal.timeout(20000),
    });
    if (!res.ok) return null;
    const ocrResult = await res.json();
    ocrResults.set(tabId, ocrResult);
    chrome.storage.local.set({ lastOcrResult: ocrResult });
    // Re-analyze with combined scores
    await reAnalyzeWithAllLayers(tabId, url);
    return ocrResult;
  } catch { return null; }
}


// ── DOM check ─────────────────────────────────────────────────────────────────
async function runPageCheck(tabId, url) {
  try {
    const res = await fetch(PAGE_API, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return null;
    const pageResult = await res.json();
    pageResults.set(tabId, pageResult);
    chrome.storage.local.set({ lastPageResult: pageResult });
    // Re-analyze with combined scores
    await reAnalyzeWithAllLayers(tabId, url);
    return pageResult;
  } catch { return null; }
}


// ── URL scan ──────────────────────────────────────────────────────────────────
async function scan(url) {
  const hit = fromCache(url);
  if (hit) return hit;
  try {
    const res = await fetch(API, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const result = await res.json();
    urlCache.set(url, { result, ts: Date.now() });
    return result;
  } catch { return null; }
}


// ── Tab lifecycle ─────────────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (!tab.url || !shouldScan(tab.url)) return;

  if (info.status === "loading") {
    setBadge(tabId, "…", "#64748b");
    tabResults.delete(tabId);
    ocrResults.delete(tabId);
    pageResults.delete(tabId);
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

  const urlResult = tabResults.get(tabId);
  if (urlResult && urlResult.verdict !== "SAFE") {
    setTimeout(() => runOcr(tabId, url), 1500);
    setTimeout(() => runPageCheck(tabId, url), 2000);
  }

  setTimeout(() => injectQrDetector(tabId), 1000);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId); ocrResults.delete(tabId);
  pageResults.delete(tabId); clearBadge(tabId);
});
chrome.tabs.onActivated.addListener(({ tabId }) => {
  const result = tabResults.get(tabId);
  if (result) applyBadge(tabId, result);
});


// ── Messages ──────────────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === "GET_TAB_RESULT") {
    reply({ result: tabResults.get(msg.tabId) || null }); return true;
  }
  if (msg.type === "GET_OCR_RESULT") {
    reply({ result: ocrResults.get(msg.tabId) || null }); return true;
  }
  if (msg.type === "GET_PAGE_RESULT") {
    reply({ result: pageResults.get(msg.tabId) || null }); return true;
  }
  if (msg.type === "SCAN") {
    scan(msg.url).then(async (result) => {
      if (result && msg.tabId) {
        tabResults.set(msg.tabId, result);
        applyBadge(msg.tabId, result);
        chrome.storage.local.set({ lastURL: msg.url, lastResult: result });
        if (result.verdict === "MALICIOUS") sendBlockPage(msg.tabId, result, msg.url);
        if (result.verdict !== "SAFE") {
          setTimeout(() => runOcr(msg.tabId, msg.url), 1000);
          setTimeout(() => runPageCheck(msg.tabId, msg.url), 1500);
        }
      }
      reply({ result });
    });
    return true;
  }
  if (msg.type === "SCAN_QR_URL") {
    scan(msg.url).then((result) => {
      reply({ result });
      if (result?.verdict === "MALICIOUS" && sender.tab?.id)
        setBadge(sender.tab.id, "!", "#f43f5e");
    });
    return true;
  }
  if (msg.type === "QR_THREAT_FOUND") {
    maybeNotify(msg.url, { verdict: "MALICIOUS", score: msg.score },
      `Malicious QR code found on this page — links to ${new URL(msg.url).hostname}`);
    return true;
  }
  if (msg.type === "QR_BADGE_CLICK") {
    chrome.storage.local.set({ qrClickUrl: msg.url }); return true;
  }
});