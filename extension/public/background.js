/**
 * background.js — LinkLens Service Worker
 *
 * Responsibilities:
 *  1. Auto-scan every tab that finishes loading
 *  2. Cache results (5 min) to avoid duplicate API calls
 *  3. Fire a Chrome notification when a MALICIOUS page is detected
 *  4. Respond to messages from the popup (manual scan requests)
 */

const API = "http://localhost:8000/analyze";
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes in ms

// Simple in-memory cache:  url → { result, ts }
const cache = new Map();

function cached(url) {
  const entry = cache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL) { cache.delete(url); return null; }
  return entry.result;
}

async function scan(url) {
  // Skip internal / extension pages
  if (!url || !url.startsWith("http")) return null;
  if (url.includes("localhost") || url.includes("127.0.0.1")) return null;

  const hit = cached(url);
  if (hit) return hit;

  try {
    const res = await fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const result = await res.json();
    cache.set(url, { result, ts: Date.now() });
    chrome.storage.local.set({ lastURL: url, lastResult: result });
    return result;
  } catch {
    return null; // Popup handles the offline fallback itself
  }
}

function notify(url, result) {
  if (result?.verdict !== "MALICIOUS") return;
  const host = new URL(url).hostname;
  chrome.notifications.create({
    type: "basic",
    iconUrl: "icon.svg",
    title: "⚠️ LinkLens: Threat Detected",
    message: `${host} scored ${result.score}/100 and appears malicious.`,
    priority: 2,
  });
}

// Auto-scan on every page load
chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.status !== "complete" || !tab.url) return;
  const result = await scan(tab.url);
  if (result) notify(tab.url, result);
});

// Respond to popup scan requests
chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg.type !== "SCAN") return;
  scan(msg.url).then((result) => reply({ result }));
  return true; // keep port open for async reply
});
