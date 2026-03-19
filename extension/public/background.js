const API      = "http://localhost:8000/analyze";
const CACHE_TTL = 5 * 60 * 1000;

const urlCache   = new Map();
const tabResults = new Map();

function setBadge(tabId, text, color) {
  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
}
function clearBadge(tabId) {
  chrome.action.setBadgeText({ text: "", tabId });
}
function applyBadge(tabId, result) {
  if (!result) { clearBadge(tabId); return; }
  if (result.verdict === "MALICIOUS")  setBadge(tabId, "!", "#f43f5e");
  else if (result.verdict === "SUSPICIOUS") setBadge(tabId, "?", "#f59e0b");
  else { setBadge(tabId, "✓", "#22d3a4"); setTimeout(() => clearBadge(tabId), 3000); }
}

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

async function scan(url) {
  const hit = fromCache(url);
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
    urlCache.set(url, { result, ts: Date.now() });
    return result;
  } catch { return null; }
}

function maybeNotify(url, result) {
  if (result?.verdict !== "MALICIOUS") return;
  const host = new URL(url).hostname;
  chrome.notifications.create(`linklens-${Date.now()}`, {
    type: "basic", iconUrl: "icon.svg",
    title: "LinkLens: Threat Detected",
    message: `${host} scored ${result.score}/100 — this site appears malicious.`,
    priority: 2,
  });
}

chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (!tab.url || !shouldScan(tab.url)) return;
  if (info.status === "loading") {
    setBadge(tabId, "…", "#64748b");
    tabResults.delete(tabId);
    return;
  }
  if (info.status !== "complete") return;

  const cached = fromCache(tab.url);
  if (cached) {
    tabResults.set(tabId, cached);
    applyBadge(tabId, cached);
    chrome.storage.local.set({ lastURL: tab.url, lastResult: cached });
    return;
  }
  const result = await scan(tab.url);
  if (!result) { clearBadge(tabId); return; }
  tabResults.set(tabId, result);
  applyBadge(tabId, result);
  chrome.storage.local.set({ lastURL: tab.url, lastResult: result });
  maybeNotify(tab.url, result);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId);
  clearBadge(tabId);
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  const result = tabResults.get(tabId);
  if (result) applyBadge(tabId, result);
});

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg.type === "GET_TAB_RESULT") {
    reply({ result: tabResults.get(msg.tabId) || null });
    return true;
  }
  if (msg.type === "SCAN") {
    scan(msg.url).then((result) => {
      if (result && msg.tabId) {
        tabResults.set(msg.tabId, result);
        applyBadge(msg.tabId, result);
        chrome.storage.local.set({ lastURL: msg.url, lastResult: result });
      }
      reply({ result });
    });
    return true;
  }
});