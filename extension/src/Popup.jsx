/**
 * Popup.jsx — LinkLens v1.1
 *
 * Opens → immediately shows current tab's result (fetched from background).
 * No manual action needed for the page you're on.
 * URL input still available for scanning any other URL.
 */

import { useEffect, useState, useCallback } from "react";

const API = "http://localhost:8000/analyze";

// ── Colour helpers ────────────────────────────────────────────────────────────
function verdictColor(v) {
  if (v === "MALICIOUS")  return "#f43f5e";
  if (v === "SUSPICIOUS") return "#f59e0b";
  if (v === "SAFE")       return "#22d3a4";
  return "#64748b";
}
function scoreColor(n) {
  if (n >= 70) return "#f43f5e";
  if (n >= 30) return "#f59e0b";
  return "#22d3a4";
}
function fmtDate(ts) {
  return new Date(ts).toLocaleDateString("en-GB", { day: "2-digit", month: "short" });
}

// ── Offline fallback ──────────────────────────────────────────────────────────
function localScore(url) {
  let s = 0;
  if (!url.startsWith("https://")) s += 20;
  if (/\d{1,3}(\.\d{1,3}){3}/.test(url)) s += 30;
  if (url.length > 75) s += 10;
  if (/login|secure|verify|banking|confirm|paypal|apple/i.test(url)) s += 15;
  if (/\.(tk|ml|ga|cf|gq|xyz|top|loan)/.test(url)) s += 25;
  s = Math.min(s, 100);
  const v = s >= 70 ? "MALICIOUS" : s >= 30 ? "SUSPICIOUS" : "SAFE";
  return {
    score: s, verdict: v, confidence: s / 100,
    highlights: ["Offline — backend unreachable. Pattern-based result only."],
    bars: [], offline: true,
  };
}

// ── Sub-components ────────────────────────────────────────────────────────────
function Bar({ label, value }) {
  const c = scoreColor(value);
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between",
                    fontSize: 11, color: "#94a3b8", marginBottom: 3 }}>
        <span>{label}</span>
        <span style={{ color: c, fontVariantNumeric: "tabular-nums" }}>{value}</span>
      </div>
      <div style={{ height: 6, borderRadius: 3, background: "rgba(255,255,255,0.06)" }}>
        <div style={{
          height: "100%", borderRadius: 3, width: `${value}%`,
          background: `linear-gradient(90deg,${c}66,${c})`,
          transition: "width .5s cubic-bezier(.22,1,.36,1)",
        }} />
      </div>
    </div>
  );
}

function Gauge({ score, verdict }) {
  const c = verdictColor(verdict);
  const r = 44, cx = 56, cy = 56;
  const circ = Math.PI * r;
  const fill = (score / 100) * circ;
  return (
    <div style={{ textAlign: "center" }}>
      <svg width="112" height="70" viewBox="0 0 112 70">
        <path d={`M 12,56 A ${r},${r} 0 0 1 100,56`}
          fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="10" strokeLinecap="round" />
        <path d={`M 12,56 A ${r},${r} 0 0 1 100,56`}
          fill="none" stroke={c} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${fill} ${circ}`}
          style={{ transition: "stroke-dasharray .6s cubic-bezier(.22,1,.36,1)" }} />
      </svg>
      <div style={{ marginTop: -8 }}>
        <div style={{ fontSize: 32, fontWeight: 700,
                      fontVariantNumeric: "tabular-nums", color: "#f8fafc" }}>
          {score}
        </div>
        <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: "0.1em",
                      color: c, marginTop: 2 }}>
          {verdict}
        </div>
      </div>
    </div>
  );
}

// ── Loading skeleton ──────────────────────────────────────────────────────────
function Scanning({ url }) {
  return (
    <div style={{ textAlign: "center", padding: "24px 0" }}>
      <div style={{
        width: 36, height: 36, borderRadius: "50%",
        border: "3px solid rgba(56,189,248,0.15)",
        borderTopColor: "#38bdf8",
        margin: "0 auto 12px",
        animation: "spin 0.8s linear infinite",
      }} />
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      <div style={{ fontSize: 12, color: "#475569" }}>Scanning</div>
      <div style={{ fontSize: 11, color: "#334155", fontFamily: "monospace",
                    marginTop: 4, maxWidth: 200, margin: "4px auto 0",
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {url.replace(/^https?:\/\//, "")}
      </div>
    </div>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────
export default function Popup() {
  const [tabId,    setTabId]    = useState(null);
  const [tabUrl,   setTabUrl]   = useState("");
  const [url,      setUrl]      = useState("");
  const [result,   setResult]   = useState(null);
  const [scanning, setScanning] = useState(false);
  const [online,   setOnline]   = useState(true);
  const [history,  setHistory]  = useState([]);
  // "tab" = showing current page result | "manual" = user typed a different URL
  const [mode,     setMode]     = useState("tab");

  // ── On mount: get current tab and its background result ───────────────────
  useEffect(() => {
    if (typeof chrome === "undefined") return;

    // Load history
    chrome.storage.local.get(["history"], (d) => {
      if (d.history) setHistory(d.history);
    });

    // Get active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs?.[0];
      if (!tab) return;

      const id  = tab.id;
      const raw = tab.url || "";
      setTabId(id);
      setTabUrl(raw);
      setUrl(raw);

      // Ask background for cached result for this tab
      chrome.runtime.sendMessage({ type: "GET_TAB_RESULT", tabId: id }, (res) => {
        if (res?.result) {
          setResult(res.result);
          setOnline(!res.result.offline);
        } else {
          // Not cached yet — trigger a scan
          triggerScan(raw, id);
        }
      });
    });
  }, []);

  // ── Scan via background (uses its cache + badge update) ───────────────────
  const triggerScan = useCallback(async (targetUrl, tid) => {
    const u = (targetUrl || url).trim();
    if (!u || !u.startsWith("http")) return;
    setScanning(true);

    if (typeof chrome !== "undefined" && chrome.runtime) {
      chrome.runtime.sendMessage(
        { type: "SCAN", url: u, tabId: tid ?? tabId },
        (res) => {
          setScanning(false);
          if (res?.result) {
            setResult(res.result);
            setOnline(!res.result.offline);
            pushHistory(u, res.result);
          } else {
            // API unreachable — local fallback
            const fb = localScore(u);
            setResult(fb);
            setOnline(false);
            pushHistory(u, fb);
          }
        }
      );
    } else {
      // Dev mode (no chrome runtime) — direct fetch
      try {
        const r = await fetch(API, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: u }),
          signal: AbortSignal.timeout(9000),
        });
        const data = await r.json();
        setResult(data);
        setOnline(true);
        pushHistory(u, data);
      } catch {
        const fb = localScore(u);
        setResult(fb);
        setOnline(false);
        pushHistory(u, fb);
      } finally {
        setScanning(false);
      }
    }
  }, [url, tabId]);

  // ── Manual scan from input ────────────────────────────────────────────────
  const handleScan = useCallback(() => {
    setMode("manual");
    triggerScan(url, tabId);
  }, [url, tabId, triggerScan]);

  // ── History push ──────────────────────────────────────────────────────────
  function pushHistory(u, r) {
    const item = {
      url: u.replace(/^https?:\/\//, "").slice(0, 36),
      ts: Date.now(),
      score: r.score,
      verdict: r.verdict,
    };
    setHistory(prev => {
      const next = [item, ...prev.slice(0, 14)];
      if (typeof chrome !== "undefined" && chrome.storage)
        chrome.storage.local.set({ history: next });
      return next;
    });
  }

  const vc = result ? verdictColor(result.verdict) : "#38bdf8";
  const isCurrentTab = mode === "tab";

  return (
    <div style={{
      width: 580, fontFamily: "'Inter', system-ui, sans-serif",
      background: "#0b1422", color: "#e2e8f0", userSelect: "none",
    }}>

      {/* ── Header ── */}
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "12px 16px",
        background: "linear-gradient(90deg,#0f1f33,#0b1a2e)",
        borderBottom: "1px solid rgba(56,189,248,0.12)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{
            width: 28, height: 28, borderRadius: 7,
            background: "linear-gradient(135deg,#38bdf8,#2dd4bf)",
            display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14,
          }}>🔍</div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700,
                          letterSpacing: "0.05em", color: "#f0f9ff" }}>LinkLens</div>
            <div style={{ fontSize: 10, color: "#475569", letterSpacing: "0.08em" }}>
              PHISHING DETECTOR
            </div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6,
                      fontSize: 11, color: online ? "#22d3a4" : "#f59e0b" }}>
          <div style={{
            width: 7, height: 7, borderRadius: "50%",
            background: online ? "#22d3a4" : "#f59e0b",
            boxShadow: `0 0 6px ${online ? "#22d3a4" : "#f59e0b"}`,
          }} />
          {online ? "API Online" : "Offline"}
        </div>
      </div>

      {/* ── URL bar — shows current tab URL, editable for manual scan ── */}
      <div style={{ padding: "12px 16px 0", display: "flex", gap: 8, alignItems: "center" }}>
        {/* Tab indicator pill */}
        {isCurrentTab && tabUrl && (
          <div style={{
            fontSize: 9, fontWeight: 600, padding: "2px 6px", borderRadius: 4,
            background: "rgba(56,189,248,0.12)", color: "#38bdf8",
            letterSpacing: "0.08em", flexShrink: 0, whiteSpace: "nowrap",
          }}>
            CURRENT TAB
          </div>
        )}
        <input
          value={url}
          onChange={e => { setUrl(e.target.value); setMode("manual"); }}
          onKeyDown={e => e.key === "Enter" && handleScan()}
          placeholder="Or paste any URL to scan…"
          disabled={scanning}
          style={{
            flex: 1, padding: "9px 12px",
            background: "rgba(255,255,255,0.05)",
            border: `1px solid ${isCurrentTab ? "rgba(56,189,248,0.3)" : "rgba(56,189,248,0.2)"}`,
            borderRadius: 8, color: "#e2e8f0",
            fontSize: 12, fontFamily: "monospace", outline: "none",
          }}
        />
        <button
          onClick={handleScan}
          disabled={scanning || !url.trim()}
          style={{
            padding: "9px 18px", borderRadius: 8, border: "none",
            background: scanning
              ? "rgba(56,189,248,0.2)"
              : "linear-gradient(90deg,#0ea5e9,#14b8a6)",
            color: "#fff", fontWeight: 600, fontSize: 13,
            cursor: scanning ? "not-allowed" : "pointer",
            letterSpacing: "0.04em", whiteSpace: "nowrap",
          }}
        >
          {scanning ? "Scanning…" : "Scan"}
        </button>
      </div>

      {/* ── Two-column body ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, padding: 16 }}>

        {/* ── Left: gauge + findings ── */}
        <div style={{
          background: "rgba(255,255,255,0.03)",
          border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 12, padding: 16,
        }}>
          {scanning ? (
            <Scanning url={url} />
          ) : result ? (
            <>
              <Gauge score={result.score} verdict={result.verdict} />
              <div style={{ height: 1, background: "rgba(255,255,255,0.06)", margin: "14px 0" }} />
              <div style={{ fontSize: 11, fontWeight: 600, color: "#64748b",
                            letterSpacing: "0.08em", marginBottom: 8 }}>FINDINGS</div>
              {result.highlights.map((h, i) => (
                <div key={i} style={{ display: "flex", gap: 8, alignItems: "flex-start",
                                      marginBottom: 6 }}>
                  <span style={{ color: vc, marginTop: 1, flexShrink: 0 }}>›</span>
                  <span style={{ fontSize: 12, color: "#94a3b8", lineHeight: 1.5 }}>{h}</span>
                </div>
              ))}
            </>
          ) : (
            <div style={{ textAlign: "center", padding: "28px 0", color: "#334155" }}>
              <div style={{ fontSize: 28, marginBottom: 8 }}>🔍</div>
              <div style={{ fontSize: 12 }}>Enter a URL above to scan</div>
            </div>
          )}
        </div>

        {/* ── Right: bars + history ── */}
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>

          {/* Risk signal bars */}
          <div style={{
            background: "rgba(255,255,255,0.03)",
            border: "1px solid rgba(255,255,255,0.07)",
            borderRadius: 12, padding: 16, flex: 1,
          }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: "#64748b",
                          letterSpacing: "0.08em", marginBottom: 12 }}>RISK SIGNALS</div>
            {result?.bars?.length ? (
              result.bars.map(b => <Bar key={b.label} label={b.label} value={b.value} />)
            ) : scanning ? (
              [1,2,3,4].map(i => (
                <div key={i} style={{ marginBottom: 12 }}>
                  <div style={{ height: 10, borderRadius: 4,
                                background: "rgba(255,255,255,0.04)", marginBottom: 6,
                                width: `${60 + i * 10}%` }} />
                  <div style={{ height: 6, borderRadius: 3,
                                background: "rgba(255,255,255,0.04)" }} />
                </div>
              ))
            ) : (
              <div style={{ color: "#334155", fontSize: 12,
                            paddingTop: 20, textAlign: "center" }}>No data yet</div>
            )}
          </div>

          {/* Scan history */}
          <div style={{
            background: "rgba(255,255,255,0.03)",
            border: "1px solid rgba(255,255,255,0.07)",
            borderRadius: 12, padding: 16,
          }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: "#64748b",
                          letterSpacing: "0.08em", marginBottom: 10 }}>RECENT SCANS</div>
            {history.length === 0 ? (
              <div style={{ color: "#334155", fontSize: 12 }}>No scans yet</div>
            ) : (
              <div style={{ maxHeight: 130, overflowY: "auto" }}>
                {history.map((h, i) => (
                  <div key={i} style={{
                    display: "flex", justifyContent: "space-between",
                    alignItems: "center", paddingBottom: 6, marginBottom: 6,
                    borderBottom: i < history.length - 1
                      ? "1px solid rgba(255,255,255,0.05)" : "none",
                  }}>
                    <div>
                      <div style={{ fontSize: 11, fontFamily: "monospace", color: "#cbd5e1",
                                    maxWidth: 140, overflow: "hidden",
                                    textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {h.url}
                      </div>
                      <div style={{ fontSize: 10, color: "#475569", marginTop: 1 }}>
                        {fmtDate(h.ts)}
                      </div>
                    </div>
                    <span style={{
                      fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 10,
                      background: `${verdictColor(h.verdict)}18`,
                      color: verdictColor(h.verdict),
                      border: `1px solid ${verdictColor(h.verdict)}30`,
                      letterSpacing: "0.06em",
                    }}>
                      {h.verdict}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

        </div>
      </div>

      {/* ── Footer ── */}
      <div style={{
        padding: "8px 16px", borderTop: "1px solid rgba(255,255,255,0.05)",
        display: "flex", justifyContent: "space-between",
        fontSize: 10, color: "#334155",
      }}>
        <span>LinkLens v1.1.0</span>
        <span>{result?.offline ? "Offline Mode" : "Live Analysis"} · ML-Powered</span>
      </div>

    </div>
  );
}