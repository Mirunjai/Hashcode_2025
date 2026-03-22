/**
 * Popup.jsx — LinkLens v1.6
 *
 * Changes from v1.5:
 *  - New 4-layer scoreboard replacing the old single gauge
 *  - Shows URL, OCR, DOM, and WHOIS as separate scored rows
 *  - Combined score computed server-side from all layers
 *  - Listens for RESULT_UPDATED message from background
 *  - WHOIS status shown explicitly (working/failed/age)
 */

import { useEffect, useState, useCallback } from "react";

const API    = "http://localhost:8000/analyze";
const QR_API = "http://localhost:8000/decode-qr";

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
function localScore(url) {
  let s = 0;
  if (!url.startsWith("https://")) s += 20;
  if (/\d{1,3}(\.\d{1,3}){3}/.test(url)) s += 30;
  if (url.length > 75) s += 10;
  if (/login|secure|verify|banking|confirm|paypal|apple/i.test(url)) s += 15;
  if (/\.(tk|ml|ga|cf|gq|xyz|top|loan)/.test(url)) s += 25;
  s = Math.min(s, 100);
  const v = s >= 70 ? "MALICIOUS" : s >= 30 ? "SUSPICIOUS" : "SAFE";
  return { score: s, verdict: v, confidence: s / 100,
           highlights: ["Offline — backend unreachable. Pattern-based result only."],
           bars: [], offline: true };
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
        <div style={{ height: "100%", borderRadius: 3, width: `${value}%`,
                      background: `linear-gradient(90deg,${c}66,${c})`,
                      transition: "width .5s cubic-bezier(.22,1,.36,1)" }} />
      </div>
    </div>
  );
}

function Scanning({ url }) {
  return (
    <div style={{ textAlign: "center", padding: "24px 0" }}>
      <div style={{ width: 36, height: 36, borderRadius: "50%",
                    border: "3px solid rgba(56,189,248,0.15)",
                    borderTopColor: "#38bdf8", margin: "0 auto 12px",
                    animation: "spin 0.8s linear infinite" }} />
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

// ── 4-layer scoreboard ────────────────────────────────────────────────────────
function Scoreboard({ result, ocrResult, pageResult }) {
  if (!result) return null;

  const layers = result.layers || {};
  const whois  = result.whois  || {};

  // Final combined score — big gauge
  const vc    = verdictColor(result.verdict);
  const r     = 44, circ = Math.PI * r;
  const fill  = (result.score / 100) * circ;

  // Layer rows
  const rows = [
    {
      key:     "url",
      label:   "URL Analysis",
      icon:    "🔗",
      score:   layers.url?.score ?? result.url_score ?? result.score,
      verdict: layers.url?.verdict ?? result.verdict,
      weight:  "60%",
      detail:  result.highlights?.[0] || "",
    },
    {
      key:     "ocr",
      label:   "Page Content (OCR)",
      icon:    "👁",
      score:   ocrResult?.ocr_score ?? layers.ocr?.score,
      verdict: ocrResult?.ocr_verdict ?? layers.ocr?.verdict ?? "PENDING",
      weight:  "25%",
      detail:  ocrResult?.ocr_highlights?.[0] || (ocrResult ? "" : "Scanning…"),
    },
    {
      key:     "dom",
      label:   "Page Structure (DOM)",
      icon:    "🏗",
      score:   pageResult?.page_score ?? layers.dom?.score,
      verdict: pageResult?.page_verdict ?? layers.dom?.verdict ?? "PENDING",
      weight:  "15%",
      detail:  pageResult?.page_highlights?.[0] || (pageResult ? "" : "Checking…"),
    },
  ];

  return (
    <div>
      {/* Combined score gauge */}
      <div style={{ display: "flex", alignItems: "center", gap: 16,
                    paddingBottom: 14, borderBottom: "1px solid rgba(255,255,255,0.06)",
                    marginBottom: 14 }}>
        <div style={{ textAlign: "center", flexShrink: 0 }}>
          <svg width="90" height="56" viewBox="0 0 112 70">
            <path d={`M 12,56 A ${r},${r} 0 0 1 100,56`}
              fill="none" stroke="rgba(255,255,255,0.07)"
              strokeWidth="10" strokeLinecap="round" />
            <path d={`M 12,56 A ${r},${r} 0 0 1 100,56`}
              fill="none" stroke={vc} strokeWidth="10" strokeLinecap="round"
              strokeDasharray={`${fill} ${circ}`}
              style={{ transition: "stroke-dasharray .6s cubic-bezier(.22,1,.36,1)" }} />
          </svg>
          <div style={{ marginTop: -6 }}>
            <div style={{ fontSize: 26, fontWeight: 700, color: "#f8fafc",
                          fontVariantNumeric: "tabular-nums" }}>{result.score}</div>
            <div style={{ fontSize: 11, fontWeight: 700, color: vc,
                          letterSpacing: "0.1em" }}>{result.verdict}</div>
          </div>
        </div>

        {/* WHOIS status */}
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 10, fontWeight: 600, color: "#475569",
                        letterSpacing: "0.08em", marginBottom: 6 }}>DOMAIN INFO</div>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{
              width: 7, height: 7, borderRadius: "50%", flexShrink: 0,
              background: whois.status === "old"     ? "#22d3a4"
                        : whois.status === "trusted" ? "#38bdf8"
                        : whois.status === "failed"  ? "#64748b"
                        : whois.status === "new"     ? "#f43f5e"
                        : "#f59e0b",
            }} />
            <span style={{ fontSize: 11, color: "#94a3b8", lineHeight: 1.4 }}>
              {whois.label || "WHOIS unknown"}
            </span>
          </div>
          {result.confidence !== undefined && (
            <div style={{ marginTop: 6, fontSize: 10, color: "#475569" }}>
              ML confidence: {Math.round(result.confidence * 100)}%
              {result.ocr_applied || result.dom_applied
                ? " · Combined score"
                : " · URL score only"}
            </div>
          )}
        </div>
      </div>

      {/* Layer rows */}
      <div style={{ fontSize: 10, fontWeight: 600, color: "#475569",
                    letterSpacing: "0.08em", marginBottom: 8 }}>
        DETECTION LAYERS
      </div>
      {rows.map(row => {
        const hasScore  = row.score !== null && row.score !== undefined;
        const isPending = row.verdict === "PENDING" || row.verdict === "UNKNOWN";
        const c = isPending ? "#475569" : verdictColor(row.verdict);
        const bgc = isPending ? "rgba(71,85,105,0.08)"
                  : row.verdict === "MALICIOUS"  ? "rgba(244,63,94,0.06)"
                  : row.verdict === "SUSPICIOUS" ? "rgba(245,158,11,0.06)"
                  : "rgba(34,211,164,0.06)";
        return (
          <div key={row.key} style={{ display: "flex", gap: 10, alignItems: "flex-start",
                                      padding: "8px 10px", borderRadius: 8,
                                      background: bgc, marginBottom: 6,
                                      border: `1px solid ${c}22` }}>
            <span style={{ fontSize: 14, flexShrink: 0, marginTop: 1 }}>{row.icon}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: "flex", justifyContent: "space-between",
                            alignItems: "center", marginBottom: 3 }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: "#cbd5e1" }}>
                  {row.label}
                </span>
                <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                  <span style={{ fontSize: 9, color: "#475569" }}>{row.weight}</span>
                  <span style={{ fontSize: 10, fontWeight: 700, padding: "1px 7px",
                                 borderRadius: 10, background: `${c}18`, color: c,
                                 border: `1px solid ${c}30`, letterSpacing: "0.06em",
                                 whiteSpace: "nowrap" }}>
                    {isPending ? "…" : `${row.verdict} · ${hasScore ? row.score : "?"}`}
                  </span>
                </div>
              </div>
              {row.detail && (
                <div style={{ fontSize: 10, color: "#64748b", lineHeight: 1.4,
                              overflow: "hidden", textOverflow: "ellipsis",
                              whiteSpace: "nowrap" }}>
                  {row.detail}
                </div>
              )}
            </div>
          </div>
        );
      })}

      {/* QR decoded URL badge */}
      {result.qr_url && (
        <div style={{ marginTop: 8, padding: "6px 10px", borderRadius: 6,
                      background: "rgba(56,189,248,0.08)",
                      border: "1px solid rgba(56,189,248,0.2)",
                      fontSize: 10, color: "#38bdf8", fontFamily: "monospace",
                      wordBreak: "break-all" }}>
          QR → {result.qr_url}
        </div>
      )}
    </div>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────
export default function Popup() {
  const [tabId,       setTabId]       = useState(null);
  const [tabUrl,      setTabUrl]      = useState("");
  const [url,         setUrl]         = useState("");
  const [result,      setResult]      = useState(null);
  const [ocrResult,   setOcrResult]   = useState(null);
  const [pageResult,  setPageResult]  = useState(null);
  const [scanning,    setScanning]    = useState(false);
  const [online,      setOnline]      = useState(true);
  const [history,     setHistory]     = useState([]);
  const [mode,        setMode]        = useState("tab");
  const [qrScanning,  setQrScanning]  = useState(false);
  const [qrError,     setQrError]     = useState("");

  useEffect(() => {
    if (typeof chrome === "undefined") return;
    chrome.storage.local.get(["history"], (d) => {
      if (d.history) setHistory(d.history);
    });
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs?.[0];
      if (!tab) return;
      setTabId(tab.id);
      setTabUrl(tab.url || "");
      setUrl(tab.url || "");
      chrome.runtime.sendMessage({ type: "GET_TAB_RESULT",  tabId: tab.id },
        (res) => { if (res?.result) { setResult(res.result); setOnline(!res.result.offline); }
                   else triggerScan(tab.url, tab.id); });
      chrome.runtime.sendMessage({ type: "GET_OCR_RESULT",  tabId: tab.id },
        (res) => { if (res?.result) setOcrResult(res.result); });
      chrome.runtime.sendMessage({ type: "GET_PAGE_RESULT", tabId: tab.id },
        (res) => { if (res?.result) setPageResult(res.result); });
    });

    // Listen for background pushing a combined result update
    const handler = (msg) => {
      if (msg.type === "RESULT_UPDATED" && msg.result) {
        setResult(msg.result);
        setOnline(!msg.result.offline);
      }
    };
    chrome.runtime.onMessage.addListener(handler);
    return () => chrome.runtime.onMessage.removeListener(handler);
  }, []);

  const triggerScan = useCallback((targetUrl, tid) => {
    const u = (targetUrl || "").trim();
    if (!u || !u.startsWith("http")) return;
    setScanning(true);
    setOcrResult(null);
    setPageResult(null);
    chrome.runtime.sendMessage({ type: "SCAN", url: u, tabId: tid }, (res) => {
      setScanning(false);
      const r = res?.result || localScore(u);
      setResult(r);
      setOnline(!r.offline);
      if (r.verdict !== "SAFE") {
        setTimeout(() => {
          chrome.runtime.sendMessage({ type: "GET_OCR_RESULT",  tabId: tid },
            (ocr) => { if (ocr?.result) setOcrResult(ocr.result); });
          chrome.runtime.sendMessage({ type: "GET_PAGE_RESULT", tabId: tid },
            (pg)  => { if (pg?.result)  setPageResult(pg.result); });
        }, 5000);
      }
    });
  }, []);

  const handleScan = useCallback(() => {
    setMode("manual"); setQrError("");
    triggerScan(url, tabId);
  }, [url, tabId, triggerScan]);

  async function handleQRUpload(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    setQrScanning(true); setQrError("");
    const reader = new FileReader();
    reader.onload = async (ev) => {
      try {
        const base64 = ev.target.result.split(",")[1];
        const res    = await fetch(QR_API, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ image_base64: base64 }),
          signal: AbortSignal.timeout(12000),
        });
        const data = await res.json();
        if (!data.success) { setQrError(data.error || "QR decode failed."); }
        else { setUrl(data.qr_url); setResult(data); setOnline(true);
               setMode("manual"); pushHistory(data.qr_url, data); }
      } catch { setQrError("QR scan failed — is the backend running?"); }
      finally { setQrScanning(false); e.target.value = ""; }
    };
    reader.readAsDataURL(file);
  }

  function pushHistory(u, r) {
    const item = { url: u.replace(/^https?:\/\//, "").slice(0, 36),
                   ts: Date.now(), score: r.score, verdict: r.verdict };
    setHistory(prev => {
      const next = [item, ...prev.slice(0, 14)];
      if (typeof chrome !== "undefined" && chrome.storage)
        chrome.storage.local.set({ history: next });
      return next;
    });
  }

  const isCurrentTab = mode === "tab";

  return (
    <div style={{ width: 580, fontFamily: "'Inter', system-ui, sans-serif",
                  background: "#0b1422", color: "#e2e8f0", userSelect: "none" }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between",
                    padding: "12px 16px",
                    background: "linear-gradient(90deg,#0f1f33,#0b1a2e)",
                    borderBottom: "1px solid rgba(56,189,248,0.12)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 28, height: 28, borderRadius: 7,
                        background: "linear-gradient(135deg,#38bdf8,#2dd4bf)",
                        display: "flex", alignItems: "center",
                        justifyContent: "center", fontSize: 14 }}>🔍</div>
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
          <div style={{ width: 7, height: 7, borderRadius: "50%",
                        background: online ? "#22d3a4" : "#f59e0b",
                        boxShadow: `0 0 6px ${online ? "#22d3a4" : "#f59e0b"}` }} />
          {online ? "API Online" : "Offline"}
        </div>
      </div>

      {/* Scan bar */}
      <div style={{ padding: "12px 16px 0", display: "flex", gap: 8, alignItems: "center" }}>
        {isCurrentTab && tabUrl && (
          <div style={{ fontSize: 9, fontWeight: 600, padding: "2px 6px", borderRadius: 4,
                        background: "rgba(56,189,248,0.12)", color: "#38bdf8",
                        letterSpacing: "0.08em", flexShrink: 0, whiteSpace: "nowrap" }}>
            CURRENT TAB
          </div>
        )}
        <input value={url}
          onChange={e => { setUrl(e.target.value); setMode("manual"); }}
          onKeyDown={e => e.key === "Enter" && handleScan()}
          placeholder="Paste a URL to scan…"
          disabled={scanning || qrScanning}
          style={{ flex: 1, padding: "9px 12px",
                   background: "rgba(255,255,255,0.05)",
                   border: `1px solid ${isCurrentTab ? "rgba(56,189,248,0.3)" : "rgba(56,189,248,0.2)"}`,
                   borderRadius: 8, color: "#e2e8f0",
                   fontSize: 12, fontFamily: "monospace", outline: "none" }} />
        <button onClick={handleScan}
          disabled={scanning || qrScanning || !url.trim()}
          style={{ padding: "9px 18px", borderRadius: 8, border: "none",
                   background: scanning ? "rgba(56,189,248,0.2)"
                                        : "linear-gradient(90deg,#0ea5e9,#14b8a6)",
                   color: "#fff", fontWeight: 600, fontSize: 13,
                   cursor: (scanning || qrScanning) ? "not-allowed" : "pointer",
                   letterSpacing: "0.04em", whiteSpace: "nowrap" }}>
          {scanning ? "Scanning…" : "Scan"}
        </button>
        <label title="Upload a QR code image"
          style={{ padding: "9px 12px", borderRadius: 8,
                   cursor: qrScanning ? "not-allowed" : "pointer",
                   background: qrScanning ? "rgba(56,189,248,0.2)" : "rgba(255,255,255,0.05)",
                   border: "1px solid rgba(56,189,248,0.2)",
                   color: qrScanning ? "#38bdf8" : "#94a3b8",
                   fontSize: 12, whiteSpace: "nowrap",
                   display: "flex", alignItems: "center", gap: 5 }}>
          <span style={{ fontSize: 14 }}>⬡</span>
          {qrScanning ? "Reading…" : "QR"}
          <input type="file" accept="image/*" style={{ display: "none" }}
            onChange={handleQRUpload} disabled={qrScanning || scanning} />
        </label>
      </div>

      {qrError && (
        <div style={{ margin: "6px 16px 0", padding: "7px 12px", borderRadius: 8,
                      background: "rgba(244,63,94,0.08)",
                      border: "1px solid rgba(244,63,94,0.25)",
                      fontSize: 11, color: "#f43f5e" }}>{qrError}</div>
      )}

      {/* Two-column body */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, padding: 16 }}>

        {/* Left: scoreboard */}
        <div style={{ background: "rgba(255,255,255,0.03)",
                      border: "1px solid rgba(255,255,255,0.07)",
                      borderRadius: 12, padding: 16 }}>
          {(scanning || qrScanning) ? (
            <Scanning url={url} />
          ) : result ? (
            <Scoreboard
              result={result}
              ocrResult={ocrResult}
              pageResult={pageResult}
            />
          ) : (
            <div style={{ textAlign: "center", padding: "28px 0", color: "#334155" }}>
              <div style={{ fontSize: 28, marginBottom: 8 }}>🔍</div>
              <div style={{ fontSize: 12 }}>Enter a URL or upload a QR image</div>
            </div>
          )}
        </div>

        {/* Right: risk signal bars + history */}
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={{ background: "rgba(255,255,255,0.03)",
                        border: "1px solid rgba(255,255,255,0.07)",
                        borderRadius: 12, padding: 16, flex: 1 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: "#64748b",
                          letterSpacing: "0.08em", marginBottom: 12 }}>RISK SIGNALS</div>
            {result?.bars?.length ? (
              result.bars.map(b => <Bar key={b.label} label={b.label} value={b.value} />)
            ) : (scanning || qrScanning) ? (
              [1,2,3,4].map(i => (
                <div key={i} style={{ marginBottom: 12 }}>
                  <div style={{ height: 10, borderRadius: 4, marginBottom: 6,
                                background: "rgba(255,255,255,0.04)",
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

          <div style={{ background: "rgba(255,255,255,0.03)",
                        border: "1px solid rgba(255,255,255,0.07)",
                        borderRadius: 12, padding: 16 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: "#64748b",
                          letterSpacing: "0.08em", marginBottom: 10 }}>RECENT SCANS</div>
            {history.length === 0 ? (
              <div style={{ color: "#334155", fontSize: 12 }}>No scans yet</div>
            ) : (
              <div style={{ maxHeight: 130, overflowY: "auto" }}>
                {history.map((h, i) => (
                  <div key={i} style={{ display: "flex", justifyContent: "space-between",
                                        alignItems: "center", paddingBottom: 6, marginBottom: 6,
                                        borderBottom: i < history.length - 1
                                          ? "1px solid rgba(255,255,255,0.05)" : "none" }}>
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
                    <span style={{ fontSize: 10, fontWeight: 700, padding: "2px 8px",
                                   borderRadius: 10,
                                   background: `${verdictColor(h.verdict)}18`,
                                   color: verdictColor(h.verdict),
                                   border: `1px solid ${verdictColor(h.verdict)}30`,
                                   letterSpacing: "0.06em" }}>
                      {h.verdict}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Footer */}
      <div style={{ padding: "8px 16px", borderTop: "1px solid rgba(255,255,255,0.05)",
                    display: "flex", justifyContent: "space-between",
                    fontSize: 10, color: "#334155" }}>
        <span>LinkLens v1.6.0</span>
        <span>
          {result?.offline ? "Offline" : result?.qr_url ? "QR Scan" : "Live"}
          {" · URL"}
          {ocrResult?.success  ? " · OCR"  : ""}
          {pageResult?.success ? " · DOM"  : ""}
          {result?.whois?.status === "old" || result?.whois?.status === "trusted" ? " · WHOIS ✓" : " · WHOIS ?"}
        </span>
      </div>

    </div>
  );
}