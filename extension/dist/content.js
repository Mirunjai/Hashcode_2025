/**
 * content.js — LinkLens Block Page
 *
 * Injected into every page at document_start (before the page renders).
 * Listens for BLOCK_PAGE messages from the background service worker.
 * When a MALICIOUS verdict arrives, injects a full-screen warning overlay
 * that prevents interaction with the underlying page.
 *
 * The user can choose to proceed anyway — their choice is saved so the
 * overlay doesn't re-appear on the same URL in the same session.
 */

(function () {
  const proceeded = new Set();

  function showBlockPage(data) {
    const { score, url, highlights } = data;

    if (proceeded.has(url)) return;

    document.documentElement.style.overflow = "hidden";
    document.body && (document.body.style.overflow = "hidden");

    const existing = document.getElementById("linklens-block-overlay");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "linklens-block-overlay";

    overlay.style.cssText = `
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      z-index: 2147483647;
      background: #0a0a0a;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      color: #e2e8f0;
    `;

    const highlightItems = (highlights || [])
      .map(h => `<li style="margin-bottom:6px;color:#94a3b8;font-size:13px;line-height:1.5;">${h}</li>`)
      .join("");

    overlay.innerHTML = `
      <div style="
        max-width: 520px;
        width: 90%;
        background: #0f172a;
        border: 1px solid rgba(244,63,94,0.4);
        border-radius: 16px;
        padding: 40px 36px;
        text-align: center;
        box-shadow: 0 0 80px rgba(244,63,94,0.15);
      ">
        <div style="
          width: 64px; height: 64px;
          border-radius: 50%;
          background: rgba(244,63,94,0.12);
          border: 2px solid rgba(244,63,94,0.4);
          display: flex; align-items: center; justify-content: center;
          margin: 0 auto 20px;
          font-size: 28px;
        ">🛡️</div>

        <div style="font-size:22px;font-weight:700;color:#f43f5e;letter-spacing:0.02em;margin-bottom:8px;">
          Threat Detected
        </div>

        <div style="
          display:inline-block;
          background:rgba(244,63,94,0.12);
          border:1px solid rgba(244,63,94,0.3);
          border-radius:20px;
          padding:4px 14px;
          font-size:12px;
          font-weight:600;
          color:#f43f5e;
          letter-spacing:0.08em;
          margin-bottom:20px;
        ">MALICIOUS · ${score}/100</div>

        <div style="
          background:#0b1422;
          border:1px solid rgba(255,255,255,0.08);
          border-radius:8px;
          padding:10px 14px;
          font-family:monospace;
          font-size:12px;
          color:#64748b;
          word-break:break-all;
          margin-bottom:20px;
          text-align:left;
        ">${url}</div>

        ${highlightItems ? `
        <ul style="text-align:left;padding-left:18px;margin-bottom:24px;list-style:disc;">
          ${highlightItems}
        </ul>` : ""}

        <div style="font-size:11px;color:#334155;margin-bottom:28px;letter-spacing:0.06em;">
          🔍 LINKLENS · ML-POWERED PHISHING DETECTION
        </div>

        <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap;">
          <button id="ll-go-back" style="
            padding:11px 24px;
            border-radius:8px;
            border:none;
            background:linear-gradient(90deg,#0ea5e9,#14b8a6);
            color:#fff;
            font-size:14px;
            font-weight:600;
            cursor:pointer;
            letter-spacing:0.04em;
          ">← Go back safely</button>

          <button id="ll-proceed" style="
            padding:11px 24px;
            border-radius:8px;
            border:1px solid rgba(255,255,255,0.12);
            background:transparent;
            color:#64748b;
            font-size:13px;
            cursor:pointer;
          ">Proceed anyway (unsafe)</button>
        </div>

        <div style="font-size:11px;color:#1e293b;margin-top:16px;">
          Proceeding may expose your data. LinkLens cannot protect you on this page.
        </div>
      </div>
    `;

    document.documentElement.appendChild(overlay);

    // ── Go back safely ────────────────────────────────────────────────────────
    document.getElementById("ll-go-back").addEventListener("click", () => {
      if (history.length > 1) {
        history.back();
      } else {
        window.location.replace("https://www.google.com");
      }
    });

    // ── Proceed anyway ────────────────────────────────────────────────────────
    document.getElementById("ll-proceed").addEventListener("click", () => {
      proceeded.add(url);
      const el = document.getElementById("linklens-block-overlay");
      if (el) {
        el.style.display = "none";
        el.remove();
      }
      document.documentElement.style.overflow = "";
      if (document.body) document.body.style.overflow = "";
    });
  }

  function hideBlockPage() {
    const existing = document.getElementById("linklens-block-overlay");
    if (existing) {
      existing.remove();
      document.documentElement.style.overflow = "";
      if (document.body) document.body.style.overflow = "";
    }
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "BLOCK_PAGE") {
      if (document.documentElement) {
        showBlockPage(msg);
      } else {
        document.addEventListener("DOMContentLoaded", () => showBlockPage(msg));
      }
    }
    if (msg.type === "CLEAR_BLOCK") {
      hideBlockPage();
    }
  });

})();