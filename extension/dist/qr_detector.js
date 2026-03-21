/**
 * qr_detector.js — LinkLens Auto QR Detector
 *
 * Injected into every page after load. Scans all <img> elements
 * for QR codes using jsQR (loaded from CDN via background injection).
 * For each QR found, sends the decoded URL to the background for
 * analysis and overlays a coloured badge on the image.
 *
 * Flow:
 *   1. Find all <img> tags on the page
 *   2. Draw each onto a canvas, extract pixel data
 *   3. Run jsQR to decode
 *   4. If QR found, send URL to background via chrome.runtime.sendMessage
 *   5. Background returns verdict
 *   6. Overlay badge on the image (green / amber / red)
 *   7. MutationObserver watches for new images added dynamically
 */

(function () {
  // Avoid running twice
  if (window.__linklensQrDetectorRunning) return;
  window.__linklensQrDetectorRunning = true;

  const scanned = new Set();   // track already-scanned img src values

  // ── Draw image to canvas and return pixel data ──────────────────────────────
  function getImageData(img) {
    try {
      const canvas = document.createElement("canvas");
      canvas.width  = img.naturalWidth  || img.width  || 300;
      canvas.height = img.naturalHeight || img.height || 300;
      if (canvas.width < 10 || canvas.height < 10) return null;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      return ctx.getImageData(0, 0, canvas.width, canvas.height);
    } catch {
      return null;   // cross-origin images will throw — skip silently
    }
  }

  // ── Overlay badge on the image element ────────────────────────────────────
  function overlayBadge(img, verdict, score, decodedUrl) {
    // Make sure parent is positioned so badge can be absolute
    const parent = img.parentElement;
    if (!parent) return;

    const existingBadge = img.__linklens_badge;
    if (existingBadge) existingBadge.remove();

    const color = verdict === "MALICIOUS"  ? "#f43f5e"
                : verdict === "SUSPICIOUS" ? "#f59e0b"
                : "#22d3a4";

    const bg    = verdict === "MALICIOUS"  ? "rgba(244,63,94,0.15)"
                : verdict === "SUSPICIOUS" ? "rgba(245,158,11,0.15)"
                : "rgba(34,211,164,0.15)";

    const label = verdict === "MALICIOUS"  ? "⚠ QR THREAT"
                : verdict === "SUSPICIOUS" ? "? QR SUSPICIOUS"
                : "✓ QR SAFE";

    // Wrap the image if not already wrapped
    if (!img.parentElement.classList.contains("ll-qr-wrapper")) {
      const wrapper = document.createElement("div");
      wrapper.className = "ll-qr-wrapper";
      wrapper.style.cssText = `
        position: relative;
        display: inline-block;
      `;
      img.parentNode.insertBefore(wrapper, img);
      wrapper.appendChild(img);
    }

    const badge = document.createElement("div");
    badge.style.cssText = `
      position: absolute;
      top: 4px;
      left: 4px;
      background: ${bg};
      border: 1px solid ${color};
      border-radius: 6px;
      padding: 3px 8px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 11px;
      font-weight: 600;
      color: ${color};
      letter-spacing: 0.05em;
      z-index: 999999;
      cursor: pointer;
      white-space: nowrap;
      backdrop-filter: blur(4px);
    `;
    badge.textContent = `${label} · ${score}`;
    badge.title = `Decoded URL: ${decodedUrl}`;

    // Click badge to open popup with URL pre-filled
    badge.addEventListener("click", (e) => {
      e.stopPropagation();
      e.preventDefault();
      chrome.runtime.sendMessage({
        type: "QR_BADGE_CLICK",
        url:  decodedUrl,
      });
    });

    img.__linklens_badge = badge;
    img.parentElement.appendChild(badge);
  }

  // ── Process a single image ────────────────────────────────────────────────
  async function processImage(img) {
    if (!img.complete || !img.naturalWidth) return;
    const key = img.src || img.currentSrc;
    if (!key || scanned.has(key)) return;
    scanned.add(key);

    const imageData = getImageData(img);
    if (!imageData) return;

    // jsQR is injected into the page by the background script
    if (typeof jsQR === "undefined") return;

    const code = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: "dontInvert",
    });

    if (!code) return;

    const decodedUrl = code.data.trim();
    if (!decodedUrl.startsWith("http")) return;

    // Send to background for analysis
    chrome.runtime.sendMessage(
      { type: "SCAN_QR_URL", url: decodedUrl },
      (response) => {
        if (!response?.result) return;
        const { verdict, score } = response.result;
        overlayBadge(img, verdict, score, decodedUrl);

        // If malicious QR found on page — notify
        if (verdict === "MALICIOUS") {
          chrome.runtime.sendMessage({
            type:    "QR_THREAT_FOUND",
            url:     decodedUrl,
            score,
            imgSrc:  img.src,
          });
        }
      }
    );
  }

  // ── Scan all images on the page ───────────────────────────────────────────
  function scanAllImages() {
    document.querySelectorAll("img").forEach(img => {
      if (img.complete) {
        processImage(img);
      } else {
        img.addEventListener("load", () => processImage(img), { once: true });
      }
    });
  }

  // ── Watch for dynamically added images ────────────────────────────────────
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.tagName === "IMG") processImage(node);
        if (node.querySelectorAll) {
          node.querySelectorAll("img").forEach(processImage);
        }
      }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // Run immediately on page load
  if (document.readyState === "complete") {
    scanAllImages();
  } else {
    window.addEventListener("load", scanAllImages);
  }

})();