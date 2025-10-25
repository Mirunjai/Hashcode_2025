import React, { useEffect, useState } from 'react';

// Single-file React component for the extension popup/dashboard
// Designed to visually match the provided neon dashboard image and include a "Report URL" action.

export default function PhishingDetectionPopup() {
  const [url, setUrl] = useState('https://paypal-secure-login.com');
  const [threatScore, setThreatScore] = useState(87);
  const [category, setCategory] = useState('MALICIOUS');
  const [params, setParams] = useState([
    { key: 'URL Length Score', value: 70 },
    { key: 'Special Characters Count', value: 80 },
    { key: 'Domain Age', value: 60 },
    { key: 'HTTPS/SSL Validity', value: 40 },
    { key: 'Entropy/Obfuscation', value: 85 },
    { key: 'OCR Logo Match Score', value: 85 },
    { key: 'ML Model Confidence', value: 80 },
    { key: 'QR Content Type (URL)', value: 70 },
  ]);

  const [history, setHistory] = useState([
    { url: 'example.com', date: '2023-10-19', score: 20, status: 'SAFE' },
    { url: 'paypal-secure.log', date: '2023-10-16', score: 57, status: 'MALICIOUS' },
    { url: 'secure-login.net', date: '2023-10-09', score: 43, status: 'SUSPICIOUS' },
    { url: 'bank-security.com', date: '2023-10-09', score: 63, status: 'SUSPICIOUS' },
  ]);

  const [systemMetrics, setSystemMetrics] = useState({
    totalScans: 1234,
    blockedLinks: 76,
    offlineDetections: 34,
    avgLatency: '200 ms',
  });

  useEffect(() => {
    // Placeholder: fetch initial data from backend if available
    // fetch('/api/initial').then(...)
  }, []);

  function handleScan() {
    // Call backend analyze endpoint (replace with real endpoint)
    // This example posts url and expects analysis JSON back.
    fetch('http://127.0.0.1:8000/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    })
      .then((r) => r.json())
      .then((data) => {
        // Expected response shape: { threat_score: int, category: 'MALICIOUS'|'SAFE'|..., params: [...], historyItem: {...} }
        if (data.threat_score !== undefined) setThreatScore(data.threat_score);
        if (data.category) setCategory(data.category.toUpperCase());
        if (Array.isArray(data.params)) setParams(data.params);
        if (data.historyItem) setHistory((h) => [data.historyItem, ...h].slice(0, 20));
      })
      .catch((err) => {
        console.error('analyze error', err);
        // Fallback: keep current state
      });
  }

  function handleReport() {
    // Report the URL to backend. Backend should store evidence and optionally trigger further analysis.
    fetch('http://127.0.0.1:8000/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, reportedAt: new Date().toISOString(), reason: 'user_report' }),
    })
      .then((r) => {
        if (!r.ok) throw new Error('report failed');
        alert('Reported successfully — thank you.');
      })
      .catch((e) => {
        console.error(e);
        alert('Report failed (offline or server error).');
      });
  }

  // Small helper for neon bar style
  function ParamRow({ name, value }) {
    return (
      <div className="mb-2">
        <div className="flex justify-between text-xs text-cyan-200 mb-1">
          <span>{name}</span>
          <span>{value}</span>
        </div>
        <div className="w-full h-3 rounded bg-cyan-900 overflow-hidden" aria-hidden>
          <div
            style={{ width: `${value}%` }}
            className={`h-full rounded bg-gradient-to-r from-cyan-400 via-teal-300 to-green-200`}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="w-[900px] max-w-full mx-auto p-5 font-sans text-cyan-100 bg-[#041018] rounded-2xl border border-[#06222a] shadow-2xl">
      <header className="text-center mb-4">
        <h1 className="text-3xl tracking-widest font-extrabold text-cyan-200">PHISHING DETECTION DASHBOARD</h1>
      </header>

      <div className="grid grid-cols-3 gap-4">
        {/* Left column: Scan + Gauge */}
        <div className="col-span-1 bg-[#062022] p-4 rounded-lg border border-[#08303a]">
          <div className="mb-3">
            <label className="text-xs text-cyan-200">REAL-TIME THREAT SCAN</label>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full mt-2 p-2 bg-transparent border border-[#0b3943] rounded text-cyan-100 placeholder:text-cyan-400"
            />
          </div>

          <div className="flex gap-2 mb-3">
            <button
              onClick={handleScan}
              className="flex-1 py-2 rounded bg-transparent border border-[#0f5a62] hover:bg-[#0f5a62]/20"
            >
              SCAN
            </button>
            <button
              onClick={handleReport}
              className="px-3 py-2 rounded bg-[#7b1cff]/80 hover:bg-[#7b1cff] text-white"
              title="Report this URL to the central database"
            >
              REPORT
            </button>
          </div>

          <div className="flex items-center gap-4 mt-2">
            <div className="flex-1">
              <div className="mx-auto w-40 h-40 rounded-full border-8 border-[#03363b] flex items-center justify-center bg-gradient-to-b from-[#032d30] to-transparent">
                <div className="text-center">
                  <div className="text-4xl font-bold text-cyan-100">{threatScore}</div>
                  <div className={`mt-1 text-sm font-semibold ${category === 'MALICIOUS' ? 'text-red-400' : 'text-green-300'}`}>
                    {category}
                  </div>
                </div>
              </div>
            </div>

            <div className="w-1/2">
              <div className="text-xs text-cyan-300 mb-2">THREAT RANGE</div>
              <div className="h-2 rounded bg-[#05272a] overflow-hidden mb-2">
                <div style={{ width: `${Math.min(threatScore, 100)}%` }} className="h-full bg-gradient-to-r from-green-400 via-yellow-300 to-red-500" />
              </div>
              <div className="text-[11px] text-cyan-300">0 — 30 (Safe) • 31 — 70 (Suspicious) • 71 — 100 (Malicious)</div>
            </div>
          </div>
        </div>

        {/* Middle column: parameter breakdown */}
        <div className="col-span-1 bg-[#062022] p-4 rounded-lg border border-[#08303a]">
          <h3 className="text-sm font-semibold mb-3 text-cyan-200">DETAILED PARAMETER BREAKDOWN</h3>

          <div className="space-y-2">
            {params.map((p) => (
              <ParamRow key={p.key} name={p.key} value={p.value} />
            ))}
          </div>
        </div>

        {/* Right column: visualization + OCR logos + metrics */}
        <div className="col-span-1 space-y-3">
          <div className="bg-[#062022] p-4 rounded-lg border border-[#08303a]">
            <h3 className="text-sm font-semibold text-cyan-200 mb-3">VISUALIZATION & ANALYTICS</h3>
            <div className="grid grid-cols-2 gap-3">
              <div className="h-28 bg-[#05282c] rounded flex items-center justify-center">Bar Chart</div>
              <div className="h-28 bg-[#05282c] rounded flex items-center justify-center">Pie Chart</div>
            </div>
          </div>

          <div className="bg-[#062022] p-4 rounded-lg border border-[#08303a] flex gap-3">
            <div className="flex-1">
              <h4 className="text-xs text-cyan-200 mb-2">OCR & VISUAL VERIFICATION</h4>
              <div className="grid grid-cols-2 gap-2">
                <div className="p-2 bg-[#042426] rounded text-center">
                  <div className="mb-2 text-[13px]">Detected Logo</div>
                  <div className="bg-cyan-900/20 py-3 rounded">PayP</div>
                  <div className="text-[11px] text-cyan-300 mt-1">Confidence: 52%</div>
                </div>
                <div className="p-2 bg-[#042426] rounded text-center">
                  <div className="mb-2 text-[13px]">Matched Logo</div>
                  <div className="bg-cyan-900/20 py-3 rounded">PayPal</div>
                  <div className="text-[11px] text-cyan-300 mt-1">Confidence: 52%</div>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-[#062022] p-3 rounded-lg border border-[#08303a]">
            <h4 className="text-xs text-cyan-200 mb-2">SYSTEM METRICS</h4>
            <div className="grid grid-cols-2 gap-3 text-center text-cyan-100">
              <div className="p-2 bg-[#042426] rounded"> 
                <div className="text-2xl font-bold">{systemMetrics.totalScans}</div>
                <div className="text-xs text-cyan-300">Total Scans</div>
              </div>
              <div className="p-2 bg-[#042426] rounded">
                <div className="text-2xl font-bold">{systemMetrics.blockedLinks}</div>
                <div className="text-xs text-cyan-300">Blocked Links</div>
              </div>
              <div className="p-2 bg-[#042426] rounded">
                <div className="text-2xl font-bold">{systemMetrics.offlineDetections}</div>
                <div className="text-xs text-cyan-300">Offline Detections</div>
              </div>
              <div className="p-2 bg-[#042426] rounded">
                <div className="text-2xl font-bold">{systemMetrics.avgLatency}</div>
                <div className="text-xs text-cyan-300">Avg Response</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom row: history */}
      <div className="mt-4 bg-[#062022] p-4 rounded-lg border border-[#08303a]">
        <h3 className="text-sm font-semibold mb-3 text-cyan-200">HISTORY</h3>
        <div className="overflow-auto max-h-40">
          <table className="w-full text-left table-auto text-cyan-100 text-sm">
            <thead>
              <tr className="border-b border-[#0b3943] text-cyan-300">
                <th className="px-2 py-1">URL</th>
                <th className="px-2 py-1">Date</th>
                <th className="px-2 py-1">Score</th>
                <th className="px-2 py-1">Status</th>
              </tr>
            </thead>
            <tbody>
              {history.map((h, i) => (
                <tr key={i} className="border-b border-[#05282c]">
                  <td className="px-2 py-1">{h.url}</td>
                  <td className="px-2 py-1">{h.date}</td>
                  <td className="px-2 py-1">{h.score}</td>
                  <td className={`px-2 py-1 ${h.status === 'SAFE' ? 'text-green-400' : h.status === 'MALICIOUS' ? 'text-red-400' : 'text-yellow-400'}`}>
                    {h.status}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <footer className="mt-3 text-right text-xs text-cyan-400">Built for demo • connects to /api/analyze and /api/report</footer>
    </div>
  );
}
