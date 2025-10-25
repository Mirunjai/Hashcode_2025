import React, { useEffect, useState } from 'react';

const dashboardStyles = `
  .dashboard-container {
    width: 900px;
    max-width: 100%;
    margin: 0 auto;
    padding: 20px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: #b6ecff;
    background: linear-gradient(135deg, #041018 0%, #06222e 100%);
    border-radius: 16px;
    border: 1px solid rgba(6, 136, 170, 0.3);
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
  }

  .dashboard-header {
    text-align: center;
    margin-bottom: 24px;
  }

  .dashboard-title {
    font-size: 28px;
    letter-spacing: 0.1em;
    font-weight: 800;
    background: linear-gradient(90deg, #67e8f9, #5eead4);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
  }

  .dashboard-card {
    background: linear-gradient(to bottom, rgba(6, 136, 170, 0.1), rgba(6, 136, 170, 0.05));
    padding: 16px;
    border-radius: 12px;
    border: 1px solid rgba(6, 136, 170, 0.3);
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
  }

  .scan-input {
    width: 100%;
    margin-top: 8px;
    padding: 12px;
    background-color: rgba(6, 136, 170, 0.2);
    border: 1px solid rgba(6, 136, 170, 0.3);
    border-radius: 8px;
    color: #b6ecff;
    font-size: 14px;
  }

  .scan-button {
    width: 100%;
    padding: 12px;
    border-radius: 8px;
    border: none;
    font-weight: 600;
    color: white;
    cursor: pointer;
    background: linear-gradient(90deg, #0891b2, #0d9488);
    margin-top: 8px;
  }

  .scan-button:hover {
    background: linear-gradient(90deg, #0ea5e9, #14b8a6);
  }

  .threat-gauge {
    position: relative;
    width: 160px;
    height: 160px;
    border-radius: 50%;
    border: 8px solid rgba(8, 145, 178, 0.3);
    background: linear-gradient(to bottom, rgba(8, 145, 178, 0.2), transparent);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .param-bar {
    width: 100%;
    height: 8px;
    border-radius: 4px;
    background-color: rgba(8, 145, 178, 0.3);
    overflow: hidden;
    margin-top: 4px;
  }

  .param-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0.5s ease;
  }

  .metric-box {
    padding: 12px;
    background-color: rgba(4, 50, 60, 0.3);
    border-radius: 8px;
    text-align: center;
    border: 1px solid rgba(6, 136, 170, 0.2);
  }

  .history-table {
    width: 100%;
    border-collapse: collapse;
  }

  .table-header {
    background-color: rgba(6, 136, 170, 0.3);
    border-bottom: 1px solid rgba(6, 136, 170, 0.5);
    padding: 12px 16px;
    font-size: 12px;
    font-weight: 600;
    color: #67e8f9;
  }

  .table-cell {
    padding: 12px 16px;
    border-bottom: 1px solid rgba(6, 136, 170, 0.2);
    font-size: 12px;
  }

  .grid-3-col {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 16px;
    margin-bottom: 16px;
  }

  .flex-col {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .flex-center {
    display: flex;
    align-items: center;
    gap: 24px;
  }

  .pie-chart {
    width: 140px;
    height: 140px;
    border-radius: 50%;
    background: conic-gradient(
      #ef4444 0% 45%,
      #f59e0b 45% 75%,
      #10b981 75% 90%,
      #3b82f6 90% 100%
    );
    margin: 0 auto;
    position: relative;
  }

  .pie-center {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 60px;
    height: 60px;
    background: #041018;
    border-radius: 50%;
  }

  .threat-report {
    background: linear-gradient(135deg, rgba(239, 68, 68, 0.1), rgba(239, 68, 68, 0.05));
    border: 1px solid rgba(239, 68, 68, 0.3);
    padding: 16px;
    border-radius: 12px;
    margin-top: 16px;
  }

  .threat-reason {
    background: rgba(239, 68, 68, 0.1);
    padding: 12px;
    border-radius: 8px;
    border-left: 4px solid #ef4444;
    margin-top: 8px;
  }

  .text-sm { font-size: 14px; }
  .text-xs { font-size: 12px; }
  .text-2xl { font-size: 24px; }
  .text-3xl { font-size: 32px; }
  .font-bold { font-weight: bold; }
  .font-semibold { font-weight: 600; }
  .text-cyan-200 { color: #67e8f9; }
  .text-cyan-300 { color: #5eead4; }
  .text-cyan-400 { color: #2dd4bf; }
  .text-green-300 { color: #4ade80; }
  .text-yellow-300 { color: #fbbf24; }
  .text-red-300 { color: #f87171; }
  .mb-2 { margin-bottom: 8px; }
  .mb-3 { margin-bottom: 12px; }
  .mb-4 { margin-bottom: 16px; }
  .mt-2 { margin-top: 8px; }
  .mt-4 { margin-top: 16px; }
  .text-center { text-align: center; }
  .w-full { width: 100%; }
  .max-h-80 { max-height: 320px; }
  .overflow-auto { overflow: auto; }
  .overflow-y-auto { overflow-y: auto; }
  .pr-2 { padding-right: 8px; }
`;

export default function PhishingDetectionPopup() {
  const [url, setUrl] = useState('https://paypal-secure-login.com');
  const [threatScore, setThreatScore] = useState(82);
  const [category, setCategory] = useState('MALICIOUS');
  const [isScanning, setIsScanning] = useState(false);
  
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

  const [threatReasons, setThreatReasons] = useState([
    "Suspicious domain name mimicking 'paypal-secure-login'",
    "Low domain age (registered recently)",
    "High entropy suggesting obfuscation",
    "Logo mismatch detected (PayP vs PayPal)",
    "SSL certificate validity issues",
    "Unusual special characters in URL"
  ]);

  const [history, setHistory] = useState([
    { url: 'example.com', date: '2023-10-19', score: 20, status: 'SAFE' },
    { url: 'paypal-secure.log', date: '2023-10-16', score: 57, status: 'MALICIOUS' },
    { url: 'secure-login.net', date: '2023-10-09', score: 43, status: 'SUSPICIOUS' },
    { url: 'bank-security.com', date: '2023-10-09', score: 63, status: 'SUSPICIOUS' },
  ]);

  const [systemMetrics, setSystemMetrics] = useState({
    totalScans: 1253,
    blockedLinks: 81,
    offlineDetections: 34,
    avgLatency: '200 ms',
  });

  // Inject styles on component mount
  useEffect(() => {
    const styleElement = document.createElement('style');
    styleElement.textContent = dashboardStyles;
    document.head.appendChild(styleElement);

    return () => {
      document.head.removeChild(styleElement);
    };
  }, []);

  function handleScan() {
    setIsScanning(true);

    // Simulate API call
    setTimeout(() => {
      const simulatedScore = Math.floor(Math.random() * 100);
      setThreatScore(simulatedScore);
      setCategory(simulatedScore > 70 ? 'MALICIOUS' : simulatedScore > 30 ? 'SUSPICIOUS' : 'SAFE');
      
      // Update metrics
      setSystemMetrics(prev => ({
        ...prev,
        totalScans: prev.totalScans + 1,
        blockedLinks: simulatedScore > 70 ? prev.blockedLinks + 1 : prev.blockedLinks
      }));

      // Add to history
      const newHistoryItem = {
        url: url.replace(/^https?:\/\//, ''),
        date: new Date().toISOString().split('T')[0],
        score: simulatedScore,
        status: simulatedScore > 70 ? 'MALICIOUS' : simulatedScore > 30 ? 'SUSPICIOUS' : 'SAFE'
      };
      
      setHistory(prev => [newHistoryItem, ...prev.slice(0, 19)]);
      setIsScanning(false);
    }, 1500);
  }

  function handleKeyPress(e) {
    if (e.key === 'Enter') {
      handleScan();
    }
  }

  // Helper function to get status color
  function getStatusColor(status) {
    switch (status) {
      case 'SAFE': return '#4ade80';
      case 'MALICIOUS': return '#f87171';
      case 'SUSPICIOUS': return '#fbbf24';
      default: return '#b6ecff';
    }
  }

  // Helper function to get score color
  function getScoreColor(score) {
    if (score >= 70) return '#f87171';
    if (score >= 30) return '#fbbf24';
    return '#4ade80';
  }

  // ParamRow component
  function ParamRow({ param }) {
    return (
      <div className="mb-4">
        <div className="flex justify-between text-xs text-cyan-200 mb-2">
          <span className="font-semibold">{param.key}</span>
          <span className="font-bold" style={{ color: getScoreColor(param.value) }}>
            {param.value}
          </span>
        </div>
        <div className="param-bar">
          <div
            className="param-fill"
            style={{
              width: `${param.value}%`,
              background: `linear-gradient(90deg, ${getScoreColor(param.value)}99, ${getScoreColor(param.value)})`
            }}
          />
        </div>
      </div>
    );
  }

  // Pie Chart Component
  function ThreatPieChart() {
    return (
      <div className="pie-chart">
        <div className="pie-center"></div>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <h1 className="dashboard-title">PHISHING DETECTION DASHBOARD</h1>
      </header>

      <div className="grid-3-col">
        {/* Left column: Scan + Gauge */}
        <div className="dashboard-card">
          <div className="mb-4">
            <label className="text-xs font-semibold text-cyan-200 mb-2">
              REAL-TIME THREAT SCAN
            </label>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={isScanning}
              className="scan-input"
              placeholder="Enter URL to scan..."
            />
          </div>

          <button
            onClick={handleScan}
            disabled={isScanning}
            className="scan-button"
          >
            {isScanning ? 'SCANNING...' : 'SCAN'}
          </button>

          {/* Threat Gauge */}
          <div className="flex-center mt-4">
            <div className="threat-gauge">
              <div className="text-center">
                <div className="text-3xl font-bold" style={{ color: '#f0f9ff' }}>
                  {threatScore}
                </div>
                <div className="text-sm font-semibold mt-2" style={{ color: getStatusColor(category) }}>
                  {category}
                </div>
              </div>
            </div>

            <div style={{ flex: 1 }}>
              <div className="text-xs text-cyan-200 font-semibold mb-3">
                THREAT RANGE
              </div>
              <div style={{
                height: '8px',
                borderRadius: '4px',
                background: 'linear-gradient(90deg, #4ade80, #fbbf24, #f87171)',
                marginBottom: '8px'
              }} />
              <div className="text-xs text-cyan-400" style={{ lineHeight: '1.4' }}>
                <div className="flex justify-between">
                  <span>0 — 30</span>
                  <span style={{ color: '#4ade80' }}>SAFE</span>
                </div>
                <div className="flex justify-between">
                  <span>31 — 70</span>
                  <span style={{ color: '#fbbf24' }}>SUSPICIOUS</span>
                </div>
                <div className="flex justify-between">
                  <span>71 — 100</span>
                  <span style={{ color: '#f87171' }}>MALICIOUS</span>
                </div>
              </div>
            </div>
          </div>

          {/* Threat Report Block */}
          <div className="threat-report">
            <h4 className="text-sm font-semibold text-red-300 mb-3">
              🚨 THREAT REPORT
            </h4>
            <div className="text-xs text-cyan-200 mb-2">
              This URL was flagged as malicious because:
            </div>
            {threatReasons.map((reason, index) => (
              <div key={index} className="threat-reason">
                <div className="text-xs text-red-200">• {reason}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Middle column: parameter breakdown */}
        <div className="dashboard-card">
          <h3 className="text-sm font-semibold mb-4 text-cyan-200 text-center">
            DETAILED PARAMETER BREAKDOWN
          </h3>

          <div className="max-h-80 overflow-y-auto pr-2">
            {params.map((param) => (
              <ParamRow key={param.key} param={param} />
            ))}
          </div>
        </div>

        {/* Right column: visualization + OCR logos + metrics */}
        <div className="flex-col">
          {/* Visualization */}
          <div className="dashboard-card">
            <h3 className="text-sm font-semibold mb-4 text-cyan-200">
              VISUALIZATION & ANALYTICS
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', alignItems: 'center' }}>
              <div style={{
                height: '112px',
                backgroundColor: 'rgba(4, 50, 60, 0.3)',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#67e8f9',
                fontSize: '12px',
                width: '100%'
              }}>
                Bar Chart
              </div>
              <div style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: '8px'
              }}>
                <ThreatPieChart />
                <div className="text-xs text-cyan-400 text-center">
                  Threat Distribution
                </div>
              </div>
            </div>
          </div>

          {/* OCR Verification */}
          <div className="dashboard-card">
            <h4 className="text-xs font-semibold mb-3 text-cyan-200">
              OCR & VISUAL VERIFICATION
            </h4>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
              <div style={{ padding: '12px', backgroundColor: 'rgba(4, 50, 60, 0.3)', borderRadius: '8px', textAlign: 'center' }}>
                <div className="text-sm text-cyan-200 mb-2">Detected Logo</div>
                <div style={{ backgroundColor: 'rgba(6, 136, 170, 0.2)', padding: '12px', borderRadius: '4px', fontFamily: 'monospace', color: '#b6ecff' }}>
                  PayP
                </div>
                <div className="text-xs text-cyan-400 mt-2">Confidence: 52%</div>
              </div>
              <div style={{ padding: '12px', backgroundColor: 'rgba(4, 50, 60, 0.3)', borderRadius: '8px', textAlign: 'center' }}>
                <div className="text-sm text-cyan-200 mb-2">Matched Logo</div>
                <div style={{ backgroundColor: 'rgba(6, 136, 170, 0.2)', padding: '12px', borderRadius: '4px', fontFamily: 'monospace', color: '#b6ecff' }}>
                  PayPal
                </div>
                <div className="text-xs text-cyan-400 mt-2">Confidence: 52%</div>
              </div>
            </div>
          </div>

          {/* System Metrics */}
          <div className="dashboard-card">
            <h4 className="text-xs font-semibold mb-3 text-cyan-200">
              SYSTEM METRICS
            </h4>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', textAlign: 'center' }}>
              <div className="metric-box">
                <div className="text-2xl font-bold" style={{ color: '#f0f9ff' }}>{systemMetrics.totalScans}</div>
                <div className="text-xs text-cyan-300">Total Scans</div>
              </div>
              <div className="metric-box">
                <div className="text-2xl font-bold" style={{ color: '#f0f9ff' }}>{systemMetrics.blockedLinks}</div>
                <div className="text-xs text-cyan-300">Blocked Links</div>
              </div>
              <div className="metric-box">
                <div className="text-2xl font-bold" style={{ color: '#f0f9ff' }}>{systemMetrics.offlineDetections}</div>
                <div className="text-xs text-cyan-300">Offline Detections</div>
              </div>
              <div className="metric-box">
                <div className="text-2xl font-bold" style={{ color: '#f0f9ff' }}>{systemMetrics.avgLatency}</div>
                <div className="text-xs text-cyan-300">Avg Response</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* History Table */}
      <div className="dashboard-card">
        <h3 className="text-sm font-semibold mb-4 text-cyan-200">
          SCAN HISTORY
        </h3>
        <div className="overflow-auto" style={{ maxHeight: '192px' }}>
          <table className="history-table">
            <thead>
              <tr>
                <th className="table-header">URL</th>
                <th className="table-header">Date</th>
                <th className="table-header">Score</th>
                <th className="table-header">Status</th>
              </tr>
            </thead>
            <tbody>
              {history.map((h, i) => (
                <tr key={i} style={{ borderBottom: '1px solid rgba(6, 136, 170, 0.1)' }}>
                  <td className="table-cell" style={{ fontFamily: 'monospace', fontSize: '11px' }}>{h.url}</td>
                  <td className="table-cell">{h.date}</td>
                  <td className="table-cell">
                    <span style={{
                      padding: '4px 8px',
                      borderRadius: '12px',
                      fontSize: '11px',
                      fontWeight: 'bold',
                      backgroundColor: `${getScoreColor(h.score)}20`,
                      color: getScoreColor(h.score)
                    }}>
                      {h.score}
                    </span>
                  </td>
                  <td className="table-cell">
                    <span style={{
                      padding: '4px 12px',
                      borderRadius: '12px',
                      fontSize: '11px',
                      fontWeight: '600',
                      backgroundColor: `${getStatusColor(h.status)}20`,
                      color: getStatusColor(h.status),
                      border: `1px solid ${getStatusColor(h.status)}30`
                    }}>
                      {h.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <footer style={{ 
        marginTop: '16px', 
        textAlign: 'center', 
        fontSize: '12px', 
        color: '#67e8f9',
        backgroundColor: 'rgba(6, 136, 170, 0.2)',
        padding: '12px',
        borderRadius: '8px'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>🛡️ Real-time Phishing Protection</span>
          <span>ML-Powered Threat Detection</span>
          <span>v2.1.0</span>
        </div>
      </footer>
    </div>
  );
}