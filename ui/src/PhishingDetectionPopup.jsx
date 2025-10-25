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
    font-size: 32px;
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
    font-family: monospace;
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
    padding: 8px 12px;
    border-radius: 6px;
    border-left: 3px solid #ef4444;
    margin-top: 6px;
  }

  .section-heading {
    font-size: 18px;
    font-weight: 700;
    color: #67e8f9;
    margin-bottom: 16px;
    text-align: center;
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  .sub-heading {
    font-size: 14px;
    font-weight: 600;
    color: #67e8f9;
    margin-bottom: 12px;
  }

  .report-heading {
    font-size: 16px;
    font-weight: 700;
    color: #f87171;
    margin-bottom: 12px;
    text-align: center;
  }

  .text-sm { font-size: 16px; }
  .text-xs { font-size: 14px; }
  .text-2xl { font-size: 24px; }
  .text-3xl { font-size: 32px; }
  .text-4xl { font-size: 40px; }
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
  // =========================================================================
  // V V V V  START of the section you need to REPLACE/UPDATE  V V V V
  // =========================================================================

  // 1. SIMPLIFIED STATE MANAGEMENT
  // Delete all your old useState hooks for url, threatScore, category, etc.
  // Replace them with these three:
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [report, setReport] = useState(null); // This is now your SINGLE SOURCE OF TRUTH

  // 2. THE API CALLING ENGINE (useEffect Hook)
  // This block runs automatically when the popup opens.
  useEffect(() => {
    // Check if running as a Chrome extension
    if (chrome && chrome.tabs) {
      // Get the URL of the user's currently active tab
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const currentTabUrl = tabs[0]?.url;
        if (!currentTabUrl) {
            setError("Could not get the URL of the current tab.");
            setIsLoading(false);
            return;
        }

        // Call your backend API with the live URL
        fetch("http://127.0.0.1:8000/api/v1/analyze", {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: currentTabUrl }),
        })
        .then(response => {
          if (!response.ok) { throw new Error('API network response failed'); }
          return response.json();
        })
        .then(data => {
          console.log("SUCCESS: Received API Response:", data);
          setReport(data); // Store the entire backend report in our state
          setIsLoading(false); // We're done loading
        })
        .catch(apiError => {
          console.error("API Error:", apiError);
          setError("Failed to get analysis. Is the Python backend server running?");
          setIsLoading(false);
        });
      });
    } else {
      setError("This must be run as a Chrome extension.");
      setIsLoading(false);
    }

    // Your existing style injection logic is perfect, keep it.
    const styleElement = document.createElement('style');
    styleElement.textContent = dashboardStyles;
    document.head.appendChild(styleElement);
    return () => { document.head.removeChild(styleElement); };
  }, []);

  // 3. HANDLE LOADING AND ERROR STATES
  // This provides a better user experience while waiting for the API.
  if (isLoading) {
    return <div style={{ color: 'white', padding: '20px', fontFamily: 'monospace', textAlign: 'center' }}>Analyzing current page...</div>;
  }
  if (error || !report || report.success === false) {
    return <div style={{ color: '#f87171', padding: '20px', fontFamily: 'monospace', textAlign: 'center' }}>Error: {error || report.error || 'No report available.'}</div>;
  }

  // 4. THE "BRIDGE": DERIVE UI VARIABLES FROM THE LIVE REPORT
  // This connects the API data to your existing UI components.
  const url = report.url;
  const threatScore = report.final_score; // Use the final score from the scoring engine
  const threatReasons = report.reasoning_highlights || [];
  const category = report.verdict.split(" ")[1] || "UNKNOWN";

  // Derive the parameters from the nested ML details
  const mlDetails = report.ml_details || {};
  const mlFeatures = mlDetails.features || {};
  const params = [
    { key: 'ML Model Confidence', value: Math.round((mlDetails.confidence || 0) * 100) },
    { key: 'Domain Age (Days)', value: mlFeatures.domain_age !== -1 ? mlFeatures.domain_age : 'N/A' },
    { key: 'Uses IP Address', value: mlFeatures.uses_ip_address ? 'YES' : 'NO' },
    { key: 'Insecure Password Form', value: report.ml_details.features.has_insecure_password_form ? 'YES' : 'NO' }
    // Add more features from the `mlFeatures` object as you see fit
  ];

  // For the demo, we can keep the history and systemMetrics static for now
  const history = [
      { url: 'example.com', date: '2023-10-19', score: 20, status: 'SAFE' },
      { url: 'paypal-secure.log', date: '2023-10-16', score: 87, status: 'MALICIOUS' }
  ];
  const systemMetrics = { totalScans: 1253, blockedLinks: 81, avgLatency: '650 ms' };




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
        {/* Left column: Real-time Threat Scan with Report */}
        <div className="dashboard-card">
          <div className="section-heading">REAL-TIME THREAT SCAN</div>
          
          <div className="mb-4">
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="scan-input"
              placeholder="Enter URL to scan..."
            />
          </div>

          {/* Threat Gauge */}
          <div className="flex-center">
            <div className="threat-gauge">
              <div className="text-center">
                <div className="text-4xl font-bold" style={{ color: '#f0f9ff' }}>
                  {threatScore}
                </div>
                <div className="text-sm font-semibold mt-2" style={{ color: getStatusColor(category) }}>
                  {category}
                </div>
              </div>
            </div>

            <div style={{ flex: 1 }}>
              <div className="sub-heading mb-3">
                THREAT RANGE
              </div>
              <div style={{
                height: '8px',
                borderRadius: '4px',
                background: 'linear-gradient(90deg, #4ade80, #fbbf24, #f87171)',
                marginBottom: '12px'
              }} />
              <div className="text-xs text-cyan-400" style={{ lineHeight: '1.4' }}>
                <div className="flex justify-between mb-1">
                  <span>0 — 30</span>
                  <span style={{ color: '#4ade80' }}>(Safe)</span>
                </div>
                <div className="flex justify-between mb-1">
                  <span>31 — 70</span>
                  <span style={{ color: '#fbbf24' }}>(Suspicious)</span>
                </div>
                <div className="flex justify-between">
                  <span>71 — 100</span>
                  <span style={{ color: '#f87171' }}>(Malicious)</span>
                </div>
              </div>
            </div>
          </div>

          {/* SCAN REPORT - Placed in the highlighted area */}
          <div className="threat-report">
            <div className="report-heading">SCAN REPORT</div>
            <div className="text-xs text-cyan-200 mb-3">
              This URL was classified as <span style={{ color: '#f87171', fontWeight: 'bold' }}>MALICIOUS</span> because:
            </div>
            <div style={{ maxHeight: '120px', overflowY: 'auto' }}>
              {threatReasons.map((reason, index) => (
                <div key={index} className="threat-reason">
                  <div className="text-xs text-red-200">• {reason}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Middle column: Parameter Breakdown */}
        <div className="dashboard-card">
          <div className="section-heading">DETAILED PARAMETER BREAKDOWN</div>

          <div className="max-h-80 overflow-y-auto pr-2">
            {params.map((param) => (
              <ParamRow key={param.key} param={param} />
            ))}
          </div>
        </div>

        {/* Right column: Visualization + OCR + Metrics */}
        <div className="flex-col">
          {/* Visualization */}
          <div className="dashboard-card">
            <div className="section-heading">VISUALIZATION & ANALYTICS</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div style={{
                height: '120px',
                backgroundColor: 'rgba(4, 50, 60, 0.3)',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#67e8f9',
                fontSize: '14px'
              }}>
                Bar Chart
              </div>
              <div style={{
                height: '120px',
                backgroundColor: 'rgba(4, 50, 60, 0.3)',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#67e8f9',
                fontSize: '14px'
              }}>
                Pie Chart
              </div>
            </div>
          </div>

          {/* OCR Verification */}
          <div className="dashboard-card">
            <div className="sub-heading">OCR & VISUAL VERIFICATION</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div style={{ padding: '12px', backgroundColor: 'rgba(4, 50, 60, 0.3)', borderRadius: '8px', textAlign: 'center' }}>
                <div className="text-sm text-cyan-200 mb-2">Detected Logo</div>
                <div style={{ 
                  backgroundColor: 'rgba(6, 136, 170, 0.2)', 
                  padding: '16px', 
                  borderRadius: '4px', 
                  fontFamily: 'monospace', 
                  color: '#b6ecff',
                  fontSize: '16px',
                  fontWeight: 'bold'
                }}>
                  PayP
                </div>
                <div className="text-xs text-cyan-400 mt-2">Confidence: 52%</div>
              </div>
              <div style={{ padding: '12px', backgroundColor: 'rgba(4, 50, 60, 0.3)', borderRadius: '8px', textAlign: 'center' }}>
                <div className="text-sm text-cyan-200 mb-2">Matched Logo</div>
                <div style={{ 
                  backgroundColor: 'rgba(6, 136, 170, 0.2)', 
                  padding: '16px', 
                  borderRadius: '4px', 
                  fontFamily: 'monospace', 
                  color: '#b6ecff',
                  fontSize: '16px',
                  fontWeight: 'bold'
                }}>
                  PayPal
                </div>
                <div className="text-xs text-cyan-400 mt-2">Confidence: 52%</div>
              </div>
            </div>
          </div>

          {/* System Metrics */}
          <div className="dashboard-card">
            <div className="sub-heading">SYSTEM METRICS</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', textAlign: 'center' }}>
              <div className="metric-box">
                <div className="text-2xl font-bold" style={{ color: '#f0f9ff' }}>{systemMetrics.totalScans}</div>
                <div className="text-sm text-cyan-300">Total Scans</div>
              </div>
              <div className="metric-box">
                <div className="text-2xl font-bold" style={{ color: '#f0f9ff' }}>{systemMetrics.blockedLinks}</div>
                <div className="text-sm text-cyan-300">Blocked Links</div>
              </div>
              <div className="metric-box">
                <div className="text-2xl font-bold" style={{ color: '#f0f9ff' }}>{systemMetrics.offlineDetections}</div>
                <div className="text-sm text-cyan-300">Offline Detections</div>
              </div>
              <div className="metric-box">
                <div className="text-2xl font-bold" style={{ color: '#f0f9ff' }}>{systemMetrics.avgLatency}</div>
                <div className="text-sm text-cyan-300">Avg Response</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* History Table */}
      <div className="dashboard-card">
        <div className="section-heading" style={{ textAlign: 'left' }}>SCAN HISTORY</div>
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
                  <td className="table-cell" style={{ fontFamily: 'monospace', fontSize: '12px' }}>{h.url}</td>
                  <td className="table-cell">{h.date}</td>
                  <td className="table-cell">
                    <span style={{
                      padding: '6px 10px',
                      borderRadius: '12px',
                      fontSize: '12px',
                      fontWeight: 'bold',
                      backgroundColor: `${getScoreColor(h.score)}20`,
                      color: getScoreColor(h.score)
                    }}>
                      {h.score}
                    </span>
                  </td>
                  <td className="table-cell">
                    <span style={{
                      padding: '6px 14px',
                      borderRadius: '12px',
                      fontSize: '12px',
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
        fontSize: '14px', 
        color: '#67e8f9',
        backgroundColor: 'rgba(6, 136, 170, 0.2)',
        padding: '12px',
        borderRadius: '8px'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>🛡️ Real-time Phishing Protection</span>
          <span>AI-Powered Threat Detection</span>
          <span>v2.1.0</span>
        </div>
      </footer>
    </div>
  );
}