import React, { useEffect, useState } from 'react';

export default function PhishingDetectionPopup() {
  const [url, setUrl] = useState('https://paypal-secure-login.com');
  const [threatScore, setThreatScore] = useState(87);
  const [category, setCategory] = useState('MALICIOUS');
  const [isScanning, setIsScanning] = useState(false);
  const [isReporting, setIsReporting] = useState(false);
  const [scanError, setScanError] = useState('');
  const [reportMessage, setReportMessage] = useState('');
  
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

  // Inline styles object
  const styles = {
    container: {
      width: '900px',
      maxWidth: '100%',
      margin: '0 auto',
      padding: '20px',
      fontFamily: 'system-ui, -apple-system, sans-serif',
      color: '#b6ecff',
      background: 'linear-gradient(135deg, #041018 0%, #06222e 100%)',
      borderRadius: '16px',
      border: '1px solid rgba(6, 136, 170, 0.3)',
      boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)'
    },
    header: {
      textAlign: 'center',
      marginBottom: '24px'
    },
    headerText: {
      fontSize: '28px',
      letterSpacing: '0.1em',
      fontWeight: '800',
      background: 'linear-gradient(90deg, #67e8f9, #5eead4)',
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
      textShadow: '0 2px 4px rgba(0, 0, 0, 0.3)'
    },
    card: {
      background: 'linear-gradient(to bottom, rgba(6, 136, 170, 0.1), rgba(6, 136, 170, 0.05))',
      padding: '16px',
      borderRadius: '12px',
      border: '1px solid rgba(6, 136, 170, 0.3)',
      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.2)'
    },
    input: {
      width: '100%',
      marginTop: '8px',
      padding: '12px',
      backgroundColor: 'rgba(6, 136, 170, 0.2)',
      border: '1px solid rgba(6, 136, 170, 0.3)',
      borderRadius: '8px',
      color: '#b6ecff',
      fontSize: '14px'
    },
    button: {
      flex: 1,
      padding: '12px',
      borderRadius: '8px',
      border: 'none',
      fontWeight: '600',
      color: 'white',
      cursor: 'pointer',
      transition: 'all 0.2s ease',
      background: 'linear-gradient(90deg, #0891b2, #0d9488)'
    },
    reportButton: {
      padding: '12px 16px',
      borderRadius: '8px',
      border: 'none',
      fontWeight: '600',
      color: 'white',
      cursor: 'pointer',
      background: 'linear-gradient(90deg, #7c3aed, #db2777)'
    },
    gauge: {
      position: 'relative',
      width: '160px',
      height: '160px',
      borderRadius: '50%',
      border: '8px solid rgba(8, 145, 178, 0.3)',
      background: 'linear-gradient(to bottom, rgba(8, 145, 178, 0.2), transparent)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center'
    },
    paramBar: {
      width: '100%',
      height: '8px',
      borderRadius: '4px',
      backgroundColor: 'rgba(8, 145, 178, 0.3)',
      overflow: 'hidden',
      marginTop: '4px'
    },
    metricBox: {
      padding: '12px',
      backgroundColor: 'rgba(4, 50, 60, 0.3)',
      borderRadius: '8px',
      textAlign: 'center',
      border: '1px solid rgba(6, 136, 170, 0.2)'
    },
    table: {
      width: '100%',
      textAlign: 'left',
      borderCollapse: 'collapse'
    },
    tableHeader: {
      backgroundColor: 'rgba(6, 136, 170, 0.3)',
      borderBottom: '1px solid rgba(6, 136, 170, 0.5)',
      padding: '12px 16px',
      fontSize: '12px',
      fontWeight: '600',
      color: '#67e8f9'
    },
    tableCell: {
      padding: '12px 16px',
      borderBottom: '1px solid rgba(6, 136, 170, 0.2)',
      fontSize: '12px'
    }
  };

  useEffect(() => {
    // Simulate initial data fetch
    const timer = setTimeout(() => {
      setSystemMetrics(prev => ({
        ...prev,
        totalScans: 1250,
        blockedLinks: 78
      }));
    }, 1000);

    return () => clearTimeout(timer);
  }, []);

  function isValidUrl(string) {
    try {
      new URL(string);
      return true;
    } catch (_) {
      return false;
    }
  }

  function handleScan() {
    setScanError('');
    setReportMessage('');

    if (!isValidUrl(url)) {
      setScanError('Please enter a valid URL');
      return;
    }

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

  function handleReport() {
    if (!isValidUrl(url)) {
      setReportMessage('Please enter a valid URL to report');
      return;
    }

    setIsReporting(true);
    setReportMessage('');

    // Simulate report API call
    setTimeout(() => {
      setReportMessage('✅ Reported successfully — thank you for contributing to community safety.');
      setIsReporting(false);
      
      setTimeout(() => setReportMessage(''), 5000);
    }, 1000);
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

  return (
    <div style={styles.container}>
      <header style={styles.header}>
        <h1 style={styles.headerText}>PHISHING DETECTION DASHBOARD</h1>
      </header>

      {/* Messages */}
      {scanError && (
        <div style={{
          marginBottom: '16px',
          padding: '12px',
          backgroundColor: 'rgba(248, 113, 113, 0.2)',
          border: '1px solid rgba(248, 113, 113, 0.5)',
          borderRadius: '8px',
          color: '#fecaca',
          fontSize: '14px'
        }}>
          {scanError}
        </div>
      )}
      {reportMessage && (
        <div style={{
          marginBottom: '16px',
          padding: '12px',
          backgroundColor: reportMessage.includes('✅') 
            ? 'rgba(74, 222, 128, 0.2)'
            : 'rgba(248, 113, 113, 0.2)',
          border: reportMessage.includes('✅')
            ? '1px solid rgba(74, 222, 128, 0.5)'
            : '1px solid rgba(248, 113, 113, 0.5)',
          borderRadius: '8px',
          color: reportMessage.includes('✅') ? '#bbf7d0' : '#fecaca',
          fontSize: '14px'
        }}>
          {reportMessage}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px', marginBottom: '16px' }}>
        {/* Left column: Scan + Gauge */}
        <div style={styles.card}>
          <div style={{ marginBottom: '16px' }}>
            <label style={{ fontSize: '12px', fontWeight: '600', color: '#67e8f9', display: 'block', marginBottom: '8px' }}>
              REAL-TIME THREAT SCAN
            </label>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={isScanning}
              style={styles.input}
              placeholder="Enter URL to scan..."
            />
          </div>

          <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
            <button
              onClick={handleScan}
              disabled={isScanning}
              style={{
                ...styles.button,
                opacity: isScanning ? 0.6 : 1,
                cursor: isScanning ? 'not-allowed' : 'pointer'
              }}
            >
              {isScanning ? 'SCANNING...' : 'SCAN'}
            </button>
            <button
              onClick={handleReport}
              disabled={isReporting || !url}
              style={{
                ...styles.reportButton,
                opacity: (isReporting || !url) ? 0.6 : 1,
                cursor: (isReporting || !url) ? 'not-allowed' : 'pointer'
              }}
            >
              REPORT
            </button>
          </div>

          {/* Threat Gauge */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '24px', marginTop: '16px' }}>
            <div style={styles.gauge}>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#f0f9ff' }}>
                  {threatScore}
                </div>
                <div style={{ 
                  fontSize: '14px', 
                  fontWeight: '600', 
                  marginTop: '4px',
                  color: getStatusColor(category)
                }}>
                  {category}
                </div>
              </div>
            </div>

            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '12px', color: '#67e8f9', fontWeight: '600', marginBottom: '8px' }}>
                THREAT RANGE
              </div>
              <div style={{
                height: '8px',
                borderRadius: '4px',
                background: 'linear-gradient(90deg, #4ade80, #fbbf24, #f87171)',
                marginBottom: '8px'
              }} />
              <div style={{ fontSize: '11px', color: '#67e8f9', lineHeight: '1.4' }}>
                0 — 30 (Safe) • 31 — 70 (Suspicious) • 71 — 100 (Malicious)
              </div>
            </div>
          </div>
        </div>

        {/* Middle column: parameter breakdown */}
        <div style={styles.card}>
          <h3 style={{ fontSize: '14px', fontWeight: '600', marginBottom: '16px', color: '#67e8f9', textAlign: 'center' }}>
            DETAILED PARAMETER BREAKDOWN
          </h3>

          <div style={{ maxHeight: '320px', overflowY: 'auto', paddingRight: '8px' }}>
            {params.map((param) => (
              <div key={param.key} style={{ marginBottom: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: '#67e8f9', marginBottom: '4px' }}>
                  <span style={{ fontWeight: '500' }}>{param.key}</span>
                  <span style={{ fontWeight: 'bold', color: getScoreColor(param.value) }}>{param.value}</span>
                </div>
                <div style={styles.paramBar}>
                  <div
                    style={{
                      width: `${param.value}%`,
                      height: '100%',
                      borderRadius: '4px',
                      background: `linear-gradient(90deg, ${getScoreColor(param.value)}99, ${getScoreColor(param.value)})`,
                      transition: 'width 0.5s ease'
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right column: visualization + OCR logos + metrics */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Visualization */}
          <div style={styles.card}>
            <h3 style={{ fontSize: '14px', fontWeight: '600', marginBottom: '16px', color: '#67e8f9' }}>
              VISUALIZATION & ANALYTICS
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div style={{
                height: '112px',
                backgroundColor: 'rgba(4, 50, 60, 0.3)',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#67e8f9',
                fontSize: '12px'
              }}>
                Bar Chart
              </div>
              <div style={{
                height: '112px',
                backgroundColor: 'rgba(4, 50, 60, 0.3)',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#67e8f9',
                fontSize: '12px'
              }}>
                Pie Chart
              </div>
            </div>
          </div>

          {/* OCR Verification */}
          <div style={styles.card}>
            <h4 style={{ fontSize: '12px', fontWeight: '600', marginBottom: '12px', color: '#67e8f9' }}>
              OCR & VISUAL VERIFICATION
            </h4>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
              <div style={{ padding: '12px', backgroundColor: 'rgba(4, 50, 60, 0.3)', borderRadius: '8px', textAlign: 'center' }}>
                <div style={{ marginBottom: '8px', fontSize: '13px', color: '#67e8f9' }}>Detected Logo</div>
                <div style={{ backgroundColor: 'rgba(6, 136, 170, 0.2)', padding: '12px', borderRadius: '4px', fontFamily: 'monospace', color: '#b6ecff' }}>
                  PayP
                </div>
                <div style={{ fontSize: '11px', color: '#67e8f9', marginTop: '4px' }}>Confidence: 52%</div>
              </div>
              <div style={{ padding: '12px', backgroundColor: 'rgba(4, 50, 60, 0.3)', borderRadius: '8px', textAlign: 'center' }}>
                <div style={{ marginBottom: '8px', fontSize: '13px', color: '#67e8f9' }}>Matched Logo</div>
                <div style={{ backgroundColor: 'rgba(6, 136, 170, 0.2)', padding: '12px', borderRadius: '4px', fontFamily: 'monospace', color: '#b6ecff' }}>
                  PayPal
                </div>
                <div style={{ fontSize: '11px', color: '#67e8f9', marginTop: '4px' }}>Confidence: 52%</div>
              </div>
            </div>
          </div>

          {/* System Metrics */}
          <div style={styles.card}>
            <h4 style={{ fontSize: '12px', fontWeight: '600', marginBottom: '12px', color: '#67e8f9' }}>
              SYSTEM METRICS
            </h4>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', textAlign: 'center' }}>
              <div style={styles.metricBox}>
                <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#f0f9ff' }}>{systemMetrics.totalScans}</div>
                <div style={{ fontSize: '12px', color: '#67e8f9' }}>Total Scans</div>
              </div>
              <div style={styles.metricBox}>
                <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#f0f9ff' }}>{systemMetrics.blockedLinks}</div>
                <div style={{ fontSize: '12px', color: '#67e8f9' }}>Blocked Links</div>
              </div>
              <div style={styles.metricBox}>
                <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#f0f9ff' }}>{systemMetrics.offlineDetections}</div>
                <div style={{ fontSize: '12px', color: '#67e8f9' }}>Offline Detections</div>
              </div>
              <div style={styles.metricBox}>
                <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#f0f9ff' }}>{systemMetrics.avgLatency}</div>
                <div style={{ fontSize: '12px', color: '#67e8f9' }}>Avg Response</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* History Table */}
      <div style={styles.card}>
        <h3 style={{ fontSize: '14px', fontWeight: '600', marginBottom: '16px', color: '#67e8f9' }}>
          SCAN HISTORY
        </h3>
        <div style={{ overflow: 'auto', maxHeight: '192px' }}>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.tableHeader}>URL</th>
                <th style={styles.tableHeader}>Date</th>
                <th style={styles.tableHeader}>Score</th>
                <th style={styles.tableHeader}>Status</th>
              </tr>
            </thead>
            <tbody>
              {history.map((h, i) => (
                <tr key={i} style={{ borderBottom: '1px solid rgba(6, 136, 170, 0.1)' }}>
                  <td style={{ ...styles.tableCell, fontFamily: 'monospace', fontSize: '11px' }}>{h.url}</td>
                  <td style={styles.tableCell}>{h.date}</td>
                  <td style={styles.tableCell}>
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
                  <td style={styles.tableCell}>
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
          <span>Built for demo • connects to /api/analyze and /api/report</span>
          <span>v2.1.0</span>
        </div>
      </footer>
    </div>
  );
}