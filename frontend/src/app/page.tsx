'use client';

import { useState, useEffect, useRef } from 'react';
import { jsPDF } from 'jspdf';
import { toPng } from 'html-to-image';

interface CertDetail {
  common_name: string;
  organization: string;
  issuer: string;
  issuer_org: string;
  valid_from: string;
  valid_to: string;
  serial_number: string;
  signature_algorithm: string;
  fingerprint_sha256: string;
  sans: string[];
}

interface CheckItem {
  label: string;
  status: 'success' | 'error' | 'info';
}

interface TraceEntry {
  timestamp: string;
  message: string;
}

interface SSLResult {
  hostname: string;
  ip: string;
  geo: { country: string; city: string; isp: string; is_cdn: boolean };
  server_type: string;
  chain: CertDetail[];
  checklist: CheckItem[];
  protocols: Record<string, boolean>;
  cipher_info: { name: string; bits: number; strength: string };
  handshake_time: number;
  alpn: string;
  security_grade: string;
  hsts_info: { enabled: boolean; preloaded: boolean };
  trace: TraceEntry[];
  is_valid: boolean;
}

export default function SSLCheck() {
  const [hostname, setHostname] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SSLResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [history, setHistory] = useState<string[]>([]);
  const [showConsole, setShowConsole] = useState(false);
  const [visibleLogs, setVisibleLogs] = useState<TraceEntry[]>([]);
  const reportRef = useRef<HTMLDivElement>(null);
  const consoleBodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const savedTheme = localStorage.getItem('theme') as 'dark' | 'light';
    if (savedTheme) {
      setTheme(savedTheme);
      document.documentElement.setAttribute('data-theme', savedTheme);
    }
    const savedHistory = JSON.parse(localStorage.getItem('ssl_history') || '[]');
    setHistory(savedHistory);
  }, []);

  const toggleTheme = () => {
    const newTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
  };

  const handleCheck = async (targetHost?: string) => {
    const hostToQuery = targetHost || hostname;
    if (!hostToQuery) return;
    
    setHostname(hostToQuery);
    setLoading(true);
    setError(null);
    setResult(null);
    setVisibleLogs([]);
    setShowConsole(false);

    try {
      const response = await fetch('/api/run-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname: hostToQuery }),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Analysis failed');
      
      setResult(data);
      
      // Fixed: Stabilized playback logic
      if (data.trace && Array.isArray(data.trace)) {
        let currentIdx = 0;
        const total = data.trace.length;
        const interval = setInterval(() => {
          if (currentIdx < total) {
            const nextLog = data.trace[currentIdx];
            if (nextLog) {
              setVisibleLogs(prev => [...prev, nextLog]);
            }
            currentIdx++;
          } else {
            clearInterval(interval);
          }
        }, 80);
      }

      const newHistory = [hostToQuery, ...history.filter(h => h !== hostToQuery)].slice(0, 5);
      setHistory(newHistory);
      localStorage.setItem('ssl_history', JSON.stringify(newHistory));
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (showConsole && consoleBodyRef.current) {
      consoleBodyRef.current.scrollTop = consoleBodyRef.current.scrollHeight;
    }
  }, [visibleLogs, showConsole]);

  const downloadICS = () => {
    if (!result) return;
    const cert = result.chain[0];
    const expiryDate = new Date(cert.valid_to);
    const dateStr = expiryDate.toISOString().replace(/-|:|\.\d+/g, '');
    const icsContent = ['BEGIN:VCALENDAR','VERSION:2.0','BEGIN:VEVENT',`DTSTART:${dateStr}`,`DTEND:${dateStr}`,`SUMMARY:SSL Expiry: ${result.hostname}`,`DESCRIPTION:SSL for ${result.hostname} expires today.`,'END:VEVENT','END:VCALENDAR'].join('\r\n');
    const blob = new Blob([icsContent], { type: 'text/calendar;charset=utf-8' });
    const link = document.createElement('a');
    link.href = window.URL.createObjectURL(blob);
    link.download = `ssl_expiry_${result.hostname}.ics`;
    link.click();
  };

  const downloadPDF = async () => {
    if (!reportRef.current) return;
    try {
      const dataUrl = await toPng(reportRef.current, { backgroundColor: theme === 'dark' ? '#0d0f14' : '#f1f5f9' });
      const pdf = new jsPDF('p', 'mm', 'a4');
      const imgProps = pdf.getImageProperties(dataUrl);
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = (imgProps.height * pdfWidth) / imgProps.width;
      pdf.addImage(dataUrl, 'PNG', 0, 0, pdfWidth, pdfHeight);
      pdf.save(`SSLCheck_Report_${result?.hostname}.pdf`);
    } catch (err) { console.error(err); }
  };

  return (
    <main>
      <button className="theme-toggle" onClick={toggleTheme} aria-label="Toggle Theme">
        {theme === 'dark' ? '☀️' : '🌙'}
      </button>

      <header>
        <h1>SSLCheck</h1>
        <p className="subtitle">Enterprise SSL Monitoring & Intelligence</p>
      </header>

      <div className="search-container">
        <input
          type="text"
          placeholder="Enter hostname (e.g. google.com)"
          value={hostname}
          onChange={(e) => setHostname(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleCheck()}
        />
        <button onClick={() => handleCheck()} disabled={loading}>
          {loading ? 'Checking...' : 'Check SSL'}
        </button>
      </div>

      {history.length > 0 && !result && !loading && (
        <div className="history-container">
          {history.map((h, i) => (
            <span key={i} className="history-pill" onClick={() => handleCheck(h)}>{h}</span>
          ))}
        </div>
      )}

      {error && (
        <div style={{ textAlign: 'center', marginBottom: '3rem' }}>
          <p style={{ color: 'var(--danger)', fontSize: '0.9rem' }}>Error: {error}</p>
        </div>
      )}

      {result && (
        <div className="results-container" ref={reportRef}>
          
          <div className="console-wrapper">
             <div className="console-header" onClick={() => setShowConsole(!showConsole)}>
                <span className="console-title">Diagnostic Trace {visibleLogs.length}/{result.trace?.length || 0}</span>
                <span style={{ fontSize: '0.7rem' }}>{showConsole ? '▼ Close' : '▲ View Trace'}</span>
             </div>
             {showConsole && (
               <div className="console-body" ref={consoleBodyRef}>
                  {visibleLogs.map((log, i) => (
                    log && (
                      <div key={i} className="log-entry">
                        <span className="log-time">[{log.timestamp}]</span>
                        <span className="log-msg">{log.message}</span>
                      </div>
                    )
                  ))}
               </div>
             )}
          </div>

          <div className="grade-container">
            <div className={`grade-circle grade-${result.security_grade}`}>
              <span className="grade-letter">{result.security_grade}</span>
              <span className="grade-label">Grade</span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'center', marginBottom: '2rem', flexWrap: 'wrap' }}>
             <div className="badge-valid" style={{ background: 'var(--primary-glow)', color: 'var(--primary)', borderColor: 'var(--primary)' }}>
                {result.handshake_time}ms
             </div>
             <div className="badge-valid" style={{ background: 'var(--glass-bg)', color: 'var(--value-color)' }}>
                {result.alpn || 'N/A'}
             </div>
             {result.geo && (
               <>
                 <div className="geo-badge">
                    📍 {result.geo.city || 'Unknown'}, {result.geo.country || 'Unknown'}
                 </div>
                 {result.geo.is_cdn && (
                   <div className="geo-badge cdn-glow">
                     ⚡ {result.geo.isp} (CDN)
                   </div>
                 )}
               </>
             )}
          </div>

          <div className="checklist">
            {result.checklist.map((item, i) => (
              <div className="check-item" key={i} style={{ animationDelay: `${i * 0.1}s` }}>
                <div className={`check-icon ${item.status}`}></div>
                <div className="check-label">{item.label}</div>
              </div>
            ))}
          </div>

          <div className="protocols-grid">
            {result.protocols && Object.entries(result.protocols).map(([name, active], i) => (
              <div key={i} className={`proto-pill ${active ? 'active' : 'inactive'}`}>
                <span className="proto-name">{name}</span>
                <span className="proto-status">{active ? '✔️' : '❌'}</span>
              </div>
            ))}
          </div>

          <div className="chain-viz">
            {result.chain && result.chain.map((cert, index) => (
              <div key={index} style={{ width: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1.25rem' }}>
                <div className="cert-card">
                  <div className="lock-container">
                    <div className="lock-icon">🔒</div>
                    <div className="lock-label">{index === 0 ? 'Server' : 'Chain'}</div>
                  </div>
                  <div className="cert-content">
                    <div className="cert-header">
                      <div className="cn">{cert.common_name}</div>
                      {index === 0 && <div className="badge-valid">VALID CERTIFICATE</div>}
                    </div>
                    <div className="grid-info">
                      <div className="info-box">
                        <label>Issuer</label>
                        <span>{cert.issuer}</span>
                      </div>
                      <div className="info-box">
                        <label>Expires</label>
                        <span>{new Date(cert.valid_to).toLocaleDateString()}</span>
                      </div>
                    </div>
                  </div>
                </div>
                {index < result.chain.length - 1 && <div className="arrow">↓</div>}
              </div>
            ))}
          </div>

          <div className="details-section">
            <div className="detail-row">
              <span className="label">Encryption & Cipher</span>
              <span className="value">
                {result.cipher_info?.name || 'Unknown'} ({result.cipher_info?.bits || 0} bits - {result.cipher_info?.strength || 'Weak'})
              </span>
            </div>

            <div className="detail-row" style={{ marginTop: '1.5rem' }}>
              <span className="label">SHA-256 FINGERPRINT</span>
              <span className="value mono">{result.chain?.[0]?.fingerprint_sha256 || 'N/A'}</span>
            </div>

            {result.chain?.[0]?.sans && result.chain[0].sans.length > 0 && (
              <div className="detail-row" style={{ marginTop: '1.5rem' }}>
                <span className="label">SUBJECT ALTERNATIVE NAMES</span>
                <div className="sans-list">
                  {result.chain[0].sans.slice(0, 30).map((san, idx) => (
                    <span key={idx} className="san-badge">{san}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
          
          <div className="action-grid">
            <button className="primary-action-btn" onClick={downloadPDF}>
              📄 Download PDF Report
            </button>
            <button className="primary-action-btn" style={{ background: 'var(--success)' }} onClick={downloadICS}>
              📅 Add to Calendar
            </button>
          </div>
        </div>
      )}

      <footer style={{ textAlign: 'center' }}>
        v1.3.1
      </footer>
    </main>
  );
}
