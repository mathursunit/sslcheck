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
  status: 'success' | 'error';
}

interface SSLResult {
  hostname: string;
  ip: string;
  server_type: string;
  chain: CertDetail[];
  checklist: CheckItem[];
  protocols: Record<string, boolean>;
  security_grade: string;
  hsts_info: { enabled: boolean; max_age: number };
  is_valid: boolean;
}

export default function SSLCheck() {
  const [hostname, setHostname] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SSLResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [history, setHistory] = useState<string[]>([]);
  const reportRef = useRef<HTMLDivElement>(null);

  // Theme support
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme') as 'dark' | 'light';
    if (savedTheme) {
      setTheme(savedTheme);
      document.documentElement.setAttribute('data-theme', savedTheme);
    }
    // Load history
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

    try {
      const response = await fetch('/api/run-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname: hostToQuery }),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Analysis failed');
      
      setResult(data);
      
      // Update history
      const newHistory = [hostToQuery, ...history.filter(h => h !== hostToQuery)].slice(0, 5);
      setHistory(newHistory);
      localStorage.setItem('ssl_history', JSON.stringify(newHistory));
      
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const downloadICS = () => {
    if (!result) return;
    const cert = result.chain[0];
    const expiryDate = new Date(cert.valid_to);
    const dateStr = expiryDate.toISOString().replace(/-|:|\.\d+/g, '');
    
    const icsContent = [
      'BEGIN:VCALENDAR',
      'VERSION:2.0',
      'BEGIN:VEVENT',
      `DTSTART:${dateStr}`,
      `DTEND:${dateStr}`,
      `SUMMARY:SSL Certificate Expiry: ${result.hostname}`,
      `DESCRIPTION:Your SSL certificate for ${result.hostname} expires today.`,
      'END:VEVENT',
      'END:VCALENDAR'
    ].join('\r\n');

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
      const imgProperties = pdf.getImageProperties(dataUrl);
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = (imgProperties.height * pdfWidth) / imgProperties.width;
      
      pdf.addImage(dataUrl, 'PNG', 0, 0, pdfWidth, pdfHeight);
      pdf.save(`SSLCheck_Report_${result?.hostname}.pdf`);
    } catch (err) {
      console.error('PDF generation failed', err);
    }
  };

  return (
    <main>
      <button className="theme-toggle" onClick={toggleTheme} aria-label="Toggle Theme">
        {theme === 'dark' ? '☀️' : '🌙'}
      </button>

      <header>
        <h1>SSLCheck</h1>
        <p className="subtitle">Enterprise SSL Monitoring & Deep Analysis</p>
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
          <div className="grade-container">
            <div className={`grade-circle grade-${result.security_grade}`}>
              <span className="grade-letter">{result.security_grade}</span>
              <span className="grade-label">Grade</span>
            </div>
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
            {Object.entries(result.protocols).map(([name, active], i) => (
              <div key={i} className={`proto-pill ${active ? 'active' : 'inactive'}`}>
                <span className="proto-name">{name}</span>
                <span className="proto-status">{active ? '✔️' : '❌'}</span>
              </div>
            ))}
          </div>

          <div className="chain-viz">
            {result.chain.map((cert, index) => (
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
              <span className="label">SHA-256 FINGERPRINT</span>
              <span className="value mono">{result.chain[0].fingerprint_sha256}</span>
            </div>

            {result.chain[0].sans && result.chain[0].sans.length > 0 && (
              <div className="detail-row" style={{ marginTop: '1.5rem' }}>
                <span className="label">SUBJECT ALTERNATIVE NAMES</span>
                <div className="sans-list">
                  {result.chain[0].sans.slice(0, 50).map((san, idx) => (
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
        v1.2.0
      </footer>
    </main>
  );
}
