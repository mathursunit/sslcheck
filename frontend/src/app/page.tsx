'use client';

import { useState } from 'react';

interface CertDetail {
  common_name: string;
  issuer: string;
  issuer_full: string;
  subject_full: string;
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
  is_valid: boolean;
}

export default function SSLCheck() {
  const [hostname, setHostname] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SSLResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleCheck = async () => {
    if (!hostname) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch('/api/run-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname }),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Analysis failed');
      setResult(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main>
      <header>
        <h1>SSLCheck</h1>
        <p className="subtitle">Verify certificate chain and validity on-demand.</p>
      </header>

      <div className="search-container">
        <input
          type="text"
          placeholder="Enter hostname (e.g. google.com)"
          value={hostname}
          onChange={(e) => setHostname(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleCheck()}
        />
        <button onClick={handleCheck} disabled={loading}>
          {loading ? 'Checking...' : 'Check SSL'}
        </button>
      </div>

      {error && (
        <div style={{ textAlign: 'center', marginBottom: '3rem' }}>
          <p style={{ color: 'var(--danger)', fontSize: '0.9rem' }}>Error: {error}</p>
        </div>
      )}

      {result && (
        <div className="results-container">
          <div className="checklist">
            {result.checklist.map((item, i) => (
              <div className="check-item" key={i} style={{ animationDelay: `${i * 0.1}s` }}>
                <div className={`check-icon ${item.status}`}></div>
                <div className="check-label">{item.label}</div>
              </div>
            ))}
          </div>

          <div className="chain-viz">
            {result.chain.map((cert, index) => (
              <div key={index} style={{ width: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '2rem' }}>
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
                      <div className="info-box" style={{ gridColumn: '1 / -1' }}>
                        <label>SHA-256 Fingerprint</label>
                        <span style={{ fontSize: '0.75rem', fontFamily: 'monospace' }}>{cert.fingerprint_sha256}</span>
                      </div>
                    </div>
                  </div>
                </div>
                {index < result.chain.length - 1 && <div className="arrow">↓</div>}
              </div>
            ))}
          </div>
        </div>
      )}

      <footer style={{ textAlign: 'center' }}>
        v1.1.1
      </footer>
    </main>
  );
}
