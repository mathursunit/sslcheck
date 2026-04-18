'use client';

import { useState } from 'react';

interface CertDetail {
  subject: Record<string, string>;
  issuer: Record<string, string>;
  not_after: string;
  is_expired: boolean;
  fingerprint_sha256: string;
}

interface SSLResult {
  hostname: string;
  is_valid: boolean;
  chain: CertDetail[];
  errors: string[];
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
      const response = await fetch('/api/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Failed to check SSL');
      }

      const data = await response.json();
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
        <div className="search-inner">
          <input
            type="text"
            placeholder="Enter hostname (e.g. google.com)"
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleCheck()}
          />
          <button onClick={handleCheck} disabled={loading}>
            {loading ? <div className="loader"></div> : 'Check SSL'}
          </button>
        </div>
        {error && <p style={{ color: 'var(--danger)', marginTop: '1rem', textAlign: 'center' }}>{error}</p>}
      </div>

      {result && (
        <div className="results">
          <div className="status-card">
            <div className="status-header">
              <div>
                <h2 style={{ fontSize: '1.5rem', marginBottom: '0.25rem' }}>{result.hostname}</h2>
                <div style={{ color: '#64748b', fontSize: '0.9rem' }}>
                  Total {result.chain.length} certificates in chain
                </div>
              </div>
              <div className={`badge ${result.is_valid ? 'valid' : 'invalid'}`}>
                {result.is_valid ? 'Valid Certificate' : 'Issues Found'}
              </div>
            </div>

            {result.errors.length > 0 && (
              <div style={{ marginBottom: '2rem', padding: '1rem', background: 'rgba(239, 68, 68, 0.1)', borderRadius: '1rem', border: '1px solid rgba(239, 68, 68, 0.2)' }}>
                {result.errors.map((err, i) => (
                  <div key={i} style={{ color: 'var(--danger)', fontSize: '0.9rem' }}>• {err}</div>
                ))}
              </div>
            )}

            <div className="chain-container">
              {result.chain.map((cert, index) => (
                <div className="chain-item" key={index}>
                  <div className="chain-index">{index === 0 ? 'Leaf' : index === result.chain.length - 1 ? 'Root' : `Intermediate ${index}`}</div>
                  <div className="cert-name">{cert.subject.CN || 'Unknown Common Name'}</div>
                  
                  <div className="cert-meta">
                    <div className="meta-group">
                      <label>Issuer</label>
                      <span>{cert.issuer.CN || 'Unknown'}</span>
                    </div>
                    <div className="meta-group">
                      <label>Expires</label>
                      <span style={{ color: cert.is_expired ? 'var(--danger)' : 'inherit' }}>
                        {new Date(cert.not_after).toLocaleDateString()}
                      </span>
                    </div>
                    <div className="meta-group" style={{ gridColumn: '1 / -1' }}>
                      <label>SHA-256 Fingerprint</label>
                      <span style={{ fontSize: '0.75rem', opacity: 0.7, fontFamily: 'monospace' }}>{cert.fingerprint_sha256}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
