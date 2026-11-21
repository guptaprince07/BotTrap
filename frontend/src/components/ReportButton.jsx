import React, { useState } from 'react';
import { api } from '../api/client';

export default function ReportButton({ ip }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  if (!ip) return null;

  const handleGenerate = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api('/api/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      });
      setReport(res.report || 'No summary returned.');
    } catch (err) {
      setError(err.message || 'Failed to generate incident report.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="col">
      <div className="row-between">
        <span className="muted mono">Attacker Profile: {ip}</span>
        <button
          type="button"
          className="btn"
          onClick={handleGenerate}
          disabled={loading}
        >
          {loading ? 'Generating Report...' : 'Generate Incident Report'}
        </button>
      </div>

      {loading && <div className="skeleton" style={{ height: '64px' }} />}

      {error && <div className="error-state">{error}</div>}

      {!loading && !error && report && (
        <div className="card">
          <div className="card-title">INCIDENT REPORT — {ip}</div>
          <p>{report}</p>
        </div>
      )}
    </div>
  );
}
