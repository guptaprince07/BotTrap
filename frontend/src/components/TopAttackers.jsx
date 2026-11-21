import React from 'react';

export default function TopAttackers({ attackers: propAttackers, loading = false, error = null }) {
  const attackers = propAttackers || [];

  return (
    <div className="card">
      <div className="row-between mb-4">
        <div className="card-title" style={{ marginBottom: 0 }}>
          TOP ATTACKERS
        </div>
        <span className="muted mono">{attackers.length} identified</span>
      </div>

      {error ? (
        <div className="error-state">Failed to load top attackers: {error}</div>
      ) : loading && attackers.length === 0 ? (
        <div className="col">
          <div className="skeleton" style={{ height: '36px' }} />
          <div className="skeleton" style={{ height: '36px' }} />
          <div className="skeleton" style={{ height: '36px' }} />
        </div>
      ) : attackers.length === 0 ? (
        <div className="empty-state">No attackers recorded yet.</div>
      ) : (
        <div className="card-scroll" style={{ maxHeight: '340px' }}>
          <table className="table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Country</th>
                <th>Events</th>
                <th>Top Attack</th>
              </tr>
            </thead>
            <tbody>
              {attackers.map((att, idx) => (
                <tr key={att.ip || idx}>
                  <td className="mono">{att.ip}</td>
                  <td>{att.country || 'Unknown'}</td>
                  <td>
                    <strong>{att.count}</strong>
                  </td>
                  <td>
                    <span className="badge badge-high">{att.top_type || 'Unknown'}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
