import React from 'react';

function formatTime(isoString) {
  if (!isoString) return '--:--:--';
  const d = new Date(isoString);
  if (Number.isNaN(d.getTime())) return isoString;
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function LiveFeed({ events, onSelect, loading, error }) {
  return (
    <div className="card">
      <div className="row-between mb-4">
        <div className="card-title" style={{ marginBottom: 0 }}>
          LIVE ATTACK FEED
        </div>
        <span className="muted mono">{events ? `${events.length} events` : ''}</span>
      </div>

      {error && <div className="error-state">Failed to load feed: {error}</div>}

      {!error && loading && (!events || events.length === 0) && (
        <div className="col">
          <div className="skeleton" style={{ height: '72px' }} />
          <div className="skeleton" style={{ height: '72px' }} />
          <div className="skeleton" style={{ height: '72px' }} />
        </div>
      )}

      {!error && !loading && (!events || events.length === 0) && (
        <div className="empty-state">
          No attack events captured yet. Run the simulator or wait for probes.
        </div>
      )}

      {!error && events && events.length > 0 && (
        <div className="card-scroll">
          {events.map((ev) => {
            const sev = ev.severity || 'Low';
            const sevKey = sev.toLowerCase();
            const target = ev.query ? `${ev.path}?${ev.query}` : ev.path || '/';
            const preview = ev.body ? ev.body.slice(0, 140) : '';

            return (
              <div
                key={ev.id}
                className={`feed-item sev-${sevKey}`}
                onClick={() => onSelect && onSelect(ev)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onSelect && onSelect(ev);
                  }
                }}
              >
                <div className="row-between">
                  <div className="row">
                    <span className={`badge badge-${sevKey}`}>{sev}</span>
                    <strong>{ev.attack_type || 'Pending Classification'}</strong>
                    {ev.mitre_id && (
                      <span className="badge badge-mitre mono">{ev.mitre_id}</span>
                    )}
                  </div>
                  <span className="muted mono">{formatTime(ev.created_at)}</span>
                </div>

                <div className="row-between mt-4">
                  <span className="mono">
                    {ev.method || 'GET'} {target}
                  </span>
                  <span className="muted mono">
                    {ev.ip}
                    {ev.country ? ` (${ev.country})` : ''}
                  </span>
                </div>

                {preview && <div className="payload mt-4">{preview}</div>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
