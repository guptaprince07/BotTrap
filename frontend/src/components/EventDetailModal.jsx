import React, { useState } from 'react';
import ReportButton from './ReportButton';

export default function EventDetailModal({ event, onClose }) {
  const [copied, setCopied] = useState(false);

  if (!event) return null;

  const sev = event.severity || 'Low';
  const sevKey = sev.toLowerCase();
  const fullTarget = event.query ? `${event.path}?${event.query}` : event.path || '/';

  const handleCopyRule = async () => {
    if (!event.recommended_rule) return;
    try {
      await navigator.clipboard.writeText(event.recommended_rule);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div
      className="modal-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget && onClose) onClose();
      }}
    >
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="event-modal-title">
        <div className="row-between mb-4">
          <div className="row">
            <span className={`badge badge-${sevKey}`}>{sev}</span>
            <h3 id="event-modal-title">{event.attack_type || 'Unclassified Event'}</h3>
            {event.mitre_id && (
              <span className="badge badge-mitre mono">
                {event.mitre_id}
                {event.mitre_name ? ` · ${event.mitre_name}` : ''}
              </span>
            )}
          </div>
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Close
          </button>
        </div>

        <div className="col">
          <div className="row-between">
            <span className="muted">Source IP</span>
            <span className="mono">
              {event.ip}
              {event.city || event.country
                ? ` — ${[event.city, event.country].filter(Boolean).join(', ')}`
                : ''}
            </span>
          </div>

          <div className="row-between">
            <span className="muted">Timestamp</span>
            <span className="mono">{event.created_at || 'Unknown'}</span>
          </div>

          <div className="row-between">
            <span className="muted">Likely Tool / Classifier</span>
            <span className="mono">
              {event.likely_tool || 'unknown'} ({event.source || 'pending'})
            </span>
          </div>

          <div>
            <div className="card-title">AI THREAT EXPLANATION</div>
            <p>{event.explanation || 'Awaiting classification pipeline analysis.'}</p>
          </div>

          <div>
            <div className="card-title">CAPTURED REQUEST &amp; PAYLOAD</div>
            <pre className="payload">
              {`${event.method || 'GET'} ${fullTarget}\nUser-Agent: ${event.user_agent || 'none'}${
                event.body ? `\n\n${event.body}` : ''
              }`}
            </pre>
          </div>

          <div>
            <div className="row-between mb-4">
              <div className="card-title" style={{ marginBottom: 0 }}>
                RECOMMENDED DEFENSE RULE
              </div>
              {event.recommended_rule && (
                <button type="button" className="btn btn-ghost" onClick={handleCopyRule}>
                  {copied ? 'Copied!' : 'Copy Rule'}
                </button>
              )}
            </div>
            <pre className="payload">
              {event.recommended_rule || 'Rate-limit source IP at reverse proxy'}
            </pre>
          </div>

          <div className="mt-4">
            <ReportButton ip={event.ip} />
          </div>
        </div>
      </div>
    </div>
  );
}
{event?.source === "dynamic" && (
  <span className="badge learned-rule-badge">Learned rule</span>
)}
