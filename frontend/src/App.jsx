// frontend/src/App.jsx
// Main dashboard layout. All data fetching happens HERE (one request per endpoint),
// components only receive props (Section 7.2).
import { useState } from 'react';
import { api } from './api/client';
import usePolling from './hooks/usePolling';
import {
  USE_MOCK, mockStats, mockEvents, mockTimeline, mockMitre, mockGeo, mockAttackers,
} from './mockData';

import Navbar from './components/Navbar';
import StatCards from './components/StatCards';
import TimelineChart from './components/TimelineChart';
import FilterBar from './components/FilterBar';
import Slot from './lib/Slot';

export default function App() {
  const [useMock, setUseMock] = useState(USE_MOCK);
  const [filters, setFilters] = useState({ severity: '', attack_type: '' });
  const [selected, setSelected] = useState(null); // event shown in the detail modal

  // Real API call, or mock data when useMock is true
  const get = (path, mockFn) => () => (useMock ? Promise.resolve(mockFn()) : api(path));

  // Build events URL from the active filters
  const qs = new URLSearchParams({ limit: '50' });
  if (filters.severity) qs.set('severity', filters.severity);
  if (filters.attack_type) qs.set('attack_type', filters.attack_type);

  const stats = usePolling(get('/api/stats', mockStats), 3000, [useMock]);
  const events = usePolling(
    get('/api/events?' + qs.toString(), () => mockEvents(filters)),
    3000,
    [useMock, filters.severity, filters.attack_type] // refresh immediately when a filter or mock mode changes
  );
  const timeline = usePolling(get('/api/timeline?minutes=60&bucket=2', mockTimeline), 3000, [useMock]);
  const mitre = usePolling(get('/api/mitre', mockMitre), 5000, [useMock]);
  const geo = usePolling(get('/api/geo', mockGeo), 5000, [useMock]);
  const attackers = usePolling(get('/api/attackers?limit=10', mockAttackers), 5000, [useMock]);

  // IP used by the incident-report button: selected event first, else top attacker
  const reportIp = (selected && selected.ip) || attackers.data?.attackers?.[0]?.ip;

  // API down = the stats request is currently failing in live mode
  const apiDown = !useMock && !!stats.error;

  return (
    <div className="app-shell">
      <Navbar useMock={useMock} onToggleMock={setUseMock} />
      <div className="container col">
        {apiDown && (
          <div className="error-state row-between">
            <div>
              <strong>Cannot reach the Dashboard API:</strong> {stats.error}.<br />
              Make sure <code className="mono">python -m api.app</code> is running in a terminal on port 5001.
            </div>
            <button
              type="button"
              className="btn btn-ghost"
              style={{ whiteSpace: 'nowrap' }}
              onClick={() => setUseMock(true)}
            >
              Use Demo Mock Data
            </button>
          </div>
        )}
        {useMock && (
          <div className="banner banner-medium row-between">
            <span>Demo Mock Mode: Showing static sample data (6 events). Real attacks require Live API mode.</span>
            <button
              type="button"
              className="btn"
              style={{ padding: '4px 10px', fontSize: '12px' }}
              onClick={() => setUseMock(false)}
            >
              Switch to Live API
            </button>
          </div>
        )}

        <Slot name="ThreatLevelBanner" level={stats.data?.threat_level} />
        <StatCards stats={stats.data} loading={stats.loading} />
        <FilterBar filters={filters} onChange={setFilters} />

        <div className="grid grid-main">
          <div className="col">
            <TimelineChart points={timeline.data?.points} loading={timeline.loading} />
            <div className="grid grid-2">
              <Slot name="AttackTypeChart" byType={stats.data?.by_type} />
              <Slot name="MitreChart" items={mitre.data?.items} />
            </div>
          </div>
          <Slot
            name="LiveFeed"
            events={events.data?.events}
            onSelect={setSelected}
            loading={events.loading}
            error={events.error}
          />
        </div>

        <div className="grid grid-2">
          <Slot name="AttackMap" points={geo.data?.points} />
          <Slot name="TopAttackers" attackers={attackers.data?.attackers} />
        </div>

        {reportIp && (
          <div className="row">
            <span className="muted">Incident report for {reportIp}:</span>
            <Slot name="ReportButton" ip={reportIp} />
          </div>
        )}

        <Slot name="AboutPanel" />
      </div>

      {selected && (
        <Slot name="EventDetailModal" silent event={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}
