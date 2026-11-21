// frontend/src/App.jsx  (TEMPORARY test version, replaced in step 5)
import { useState } from 'react';
import { api } from './api/client';
import usePolling from './hooks/usePolling';
import Navbar from './components/Navbar';
import StatCards from './components/StatCards';
import TimelineChart from './components/TimelineChart';
import FilterBar from './components/FilterBar';

const MOCK_STATS = { total: 123, last_hour: 40, unique_ips: 17, pending: 2 };
const MOCK_POINTS = [
  { t: '2025-01-01T12:00:00Z', count: 5 },
  { t: '2025-01-01T12:02:00Z', count: 12 },
  { t: '2025-01-01T12:04:00Z', count: 8 },
  { t: '2025-01-01T12:06:00Z', count: 20 },
];

export default function App() {
  const [filters, setFilters] = useState({ severity: '', attack_type: '' });

  const { data: stats, loading: statsLoading, error: statsError } =
    usePolling(() => api('/api/stats'), 3000);
  const { data: timeline, loading: tlLoading, error: tlError } =
    usePolling(() => api('/api/timeline?minutes=60&bucket=2'), 3000);

  return (
    <div className="app-shell">
      <Navbar />
      <div className="container col">
        <FilterBar filters={filters} onChange={setFilters} />
        <StatCards stats={statsError ? MOCK_STATS : stats} loading={statsLoading && !statsError} />
        <TimelineChart
          points={(statsError || tlError) ? MOCK_POINTS : timeline?.points}
          loading={tlLoading && !tlError}
        />
        <div className="muted">Current filters: {JSON.stringify(filters)}</div>
      </div>
    </div>
  );
}
