// frontend/src/App.jsx

// 1. Imports go at the very top of the file
import { useState } from 'react';
import { api } from './api/client';
import usePolling from './hooks/usePolling';

export default function App() {
  const [filters, setFilters] = useState({ severity: '', attack_type: '' });

  // 2. The first code block goes inside App(), after the useState line
  const { data: stats, loading, error } = usePolling(() => api('/api/stats'), 3000);

  // 3. The second code block goes right below it, inside App() too
  const { data: events } = usePolling(
    () => api(`/api/events?severity=${filters.severity}&attack_type=${filters.attack_type}`),
    3000,
    [filters.severity, filters.attack_type]
  );

  return (
    <div>
      {/* your layout goes here (step 5) */}
    </div>
  );
}