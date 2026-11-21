// frontend/src/components/StatCards.jsx
// Top row of 4 number cards. Data comes from /api/stats (passed in by App.jsx).

const ITEMS = [
  { key: 'total', label: 'Total attacks' },
  { key: 'last_hour', label: 'Last hour' },
  { key: 'unique_ips', label: 'Unique attackers' },
  { key: 'pending', label: 'Pending analysis' },
];

export default function StatCards({ stats, loading }) {
  // Loading state: 4 skeleton boxes
  if (loading && !stats) {
    return (
      <div className="grid grid-4">
        {ITEMS.map((it) => (
          <div className="card" key={it.key}>
            <div className="skeleton" style={{ height: 52 }} />
          </div>
        ))}
      </div>
    );
  }

  // Empty state
  if (!stats) {
    return (
      <div className="card">
        <div className="empty-state">No stats yet.</div>
      </div>
    );
  }

  return (
    <div className="grid grid-4">
      {ITEMS.map((it) => (
        <div className="card" key={it.key}>
          <div className="card-title">{it.label}</div>
          <div className="stat">
            <div className="stat-value">{stats[it.key] ?? 0}</div>
          </div>
        </div>
      ))}
    </div>
  );
}
