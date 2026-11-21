import React from 'react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
} from 'recharts';
import { COLORS, PIE_COLORS } from '../theme';

export default function AttackTypeChart({ byType, loading = false, error = null }) {
  const entries = byType
    ? Object.entries(byType)
        .map(([name, value]) => ({ name, value }))
        .filter((item) => item.value > 0)
        .sort((a, b) => b.value - a.value)
    : [];

  return (
    <div className="card">
      <div className="card-title">Attacks by Type</div>

      {loading && !byType ? (
        <div className="chart-box skeleton" />
      ) : error ? (
        <div className="error-state">Failed to load attack breakdown: {error}</div>
      ) : entries.length === 0 ? (
        <div className="empty-state">No attack classifications recorded yet.</div>
      ) : (
        <div className="chart-box">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={entries}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="48%"
                innerRadius={52}
                outerRadius={82}
                paddingAngle={3}
                stroke={COLORS.grid}
              >
                {entries.map((entry, idx) => (
                  <Cell
                    key={entry.name}
                    fill={PIE_COLORS[idx % PIE_COLORS.length]}
                  />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: '#121a2b',
                  borderColor: COLORS.grid,
                  borderRadius: '8px',
                  color: COLORS.text,
                }}
                itemStyle={{ color: COLORS.text }}
              />
              <Legend
                verticalAlign="bottom"
                height={32}
                wrapperStyle={{ fontSize: '12px', color: COLORS.muted }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
