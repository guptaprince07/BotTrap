import React from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';
import { COLORS } from '../theme';

export default function MitreChart({ items, loading = false, error = null }) {
  const chartData = Array.isArray(items)
    ? items
        .slice(0, 7)
        .map((item) => ({
          label: `${item.mitre_id} · ${item.name}`,
          shortLabel: item.mitre_id,
          name: item.name,
          count: item.count,
        }))
    : [];

  return (
    <div className="card">
      <div className="card-title">Top MITRE ATT&amp;CK Techniques</div>

      {loading && !items ? (
        <div className="chart-box skeleton" />
      ) : error ? (
        <div className="error-state">Failed to load MITRE data: {error}</div>
      ) : chartData.length === 0 ? (
        <div className="empty-state">No MITRE ATT&amp;CK mappings yet.</div>
      ) : (
        <div className="chart-box">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={chartData}
              layout="vertical"
              margin={{ top: 4, right: 20, left: 10, bottom: 4 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke={COLORS.grid} horizontal={false} />
              <XAxis
                type="number"
                allowDecimals={false}
                tick={{ fill: COLORS.muted, fontSize: 12 }}
                axisLine={{ stroke: COLORS.grid }}
                tickLine={false}
              />
              <YAxis
                type="category"
                dataKey="shortLabel"
                width={74}
                tick={{ fill: COLORS.text, fontSize: 12 }}
                axisLine={{ stroke: COLORS.grid }}
                tickLine={false}
              />
              <Tooltip
                cursor={{ fill: 'rgba(37, 49, 75, 0.35)' }}
                contentStyle={{
                  backgroundColor: '#121a2b',
                  borderColor: COLORS.grid,
                  borderRadius: '8px',
                  color: COLORS.text,
                }}
                formatter={(value, _name, props) => [
                  `${value} events`,
                  props?.payload?.name || 'Count',
                ]}
              />
              <Bar
                dataKey="count"
                fill={COLORS.accent2}
                radius={[0, 6, 6, 0]}
                barSize={18}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
