// frontend/src/components/TimelineChart.jsx
// Line chart: attacks per time bucket.
import {
  ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
} from 'recharts';
import { COLORS } from '../theme';

// "2025-01-01T12:00:00Z" -> "12:00" (local time)
function fmt(t) {
  const d = new Date(t);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export default function TimelineChart({ points, loading }) {
  let body;

  if (loading && !points) {
    body = <div className="skeleton" style={{ height: '100%' }} />;
  } else if (!points || points.length === 0) {
    body = <div className="empty-state">No attacks in this time window.</div>;
  } else {
    const data = points.map((p) => ({ time: fmt(p.t), count: p.count }));
    body = (
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <CartesianGrid stroke={COLORS.grid} strokeDasharray="3 3" />
          <XAxis dataKey="time" stroke={COLORS.muted} fontSize={12} />
          <YAxis stroke={COLORS.muted} fontSize={12} allowDecimals={false} />
          <Tooltip
            contentStyle={{
              background: '#121a2b',
              border: '1px solid ' + COLORS.grid,
              color: COLORS.text,
            }}
          />
          <Line
            type="monotone"
            dataKey="count"
            stroke={COLORS.accent}
            strokeWidth={2}
            dot={false}
          />
        </LineChart>
      </ResponsiveContainer>
    );
  }

  return (
    <div className="card">
      <div className="card-title">Attack timeline</div>
      <div className="chart-box">{body}</div>
    </div>
  );
}
