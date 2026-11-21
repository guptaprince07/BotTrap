// frontend/src/components/FilterBar.jsx
// Two dropdowns: severity + attack type. Empty string = "all".

const SEVERITIES = ['Low', 'Medium', 'High', 'Critical'];
const TYPES = [
  'SQL Injection', 'XSS', 'Brute Force', 'Credential Stuffing', 'Path Traversal',
  'Command Injection', 'Vulnerability Scan', 'Recon', 'Sensitive File Probe',
  'Web Shell Upload', 'Other',
];

export default function FilterBar({ filters, onChange }) {
  const set = (key, value) => onChange({ ...filters, [key]: value });

  return (
    <div className="card">
      <div className="row">
        <span className="muted">Filter:</span>

        <select
          className="select"
          value={filters.severity}
          onChange={(e) => set('severity', e.target.value)}
        >
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>

        <select
          className="select"
          value={filters.attack_type}
          onChange={(e) => set('attack_type', e.target.value)}
        >
          <option value="">All attack types</option>
          {TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>

        <button
          className="btn btn-ghost"
          onClick={() => onChange({ severity: '', attack_type: '' })}
        >
          Reset
        </button>
      </div>
    </div>
  );
}
