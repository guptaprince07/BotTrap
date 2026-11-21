// Colored banner showing the overall threat level (from /api/stats -> threat_level).
// Props: level ("Low" | "Medium" | "High" | "Critical" | null/undefined while loading)
const MESSAGES = {
  Low: 'No recent attack activity. Honeypot is quietly listening.',
  Medium: 'Attack activity detected in the last hour.',
  High: 'Heavy attack activity in the last 10 minutes.',
  Critical: 'Critical-severity attack detected in the last 10 minutes!',
};

export default function ThreatLevelBanner({ level }) {
  if (!level) {
    return <div className="skeleton" style={{ height: 44 }} />;
  }
  const key = String(level).toLowerCase();
  return (
    <div className={'banner banner-' + key} role="status">
      <div className="row-between">
        <span>Threat level: {level}</span>
        <span className="mono">{MESSAGES[level] || ''}</span>
      </div>
    </div>
  );
}
