// Static "how this works" panel for judges. No props, no data fetching.
const STEPS = [
  ['1. Bait', 'A fake admin portal and fake API (/admin, /wp-login.php, /.env, /api/v1/users...) look real to bots but connect to nothing.'],
  ['2. Capture', 'Every request is logged, never executed or reflected. The database acts as the queue between services.'],
  ['3. Classify', 'Regex rules run first (free, instant). The LLM is called only when rules are unsure, and results are cached.'],
  ['4. Map', 'Each attack gets a severity, a MITRE ATT&CK technique, a plain-English explanation and a ready-to-use Nginx/firewall rule.'],
  ['5. Show', 'This dashboard polls the API every ~3 seconds: live feed, charts, world map, top attackers and incident reports.'],
];

export default function AboutPanel() {
  return (
    <div className="card">
      <div className="card-title">How this works</div>
      <div className="col">
        {STEPS.map(([title, text]) => (
          <div key={title}>
            <strong>{title}</strong>
            <div className="muted">{text}</div>
          </div>
        ))}
        <div className="muted">
          Honest note: BotTrap is a research and awareness tool. It is an early-warning system, not a replacement for a firewall.
        </div>
      </div>
    </div>
  );
}
