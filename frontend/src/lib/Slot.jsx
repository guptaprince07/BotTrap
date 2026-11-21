// frontend/src/lib/Slot.jsx
// Renders a teammate's component by name. If their file is not in the repo yet,
// a placeholder card is shown instead, so nothing crashes and no import breaks.
import ErrorBoundary from './ErrorBoundary';

const modules = import.meta.glob('../components/*.jsx', { eager: true });

const OWNERS = {
  ThreatLevelBanner: 'Prince', AboutPanel: 'Prince',
  AttackTypeChart: 'Sejal', MitreChart: 'Sejal',
  LiveFeed: 'Neha', EventDetailModal: 'Neha', ReportButton: 'Neha',
  AttackMap: 'Vidanshi', TopAttackers: 'Vidanshi',
};

export default function Slot({ name, silent = false, ...props }) {
  const mod = modules['../components/' + name + '.jsx'];
  const Comp = mod && mod.default;

  if (!Comp) {
    if (silent) return null; // e.g. modals: show nothing while missing
    return (
      <div className="card">
        <div className="card-title">{name}</div>
        <div className="empty-state">Waiting for {OWNERS[name] || 'teammate'} to push {name}.jsx</div>
      </div>
    );
  }
  return (
    <ErrorBoundary name={name}>
      <Comp {...props} />
    </ErrorBoundary>
  );
}
