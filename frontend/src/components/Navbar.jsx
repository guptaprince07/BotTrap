// frontend/src/components/Navbar.jsx
export default function Navbar({ useMock, onToggleMock }) {
  return (
    <nav className="navbar">
      <div className="brand">🍯 HoneyLens</div>
      <div className="row">
        {useMock ? (
          <div className="row">
            <span className="badge badge-medium">Demo Mock Mode (Static Sample)</span>
            {onToggleMock && (
              <button
                type="button"
                className="btn"
                style={{ padding: '4px 10px', fontSize: '12px' }}
                onClick={() => onToggleMock(false)}
              >
                Switch to Live API
              </button>
            )}
          </div>
        ) : (
          <div className="row muted">
            <span className="live-dot" />
            <span>Live Feed · polling :5001 every 3s</span>
            {onToggleMock && (
              <button
                type="button"
                className="btn btn-ghost"
                style={{ padding: '4px 10px', fontSize: '12px', opacity: 0.8 }}
                onClick={() => onToggleMock(true)}
              >
                Demo Mock
              </button>
            )}
          </div>
        )}
      </div>
    </nav>
  );
}
