// frontend/src/components/Navbar.jsx
export default function Navbar() {
  return (
    <nav className="navbar">
      <div className="brand">🍯 HoneyLens</div>
      <div className="row muted">
        <span className="live-dot" />
        <span>Live · updates every 3s</span>
      </div>
    </nav>
  );
}
