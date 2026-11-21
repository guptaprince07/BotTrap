// frontend/src/lib/ErrorBoundary.jsx
// If one teammate's component crashes, only its card shows an error; the rest of the dashboard keeps working.
import { Component } from 'react';

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { failed: false, message: '' };
  }
  static getDerivedStateFromError(err) {
    return { failed: true, message: String(err && err.message ? err.message : err) };
  }
  componentDidCatch(err) {
    console.error('Component crashed:', this.props.name, err);
  }
  render() {
    if (this.state.failed) {
      return (
        <div className="card">
          <div className="card-title">{this.props.name}</div>
          <div className="error-state">This widget failed to render: {this.state.message}</div>
        </div>
      );
    }
    return this.props.children;
  }
}
