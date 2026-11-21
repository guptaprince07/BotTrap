import React, { useState } from "react";

export default function RulesPanel({
  pendingRules = [],
  activeRules = [],
  loading = false,
  error = null,
  onAction,
}) {
  const [tab, setTab] = useState("pending");
  const [busyId, setBusyId] = useState(null);

  const rules = tab === "pending" ? pendingRules : activeRules;

  async function handleAction(ruleId, action) {
    setBusyId(ruleId);
    try {
      await onAction(ruleId, action);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <section className="card rules-panel">
      <div className="card-header">
        <h2>Self-Evolving Rules</h2>
        <div className="tabs" role="tablist">
          <button
            type="button"
            className={tab === "pending" ? "tab active" : "tab"}
            onClick={() => setTab("pending")}
          >
            Pending review ({pendingRules.length})
          </button>
          <button
            type="button"
            className={tab === "active" ? "tab active" : "tab"}
            onClick={() => setTab("active")}
          >
            Active rules ({activeRules.length})
          </button>
        </div>
      </div>

      {loading && <p className="muted">Loading learned rules...</p>}
      {error && <p className="error">Failed to load rules: {error}</p>}

      {!loading && !error && rules.length === 0 && (
        <p className="muted">
          No learned rules yet. They appear when the LLM sees a new attack.
        </p>
      )}

      {!loading && !error && rules.length > 0 && (
        <div className="rules-list">
          {rules.map((rule) => (
            <div key={rule.id} className="rule-row">
              <div className="rule-meta">
                <code className="payload">{rule.pattern}</code>
                <span className="badge">{rule.attack_type || "Unknown"}</span>
                <span className={`severity severity-${(rule.severity || "low").toLowerCase()}`}>
                  {rule.severity || "Low"}
                </span>
                <span className="muted">Target: {rule.target || "any"}</span>
                <span className="muted">Hits: {rule.hit_count ?? 0}</span>
              </div>

              <div className="rule-actions">
                {tab === "pending" ? (
                  <>
                    <button
                      type="button"
                      disabled={busyId === rule.id}
                      onClick={() => handleAction(rule.id, "approve")}
                    >
                      Approve &amp; Add to Rules
                    </button>
                    <button
                      type="button"
                      disabled={busyId === rule.id}
                      onClick={() => handleAction(rule.id, "reject")}
                    >
                      Reject
                    </button>
                  </>
                ) : (
                  <button
                    type="button"
                    disabled={busyId === rule.id}
                    onClick={() => handleAction(rule.id, "disable")}
                  >
                    Disable
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
