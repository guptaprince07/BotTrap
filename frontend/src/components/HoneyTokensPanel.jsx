import React from "react";

function formatTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? "—"
    : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export default function HoneyTokensPanel({ tokens = [], loading = false, error = null }) {
  return (
    <section className="card">
      <div className="card-header">
        <h3>Honey-Tokens</h3>
      </div>

      {error ? (
        <div className="empty-state error-state">
          Failed to load honey-tokens: {String(error)}
        </div>
      ) : loading ? (
        <div className="skeleton-list" aria-busy="true">
          <div className="skeleton-row" />
          <div className="skeleton-row" />
          <div className="skeleton-row" />
        </div>
      ) : tokens.length === 0 ? (
        <div className="empty-state">
          No tokens issued yet. They appear when someone reads the fake <code>/.env</code>.
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Token</th>
                <th>Kind</th>
                <th>Issued to IP</th>
                <th>Leaked at</th>
                <th>Issued</th>
                <th>Status</th>
                <th>Uses</th>
                <th>Time to use</th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((t) => {
                const isUsed = t.status === "used";
                return (
                  <tr key={t.id}>
                    <td><code>{t.token_masked}</code></td>
                    <td>{t.kind}</td>
                    <td><code>{t.issued_to_ip}</code></td>
                    <td><code>{t.issued_on_path}</code></td>
                    <td>{formatTime(t.created_at)}</td>
                    <td>
                      <span className={isUsed ? "badge badge-critical" : "badge"}>
                        {isUsed ? "USED" : "Issued"}
                      </span>
                    </td>
                    <td>{t.used_count}</td>
                    <td>{t.seconds_to_use != null ? `${t.seconds_to_use}s` : "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
