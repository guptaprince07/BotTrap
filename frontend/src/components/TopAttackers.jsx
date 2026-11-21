import { useEffect, useState } from "react";

export default function TopAttackers() {
  const [attackers, setAttackers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAttackers = async () => {
      try {
        const API = import.meta.env.VITE_API_URL || "http://localhost:5001";

        const response = await fetch(`${API}/api/attackers?limit=10`);
        const data = await response.json();

        setAttackers(data.attackers || []);
      } catch (error) {
        console.error("Error loading attackers:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchAttackers();

    const interval = setInterval(fetchAttackers, 10000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ padding: "15px" }}>
      <h3>Top Attackers</h3>

      {loading ? (
        <p>Loading attackers...</p>
      ) : attackers.length === 0 ? (
        <p>No attackers found.</p>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th style={cellStyle}>IP Address</th>
                <th style={cellStyle}>Country</th>
                <th style={cellStyle}>Events</th>
                <th style={cellStyle}>Top Attack</th>
              </tr>
            </thead>

            <tbody>
              {attackers.map((attacker, index) => (
                <tr key={attacker.ip || index}>
                  <td style={cellStyle}>{attacker.ip}</td>
                  <td style={cellStyle}>{attacker.country || "Unknown"}</td>
                  <td style={cellStyle}>{attacker.count}</td>
                  <td style={cellStyle}>{attacker.top_type}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const cellStyle = {
  padding: "10px",
  borderBottom: "1px solid #ddd",
  textAlign: "left",
};
