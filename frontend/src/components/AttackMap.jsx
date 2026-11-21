import { useEffect, useState } from "react";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";

export default function AttackMap() {
  const [points, setPoints] = useState([]);

  useEffect(() => {
    const fetchLocations = async () => {
      try {
        const API = import.meta.env.VITE_API_URL || "http://localhost:5001";

        const response = await fetch(`${API}/api/geo`);
        const data = await response.json();

        setPoints(data.points || []);
      } catch (error) {
        console.error("Error loading attack locations:", error);
      }
    };

    fetchLocations();

    const interval = setInterval(fetchLocations, 10000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ width: "100%", height: "400px" }}>
      <h3>Attack Map</h3>

      <MapContainer
        center={[25, 0]}
        zoom={2}
        style={{ height: "350px", width: "100%" }}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a>'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />

        {points.map((point, index) => (
          <CircleMarker
            key={index}
            center={[point.lat, point.lon]}
            radius={Math.min(6 + point.count, 18)}
            pathOptions={{
              color: "red",
              fillColor: "red",
              fillOpacity: 0.6,
            }}
          >
            <Popup>
              <b>IP:</b> {point.ip}
              <br />
              <b>Country:</b> {point.country}
              <br />
              <b>Events:</b> {point.count}
            </Popup>
          </CircleMarker>
        ))}
      </MapContainer>
    </div>
  );
}
