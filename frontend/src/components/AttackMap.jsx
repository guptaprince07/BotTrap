import React from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import { COLORS } from '../theme';

export default function AttackMap({ points: propPoints, loading = false, error = null }) {
  const points = propPoints || [];

  return (
    <div className="card">
      <div className="row-between mb-4">
        <div className="card-title" style={{ marginBottom: 0 }}>
          LIVE ATTACK MAP
        </div>
        <span className="muted mono">{points.length} locations</span>
      </div>

      {error ? (
        <div className="error-state">Failed to load geographic points: {error}</div>
      ) : loading && points.length === 0 ? (
        <div className="map-box skeleton" />
      ) : (
        <div className="map-box">
          <MapContainer
            center={[20, 0]}
            zoom={2}
            scrollWheelZoom={false}
            style={{ height: '100%', width: '100%', background: '#0b1220' }}
          >
            <TileLayer
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            />
            {points.map((pt, idx) => {
              if (pt.lat == null || pt.lon == null) return null;
              const count = pt.count || 1;
              const radius = Math.min(5 + count * 1.5, 18);
              return (
                <CircleMarker
                  key={`${pt.ip}-${idx}`}
                  center={[pt.lat, pt.lon]}
                  radius={radius}
                  pathOptions={{
                    color: COLORS.severity.Critical,
                    fillColor: COLORS.severity.Critical,
                    fillOpacity: 0.65,
                    weight: 1.5,
                  }}
                >
                  <Popup className="dark-popup">
                    <div style={{ fontSize: '12px', lineHeight: 1.4 }}>
                      <strong>IP:</strong> <span className="mono">{pt.ip}</span>
                      <br />
                      <strong>Country:</strong> {pt.country || 'Unknown'}
                      <br />
                      <strong>Events:</strong> {count}
                    </div>
                  </Popup>
                </CircleMarker>
              );
            })}
          </MapContainer>
        </div>
      )}
    </div>
  );
}
