import React from "react";

const TEN_MINUTES_MS = 10 * 60 * 1000;

export default function HoneyTokenAlert({ tokens = [] }) {
  const now = Date.now();
  const recent = tokens.find((t) => {
    if (!t?.last_used_at) return false;
    const ts = Date.parse(t.last_used_at);
    return !Number.isNaN(ts) && now - ts <= TEN_MINUTES_MS;
  });

  if (!recent) return null;

  const secs = recent.seconds_to_use ?? 0;

  return (
    <div className="banner banner-critical" role="alert">
      <strong>STOLEN HONEY-TOKEN USED:</strong> an attacker used the key leaked at{" "}
      <code>{recent.issued_on_path}</code> after <strong>{secs}</strong> seconds.
    </div>
  );
}
