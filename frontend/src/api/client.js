// frontend/src/api/client.js
// Single place for all API calls. Base URL comes from frontend/.env (VITE_API_URL).
const BASE = (import.meta.env.VITE_API_URL || 'http://localhost:5001').replace(/\/+$/, '');

export async function api(path, options = {}) {
  const url = BASE + path;
  const res = await fetch(url, {
    ...options,
    cache: 'no-store',
    headers: {
      'Cache-Control': 'no-cache',
      Pragma: 'no-cache',
      ...(options.headers || {}),
    },
  });

  if (!res.ok) {
    throw new Error(`API returned HTTP ${res.status} on ${path}`);
  }
  return res.json();
}
