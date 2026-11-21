// frontend/src/api/client.js
// Single place for all API calls. Base URL comes from frontend/.env (VITE_API_URL).
const BASE = import.meta.env.VITE_API_URL || 'http://localhost:5001';

export async function api(path, options) {
  const res = await fetch(BASE + path, options);
  if (!res.ok) throw new Error('API ' + res.status);
  return res.json();
}