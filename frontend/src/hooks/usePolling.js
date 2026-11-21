// frontend/src/hooks/usePolling.js
// Calls fn() immediately, then every `ms` milliseconds.
// Pass `deps` (e.g. [filters.severity, filters.attack_type]) so it
// re-fetches right away when those values change.
import { useEffect, useState } from 'react';

export default function usePolling(fn, ms = 3000, deps = []) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true; // stops state updates after unmount or deps change

    const run = async () => {
      try {
        const d = await fn();
        if (alive) {
          setData(d);
          setError(null);
        }
      } catch (e) {
        if (alive) setError(e.message);
      } finally {
        if (alive) setLoading(false);
      }
    };

    run();
    const id = setInterval(run, ms);

    return () => {
      alive = false;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading };
}