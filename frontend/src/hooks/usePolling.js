// frontend/src/hooks/usePolling.js
// Calls fn() immediately, then every `ms` milliseconds.
// Uses useRef to avoid stale closures and always invoke the freshest function.
import { useEffect, useState, useRef } from 'react';

export default function usePolling(fn, ms = 3000, deps = []) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    let alive = true;

    const run = async () => {
      try {
        const d = await fnRef.current();
        if (alive) {
          setData(d);
          setError(null);
        }
      } catch (e) {
        if (alive) {
          setError(e.message || 'Network request failed');
        }
      } finally {
        if (alive) {
          setLoading(false);
        }
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
