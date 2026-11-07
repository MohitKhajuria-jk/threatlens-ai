import { useCallback, useEffect, useRef, useState } from "react";

/** Loads data when `deps` change. Keeps showing the previous data while reloading. */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const run = useCallback(fn, deps);

  const reload = useCallback(() => {
    const n = ++seq.current;
    setLoading(true);
    run().then(
      (d) => {
        if (n === seq.current) {
          setData(d);
          setError(null);
          setLoading(false);
        }
      },
      (e: Error) => {
        if (n === seq.current) {
          setError(e.message);
          setLoading(false);
        }
      },
    );
  }, [run]);

  useEffect(() => {
    reload();
  }, [reload]);

  return { data, error, loading, reload, setData };
}
