import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";

/**
 * usePreferences — loads /v1/me/preferences once, exposes prefs + setters that
 * auto-persist (debounced) to the server. Returns:
 *   { prefs, loading, setSection(section, partial), update(fn) }
 */
export function usePreferences() {
  const [prefs, setPrefs] = useState(null);
  const [loading, setLoading] = useState(true);
  const saveTimer = useRef(null);
  const latestPrefs = useRef(null);

  useEffect(() => {
    api.get("/v1/me/preferences").then(r => {
      setPrefs(r.data);
      latestPrefs.current = r.data;
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  const persist = useCallback((next) => {
    latestPrefs.current = next;
    setPrefs(next);
    if (saveTimer.current) clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(() => {
      api.put("/v1/me/preferences", { prefs: next }).catch(() => {});
    }, 400);
  }, []);

  const setSection = useCallback((section, partial) => {
    const cur = latestPrefs.current || {};
    persist({ ...cur, [section]: { ...(cur[section] || {}), ...partial } });
  }, [persist]);

  const update = useCallback((fn) => {
    persist(fn(latestPrefs.current || {}));
  }, [persist]);

  return { prefs, loading, setSection, update };
}
