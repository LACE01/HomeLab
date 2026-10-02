import { useCallback, useRef, useState } from "react";

// #21: one guard for every "post a note/comment" handler. A ref (not state) blocks
// the second submit synchronously -- state updates are async, so two rapid events
// (Enter + click, a double-click) could both read a stale `false` before a render
// lands. The backend also dedupes identical posts (routes/common.dedupe_post).
export function useSubmitOnce() {
  const inFlight = useRef(false);
  const [busy, setBusy] = useState(false);
  const run = useCallback(async (fn) => {
    if (inFlight.current) return undefined;
    inFlight.current = true;
    setBusy(true);
    try { return await fn(); }
    finally { inFlight.current = false; setBusy(false); }
  }, []);
  return [run, busy];
}
