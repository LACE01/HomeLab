import { describeApiError } from "@/lib/api";
import { WarningCircle, ArrowClockwise } from "@phosphor-icons/react";

/**
 * Four states, rendered four different ways: loading, failed, empty, ready.
 *
 * The bug this exists to prevent has appeared three times in this codebase:
 * a request that FAILED rendered identically to one that succeeded and found
 * nothing ("no data yet"), or identically to one still in flight ("Loading…"
 * forever). Both send the reader to the wrong conclusion — usually "the feature
 * is broken" or "we have nothing to worry about" — and neither is recoverable
 * from the screen, because there is nothing on it that says an error happened.
 *
 * Usage:
 *   <AsyncState loading={loading} error={err} empty={!items.length}
 *               onRetry={load} emptyMessage="No alerts imported yet.">
 *     {...}
 *   </AsyncState>
 */
export function AsyncState({ loading, error, empty, emptyMessage, onRetry, children,
                             label = "data" }) {
  if (loading) {
    return (
      <div className="text-[12px] text-slate-500 py-8 text-center">
        Loading {label}…
      </div>
    );
  }

  if (error) {
    const d = describeApiError(error) || { message: String(error) };
    return (
      <div className="border border-red-500/40 bg-red-500/5 rounded-md p-4 my-3">
        <div className="flex items-start gap-2.5">
          <WarningCircle size={16} className="text-red-400 mt-0.5 shrink-0"/>
          <div className="min-w-0">
            <div className="text-[12.5px] text-red-200">Couldn&apos;t load {label}.</div>
            <div className="text-[11.5px] text-slate-400 mt-1 leading-relaxed">{d.message}</div>
            {/* Said explicitly, because the empty state and the failure state look
                alike everywhere else and people have already been misled by it. */}
            <div className="text-[11px] text-slate-500 mt-1.5">
              This is a failure to load, not an empty result — the numbers below are missing, not zero.
            </div>
            {onRetry && (
              <button onClick={onRetry}
                className="mt-2.5 inline-flex items-center gap-1.5 text-[11.5px] text-blue-300 hover:underline">
                <ArrowClockwise size={13}/> Try again
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  if (empty) {
    return (
      <div className="text-[12px] text-slate-500 py-8 text-center">
        {emptyMessage || `No ${label} yet.`}
      </div>
    );
  }

  return children;
}

export default AsyncState;
