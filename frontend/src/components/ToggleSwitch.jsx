// Item 14: one switch component instead of hand-positioned thumbs. The thumb is
// laid out by flexbox inside a padded track (justify-start / justify-end), so it
// is centred vertically and sits the same 2px from either edge at any size --
// the old absolute + translate-x version drifted off-centre and off the track.
export default function ToggleSwitch({ checked, onChange, disabled, size = "md", title, testid, label }) {
  const dims = size === "sm"
    ? { track: "h-4 w-7", thumb: "h-3 w-3" }
    : { track: "h-5 w-9", thumb: "h-4 w-4" };
  return (
    <button
      type="button"
      role="switch"
      aria-checked={!!checked}
      aria-label={label || title}
      title={title}
      data-testid={testid}
      disabled={disabled}
      onClick={() => !disabled && onChange && onChange(!checked)}
      className={`${dims.track} shrink-0 inline-flex items-center rounded-full p-0.5 transition-colors
        focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/60 disabled:opacity-50 disabled:cursor-not-allowed
        ${checked ? "bg-emerald-500/80 justify-end" : "bg-slate-700 justify-start"}`}
    >
      <span className={`${dims.thumb} rounded-full bg-white shadow`} />
    </button>
  );
}
