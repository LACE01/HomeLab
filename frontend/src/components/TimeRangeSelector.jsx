import { useState } from "react";
import { CalendarBlank } from "@phosphor-icons/react";

const RANGES = [
  { id: "7d",  label: "7d"  },
  { id: "30d", label: "30d" },
  { id: "90d", label: "90d" },
  { id: "4mo", label: "4mo" },
  { id: "6mo", label: "6mo" },
  { id: "12mo", label: "12mo" },
];

export default function TimeRangeSelector({ value, onChange, customStart, customEnd, onCustomChange, testid = "time-range" }) {
  const [showCustom, setShowCustom] = useState(value === "custom");

  const pick = (id) => {
    if (id === "custom") {
      setShowCustom(true);
      onChange("custom");
    } else {
      setShowCustom(false);
      onChange(id);
    }
  };

  return (
    <div data-testid={testid} className="inline-flex items-center gap-1">
      <div className="flex items-center border border-[#30363D] rounded overflow-hidden">
        {RANGES.map(r => (
          <button
            key={r.id}
            data-testid={`${testid}-${r.id}`}
            onClick={() => pick(r.id)}
            className={`px-2.5 h-8 text-[11.5px] font-mono transition-colors ${
              value === r.id
                ? "bg-blue-500/15 text-blue-300"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
            }`}
          >
            {r.label}
          </button>
        ))}
        <button
          data-testid={`${testid}-custom`}
          onClick={() => pick("custom")}
          className={`px-2.5 h-8 text-[11.5px] font-mono inline-flex items-center gap-1 transition-colors ${
            value === "custom"
              ? "bg-blue-500/15 text-blue-300"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
          }`}
        >
          <CalendarBlank size={12}/> Custom
        </button>
      </div>
      {showCustom && (
        <div className="flex items-center gap-1 ml-1">
          <input
            data-testid={`${testid}-custom-start`}
            type="date"
            value={customStart || ""}
            onChange={(e) => onCustomChange?.({ start: e.target.value, end: customEnd })}
            className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[11.5px] text-slate-200 font-mono"
          />
          <span className="text-slate-500 text-[11px]">→</span>
          <input
            data-testid={`${testid}-custom-end`}
            type="date"
            value={customEnd || ""}
            onChange={(e) => onCustomChange?.({ start: customStart, end: e.target.value })}
            className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[11.5px] text-slate-200 font-mono"
          />
        </div>
      )}
    </div>
  );
}
