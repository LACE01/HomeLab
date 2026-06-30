import { useState } from "react";
import { CalendarBlank, CaretDown } from "@phosphor-icons/react";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Calendar } from "@/components/ui/calendar";
import { format, parseISO } from "date-fns";

const RANGES = [
  { id: "7d",  label: "7d"  },
  { id: "30d", label: "30d" },
  { id: "90d", label: "90d" },
  { id: "4mo", label: "4mo" },
  { id: "6mo", label: "6mo" },
  { id: "12mo", label: "12mo" },
];

const isoDate = (d) => d ? format(d, "yyyy-MM-dd") : "";
const toDate = (s) => { try { return s ? parseISO(s) : undefined; } catch { return undefined; } };

function DateButton({ value, onChange, testid, placeholder }) {
  const [open, setOpen] = useState(false);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          data-testid={testid}
          className="h-8 px-2 bg-[#161B22] border border-[#30363D] hover:border-[#484F58] rounded text-[11.5px] text-slate-200 font-mono inline-flex items-center gap-1.5 min-w-[110px]"
        >
          <CalendarBlank size={12} className="text-slate-500"/>
          <span className={value ? "" : "text-slate-600"}>{value || placeholder}</span>
          <CaretDown size={10} className="text-slate-600 ml-auto"/>
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-auto p-0 bg-[#0D1117] border-[#30363D]" align="start">
        <Calendar
          mode="single"
          selected={toDate(value)}
          onSelect={(d) => { onChange(isoDate(d)); setOpen(false); }}
          initialFocus
        />
      </PopoverContent>
    </Popover>
  );
}

export default function TimeRangeSelector({ value, onChange, customStart, customEnd, onCustomChange, testid = "time-range" }) {
  const showCustom = value === "custom";

  return (
    <div data-testid={testid} className="inline-flex items-center gap-1">
      <div className="flex items-center border border-[#30363D] rounded overflow-hidden">
        {RANGES.map(r => (
          <button
            key={r.id}
            data-testid={`${testid}-${r.id}`}
            onClick={() => onChange(r.id)}
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
          onClick={() => onChange("custom")}
          className={`px-2.5 h-8 text-[11.5px] font-mono inline-flex items-center gap-1 transition-colors ${
            showCustom
              ? "bg-blue-500/15 text-blue-300"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
          }`}
        >
          <CalendarBlank size={12}/> Custom
        </button>
      </div>
      {showCustom && (
        <div className="flex items-center gap-1 ml-1">
          <DateButton
            value={customStart || ""}
            onChange={(s) => onCustomChange?.({ start: s, end: customEnd })}
            placeholder="Start date"
            testid={`${testid}-custom-start`}
          />
          <span className="text-slate-500 text-[11px]">→</span>
          <DateButton
            value={customEnd || ""}
            onChange={(s) => onCustomChange?.({ start: customStart, end: s })}
            placeholder="End date"
            testid={`${testid}-custom-end`}
          />
        </div>
      )}
    </div>
  );
}
