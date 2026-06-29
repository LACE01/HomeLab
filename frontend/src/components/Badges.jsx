import { sevClass } from "@/lib/utils-fmt";

export const SevBadge = ({ severity, testid }) => (
  <span data-testid={testid} className={`chip ${sevClass(severity)}`}>{severity}</span>
);

export const Chip = ({ children, color = "slate", testid }) => {
  const map = {
    red: "bg-red-900/20 border border-red-500/30 text-red-300",
    orange: "bg-orange-900/20 border border-orange-500/30 text-orange-300",
    amber: "bg-amber-900/20 border border-amber-500/30 text-amber-300",
    blue: "bg-blue-900/20 border border-blue-500/30 text-blue-300",
    green: "bg-emerald-900/20 border border-emerald-500/30 text-emerald-300",
    slate: "bg-slate-800/40 border border-slate-600/40 text-slate-300",
    purple: "bg-violet-900/20 border border-violet-500/30 text-violet-300",
  };
  return <span data-testid={testid} className={`chip ${map[color] || map.slate}`}>{children}</span>;
};

export const RiskBar = ({ score = 0 }) => {
  const pct = Math.max(0, Math.min(100, score));
  const color = pct >= 80 ? "bg-red-500" : pct >= 60 ? "bg-orange-500" : pct >= 40 ? "bg-amber-500" : pct >= 20 ? "bg-blue-500" : "bg-slate-500";
  return (
    <div className="flex items-center gap-2 min-w-[90px]">
      <div className="h-1.5 w-16 bg-slate-800 rounded overflow-hidden">
        <div className={`${color} h-full`} style={{ width: `${pct}%` }} />
      </div>
      <span className="font-mono text-[11px] text-slate-300">{pct}</span>
    </div>
  );
};
