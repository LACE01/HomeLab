import { useState, useRef, useEffect } from "react";
import { GearSix, Check, X } from "@phosphor-icons/react";

/**
 * TilePicker — popover with checkboxes for each tile id.
 *  tiles: { [tileId]: boolean }   current visibility map
 *  catalog: [{ id, label, group? }]  what tiles are available + nice labels
 *  onToggle(id) → callback
 *  onResetAll() → optional reset
 */
export default function TilePicker({ tiles, catalog, onToggle, onResetAll, testid = "tile-picker" }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    if (open) document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  // Group tiles by their `group` field
  const grouped = catalog.reduce((acc, t) => {
    const g = t.group || "Tiles";
    (acc[g] = acc[g] || []).push(t);
    return acc;
  }, {});

  const visibleCount = catalog.filter(t => tiles[t.id] !== false).length;

  return (
    <div className="relative inline-block" ref={ref}>
      <button
        data-testid={testid}
        onClick={() => setOpen(o => !o)}
        className="h-8 px-2.5 text-[11.5px] border border-[#30363D] hover:border-[#484F58] hover:bg-slate-800/40 rounded inline-flex items-center gap-1.5 text-slate-300 font-mono"
        title="Customize tiles"
      >
        <GearSix size={13}/> Tiles ({visibleCount})
      </button>
      {open && (
        <div data-testid={`${testid}-popover`} className="absolute right-0 mt-1.5 w-72 bg-[#0D1117] border border-[#30363D] rounded-md shadow-2xl z-50">
          <div className="px-3 py-2 border-b border-[#30363D] flex items-center justify-between">
            <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400">Show / Hide Tiles</div>
            {onResetAll && (
              <button
                data-testid={`${testid}-reset`}
                onClick={onResetAll}
                className="text-[10.5px] text-blue-300 hover:text-blue-200 font-mono"
              >Reset</button>
            )}
          </div>
          <div className="max-h-80 overflow-y-auto py-1">
            {Object.entries(grouped).map(([g, items]) => (
              <div key={g}>
                <div className="px-3 pt-2 pb-1 text-[9.5px] uppercase tracking-wider font-mono text-slate-600">{g}</div>
                {items.map(t => {
                  const on = tiles[t.id] !== false;
                  return (
                    <button
                      key={t.id}
                      data-testid={`${testid}-toggle-${t.id}`}
                      onClick={() => onToggle(t.id)}
                      className="w-full flex items-center gap-2 px-3 py-1.5 text-[12px] text-slate-300 hover:bg-slate-800/60 transition-colors"
                    >
                      <div className={`w-3.5 h-3.5 rounded border flex items-center justify-center ${on ? "bg-blue-500/30 border-blue-400" : "border-slate-600"}`}>
                        {on ? <Check size={9} className="text-blue-200"/> : null}
                      </div>
                      <span className="flex-1 text-left">{t.label}</span>
                      {!on && <X size={11} className="text-slate-600"/>}
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
