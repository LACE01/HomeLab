import { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { MagnifyingGlass, ArrowRight } from "@phosphor-icons/react";
import { useAuth } from "@/lib/auth";
import { searchNav } from "@/lib/navRegistry";

// Cmd-K / Ctrl-K jump-to-page.
//
// With ~60 destinations, scanning the sidebar for the one you want is the slow
// path. This is the fast one: press Cmd-K, type a few characters of what you
// call the page, hit Enter. It searches labels, groups AND keywords, so "dmarc"
// finds Email Authentication and "edr" finds Directory even though neither word
// is in the visible label.
//
// It respects role access the same way the sidebar does -- a page you cannot
// open never appears as a result, so the palette can't offer a jump that lands
// on a 403.
export default function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef(null);
  const listRef = useRef(null);
  const nav = useNavigate();
  const { canAccess } = useAuth();

  const results = searchNav(query, canAccess).slice(0, 12);

  const close = useCallback(() => { setOpen(false); setQuery(""); setActive(0); }, []);

  // Global hotkey. Cmd-K on Mac, Ctrl-K elsewhere. Escape closes.
  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      } else if (e.key === "Escape" && open) {
        close();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, close]);

  useEffect(() => { if (open && inputRef.current) inputRef.current.focus(); }, [open]);
  useEffect(() => { setActive(0); }, [query]);

  // Keep the highlighted row in view as you arrow through.
  useEffect(() => {
    const el = listRef.current?.querySelector(`[data-idx="${active}"]`);
    if (el) el.scrollIntoView({ block: "nearest" });
  }, [active]);

  if (!open) return null;

  const go = (item) => { if (item) { nav(item.to); close(); } };

  const onKeyDown = (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(a + 1, results.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
    else if (e.key === "Enter") { e.preventDefault(); go(results[active]); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh] bg-black/50"
         onClick={close}>
      <div className="w-full max-w-xl bg-[#0D1117] border border-[#30363D] rounded-lg shadow-2xl overflow-hidden"
           onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 px-3 border-b border-[#30363D]">
          <MagnifyingGlass size={16} className="text-slate-500 shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Jump to…  (try a page name, or “dmarc”, “edr”, “sbom”)"
            className="flex-1 bg-transparent py-3 text-[14px] text-slate-100 placeholder:text-slate-600 outline-none"
          />
          <kbd className="text-[10px] font-mono text-slate-600 border border-[#30363D] rounded px-1.5 py-0.5">esc</kbd>
        </div>

        <div ref={listRef} className="max-h-[50vh] overflow-y-auto py-1">
          {results.length === 0 && (
            <div className="px-4 py-6 text-center text-[12.5px] text-slate-500">
              Nothing matches “{query}”.
            </div>
          )}
          {results.map((item, i) => (
            <button
              key={item.to}
              data-idx={i}
              onMouseEnter={() => setActive(i)}
              onClick={() => go(item)}
              className={`w-full flex items-center justify-between gap-3 px-4 py-2 text-left ${
                i === active ? "bg-blue-500/10" : ""
              }`}
            >
              <div className="min-w-0">
                <div className={`text-[13.5px] ${i === active ? "text-blue-200" : "text-slate-200"}`}>
                  {item.label}
                </div>
                <div className="text-[10.5px] text-slate-600 font-mono">{item.group}</div>
              </div>
              {i === active && <ArrowRight size={14} className="text-blue-300 shrink-0" />}
            </button>
          ))}
        </div>

        <div className="border-t border-[#30363D] px-3 py-1.5 flex items-center gap-3 text-[10px] text-slate-600 font-mono">
          <span>↑↓ move</span><span>↵ open</span><span>⌘K toggle</span>
        </div>
      </div>
    </div>
  );
}
