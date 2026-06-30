import { useEffect, useState, useRef } from "react";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { CaretDown, MagnifyingGlass, Plus, X } from "@phosphor-icons/react";

/**
 * Searchable team picker with inline "+ Create team" support.
 *
 * Props:
 *   value (string) — current selected team name (or "")
 *   onChange (fn)  — called with new team name
 *   testid (string) — base for data-testid
 *   placeholder (string)
 *   allowCreate (bool, default true) — show inline create option for admin/manager
 */
export default function TeamCombobox({ value, onChange, testid = "team-combobox", placeholder = "Select team…", allowCreate = true }) {
  const [open, setOpen] = useState(false);
  const [teams, setTeams] = useState([]);
  const [search, setSearch] = useState("");
  const [creating, setCreating] = useState(false);
  const wrapRef = useRef(null);

  const load = async () => {
    try {
      const r = await api.get("/v1/admin/teams");
      setTeams(r.data.items || []);
    } catch {
      // analyst role may not have access; keep empty
      setTeams([]);
    }
  };

  useEffect(() => { load(); }, []);

  // Close on outside click
  useEffect(() => {
    const onDoc = (e) => {
      if (open && wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  const filtered = teams.filter(t => !search || t.name.toLowerCase().includes(search.toLowerCase()));
  const exactMatch = teams.find(t => t.name.toLowerCase() === search.toLowerCase());
  const showCreate = allowCreate && search.trim() && !exactMatch;

  const pick = (name) => {
    onChange(name);
    setOpen(false);
    setSearch("");
  };

  const createTeam = async () => {
    const name = search.trim();
    if (!name) return;
    setCreating(true);
    try {
      const r = await api.post("/v1/admin/teams", { name });
      toast.success(`Team '${r.data.name}' created`);
      setTeams(prev => [...prev, r.data]);
      pick(r.data.name);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to create team");
    } finally { setCreating(false); }
  };

  return (
    <div ref={wrapRef} className="relative" data-testid={testid}>
      <button
        type="button"
        data-testid={`${testid}-trigger`}
        onClick={() => setOpen(o => !o)}
        className={`h-7 px-2.5 text-[12px] bg-[#161B22] border border-[#30363D] rounded inline-flex items-center gap-1.5 min-w-[180px] text-left ${value ? "text-slate-100" : "text-slate-500"} hover:border-[#484F58]`}
      >
        <span className="flex-1 truncate">{value || placeholder}</span>
        {value && (
          <span
            role="button"
            aria-label="Clear team"
            data-testid={`${testid}-clear`}
            onClick={(e) => { e.stopPropagation(); onChange(""); }}
            className="text-slate-500 hover:text-slate-200 cursor-pointer"
          >
            <X size={11}/>
          </span>
        )}
        <CaretDown size={11} className="text-slate-500"/>
      </button>
      {open && (
        <div className="absolute z-50 mt-1 left-0 w-[280px] bg-[#0D1117] border border-[#30363D] rounded-md shadow-xl"
             data-testid={`${testid}-popover`}>
          <div className="p-2 border-b border-[#30363D]">
            <div className="relative">
              <MagnifyingGlass size={11} className="absolute left-2 top-[8px] text-slate-500"/>
              <input
                data-testid={`${testid}-search`}
                autoFocus
                placeholder="Search or type to add…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full h-7 pl-6 pr-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"
              />
            </div>
          </div>
          <div className="max-h-[280px] overflow-y-auto">
            {filtered.length === 0 && !showCreate && (
              <div className="px-3 py-3 text-[11.5px] text-slate-500">No teams. {allowCreate ? "Type a name to create one." : "Ask an admin to create one."}</div>
            )}
            {filtered.map(t => (
              <button
                key={t.id || t.name}
                data-testid={`${testid}-opt-${t.name}`}
                onClick={() => pick(t.name)}
                className={`w-full px-3 py-1.5 text-left text-[12px] hover:bg-slate-800/40 flex items-center gap-2 ${value === t.name ? "bg-blue-500/10 text-blue-300" : "text-slate-200"}`}
              >
                <span className="w-2 h-2 rounded-full shrink-0" style={{ background: t.color || "#64748b" }}/>
                <span className="flex-1 truncate">{t.name}</span>
                {t.implicit && <span className="text-[10px] text-slate-500">implicit</span>}
                {t.member_count > 0 && <span className="text-[10.5px] text-slate-500 font-mono">{t.member_count}</span>}
              </button>
            ))}
            {showCreate && (
              <button
                data-testid={`${testid}-create`}
                disabled={creating}
                onClick={createTeam}
                className="w-full px-3 py-2 text-left text-[12px] border-t border-[#30363D] text-emerald-300 hover:bg-emerald-500/10 inline-flex items-center gap-2 disabled:opacity-50"
              >
                <Plus size={12}/> Create team "<span className="font-mono">{search.trim()}</span>"
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
