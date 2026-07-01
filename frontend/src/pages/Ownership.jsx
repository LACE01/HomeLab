import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Trash, Plus, Lightning, Gear, CheckCircle, Clock } from "@phosphor-icons/react";
import { toast } from "sonner";

const FIELDS = ["tags", "environment", "platform", "criticality", "exposure", "department", "cve", "operating_system", "hostname"];

export function AssignmentRules() {
  const [items, setItems] = useState([]);
  const [draft, setDraft] = useState({ name:"", priority:100, field:"tags", operator:"equals", value:"", assign_team:"", active:true });
  const [preview, setPreview] = useState(null);
  const [defaultTeam, setDefaultTeam] = useState("");
  const [savingDefault, setSavingDefault] = useState(false);
  const load = () => api.get("/v1/admin/assignment-rules").then(r => setItems(r.data.items));
  useEffect(() => { load(); }, []);
  useEffect(() => { api.get("/v1/admin/assignment-rules/settings").then(r => setDefaultTeam(r.data.default_team || "")); }, []);

  const saveDefaultTeam = async () => {
    setSavingDefault(true);
    try {
      await api.put("/v1/admin/assignment-rules/settings", { default_team: defaultTeam || null });
      toast.success(defaultTeam ? `Default team set to "${defaultTeam}".` : "Default team cleared.");
    } catch (e) {
      toast.error("Failed to save default team");
    } finally {
      setSavingDefault(false);
    }
  };

  const add = async () => {
    if (!draft.name || !draft.value || !draft.assign_team) { toast.error("Name, value, assign_team are required"); return; }
    await api.post("/v1/admin/assignment-rules", draft);
    setDraft({ name:"", priority:100, field:"tags", operator:"equals", value:"", assign_team:"", active:true });
    await load(); toast.success("Rule created");
  };
  const del = async (id) => { await api.delete(`/v1/admin/assignment-rules/${id}`); await load(); };
  const toggle = async (r) => { await api.patch(`/v1/admin/assignment-rules/${r.id}`, {...r, active: !r.active}); await load(); };
  const apply = async () => {
    const r = await api.post("/v1/admin/assignment-rules/apply");
    const extra = r.data.still_unassigned > 0
      ? ` · ${r.data.still_unassigned} still unassigned (no rule and no default team) — set a default team below, or add a rule.`
      : r.data.defaulted_to_fallback > 0 ? ` · ${r.data.defaulted_to_fallback} fell back to the default team.` : "";
    toast.success(`Applied — ${r.data.updated_assets} assets, ${r.data.updated_findings} findings updated${extra}`, { duration: 6000 });
    setPreview(null);
    load();
  };
  const doPreview = async () => {
    const r = await api.post("/v1/admin/assignment-rules/preview");
    setPreview(r.data);
  };

  return (
    <Layout title="Assignment Rules" subtitle="Auto-route findings to teams based on asset attributes"
      actions={
        <>
          <button data-testid="preview-rules" onClick={doPreview}
            className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-blue-500/50 hover:text-blue-300 text-slate-300 rounded inline-flex items-center gap-1.5">
            Preview
          </button>
          <button data-testid="apply-rules" onClick={apply}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5"><Lightning size={14}/> Apply Rules</button>
        </>
      }>

      {preview && (
        <div data-testid="rules-preview" className="border border-blue-500/30 bg-blue-500/5 rounded-md p-3 mb-3">
          <div className="flex items-center justify-between mb-2">
            <div className="text-[12px] uppercase tracking-wider font-mono text-blue-300">
              Preview · {preview.total_assets} assets · {preview.no_match_assets} unmatched
              {preview.default_team ? ` (would fall back to "${preview.default_team}")` : preview.no_match_assets > 0 ? " — no default team set" : ""}
            </div>
            <button onClick={()=>setPreview(null)} className="text-[11px] text-slate-400 hover:text-slate-200">Dismiss</button>
          </div>
          <div className="space-y-1.5">
            {preview.groups.map((g, i) => (
              <div key={i} className="flex items-center gap-2 text-[12px] font-mono">
                <span className="text-blue-300 min-w-[180px] truncate">{g.rule_name}</span>
                <span className="text-slate-500">→</span>
                <span className="text-emerald-300 min-w-[140px]">{g.team}</span>
                <span className="text-slate-300">{g.count} asset{g.count===1?"":"s"}</span>
                <span className="text-slate-500 truncate ml-2">e.g. {g.sample_hosts.slice(0,3).join(", ")}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3 mb-3 flex items-center gap-2">
        <Gear size={14} className="text-slate-500 shrink-0"/>
        <div className="text-[12px] text-slate-400 shrink-0">Default team for assets that match no rule:</div>
        <input data-testid="default-team-input" placeholder="e.g. IT Ops (leave blank to leave unmatched assets unassigned)"
          value={defaultTeam} onChange={(e)=>setDefaultTeam(e.target.value)}
          className="flex-1 h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]"/>
        <button data-testid="default-team-save" onClick={saveDefaultTeam} disabled={savingDefault}
          className="h-8 px-3 text-[12px] bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded disabled:opacity-50 shrink-0">
          {savingDefault ? "Saving…" : "Save"}
        </button>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3 mb-3 grid grid-cols-7 gap-2">
        <input placeholder="Rule name" data-testid="rule-name" value={draft.name} onChange={(e)=>setDraft({...draft, name:e.target.value})} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]"/>
        <input type="number" placeholder="Priority" value={draft.priority} onChange={(e)=>setDraft({...draft, priority:Number(e.target.value)})} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]"/>
        <select value={draft.field} onChange={(e)=>setDraft({...draft, field:e.target.value})} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]">{FIELDS.map(f=> <option key={f}>{f}</option>)}</select>
        <select value={draft.operator} onChange={(e)=>setDraft({...draft, operator:e.target.value})} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]"><option>equals</option><option>contains</option></select>
        <input placeholder="Value" data-testid="rule-value" value={draft.value} onChange={(e)=>setDraft({...draft, value:e.target.value})} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]"/>
        <input placeholder="Assign team" data-testid="rule-team" value={draft.assign_team} onChange={(e)=>setDraft({...draft, assign_team:e.target.value})} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]"/>
        <button onClick={add} data-testid="rule-add" className="h-8 bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded inline-flex items-center justify-center gap-1 text-[12px]"><Plus size={14}/> Add</button>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table className="dense w-full">
          <thead><tr><th>Priority</th><th className="text-left">Name</th><th>Field</th><th>Op</th><th>Value</th><th>Assign Team</th><th>Active</th><th></th></tr></thead>
          <tbody>
            {items.map(r => (
              <tr key={r.id} className="border-t border-[#30363D]">
                <td className="font-mono">{r.priority}</td>
                <td className="text-slate-200">{r.name}</td>
                <td><Chip>{r.field}</Chip></td>
                <td className="text-slate-400">{r.operator}</td>
                <td className="font-mono text-[11.5px]">{r.value}</td>
                <td className="text-slate-200">{r.assign_team}</td>
                <td><button onClick={()=>toggle(r)}><Chip color={r.active?"green":"slate"}>{r.active?"on":"off"}</Chip></button></td>
                <td><button onClick={()=>del(r.id)} className="text-red-400 hover:text-red-300"><Trash size={14}/></button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}

export function OwnershipMappings() {
  const [items, setItems] = useState([]);
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState("all"); // all | stale | low_confidence
  const [staleDays, setStaleDays] = useState(90);

  const load = () => api.get("/v1/ownership-mappings", { params: {
    ...(q ? { q } : {}),
    ...(filter === "stale" ? { stale_only: true } : {}),
    ...(filter === "low_confidence" ? { low_confidence_only: true } : {}),
  } }).then(r => { setItems(r.data.items); setStaleDays(r.data.stale_threshold_days); });
  useEffect(() => { load(); }, [filter]); // eslint-disable-line

  const confirmOwnership = async (a) => {
    await api.post(`/v1/assets/${a.id}/confirm-ownership`);
    toast.success(`Ownership confirmed for ${a.hostname}.`);
    load();
  };

  const staleCount = items.filter(a => a.stale).length;
  const lowConfCount = items.filter(a => (a.ownership_confidence||0) < 0.7).length;

  return (
    <Layout title="Ownership Mappings" subtitle="Assets, their inferred owner team, confidence, and how fresh that assignment is">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-2 mb-3 flex gap-2">
        <input placeholder="Search hostname or team…" data-testid="owner-search" value={q} onChange={(e)=>setQ(e.target.value)} onKeyDown={(e)=>e.key==='Enter'&&load()} className="flex-1 h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]"/>
        <button onClick={load} className="h-8 px-3 text-[12px] bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded">Search</button>
      </div>

      <div className="flex gap-1.5 mb-3">
        <button onClick={()=>setFilter("all")} className={`h-7 px-2.5 rounded-full text-[11px] border ${filter==="all"?"bg-slate-700/40 border-slate-500/50 text-slate-200":"border-[#30363D] text-slate-500"}`}>All</button>
        <button onClick={()=>setFilter("stale")} className={`h-7 px-2.5 rounded-full text-[11px] border inline-flex items-center gap-1 ${filter==="stale"?"bg-amber-500/15 border-amber-500/50 text-amber-300":"border-[#30363D] text-slate-500"}`}>
          <Clock size={12}/> Stale (not reconfirmed in {staleDays}d)
        </button>
        <button onClick={()=>setFilter("low_confidence")} className={`h-7 px-2.5 rounded-full text-[11px] border ${filter==="low_confidence"?"bg-red-500/15 border-red-500/50 text-red-300":"border-[#30363D] text-slate-500"}`}>Low confidence (&lt;70%)</button>
      </div>

      {filter === "all" && (staleCount > 0 || lowConfCount > 0) && (
        <div className="border border-amber-500/30 bg-amber-500/5 rounded-md px-3 py-2 mb-3 text-[11.5px] text-amber-200">
          {staleCount} asset{staleCount===1?"":"s"} haven't had ownership reconfirmed in {staleDays}+ days, {lowConfCount} are below 70% confidence. Filter above to review them.
        </div>
      )}

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table className="dense w-full">
          <thead><tr><th className="text-left">Hostname</th><th>Env</th><th>Platform</th><th>Crit</th><th>Owner Team</th><th>Confidence</th><th className="text-left">Rationale</th><th></th></tr></thead>
          <tbody>
            {items.map(a => (
              <tr key={a.id} className="border-t border-[#30363D]">
                <td className="font-mono text-[12px]">{a.hostname}</td>
                <td className="text-slate-400">{a.environment}</td>
                <td className="text-slate-400">{a.platform}</td>
                <td><Chip>{a.criticality}</Chip></td>
                <td className="text-slate-200">{a.owner_team}</td>
                <td><div className="flex items-center gap-1.5">
                  <div className="h-1 w-12 bg-slate-800 rounded overflow-hidden"><div className={`h-full ${a.ownership_confidence>=0.8?"bg-emerald-500":a.ownership_confidence>=0.6?"bg-amber-500":"bg-red-500"}`} style={{width:`${(a.ownership_confidence||0)*100}%`}}/></div>
                  <span className="font-mono text-[10.5px]">{((a.ownership_confidence||0)*100).toFixed(0)}%</span>
                  {a.stale && <Chip color="amber">stale</Chip>}
                </div></td>
                <td className="text-slate-500 text-[11px] max-w-[360px]">{a.ownership_rationale}</td>
                <td>
                  <button onClick={()=>confirmOwnership(a)} title="Confirm this ownership is correct"
                    className="h-7 px-2 text-[11px] border border-[#30363D] hover:border-emerald-500/50 hover:text-emerald-300 rounded inline-flex items-center gap-1 text-slate-400">
                    <CheckCircle size={12}/> Confirm
                  </button>
                </td>
              </tr>
            ))}
            {items.length === 0 && <tr><td colSpan="8" className="text-center text-slate-500 py-6">Nothing matches this filter.</td></tr>}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}
