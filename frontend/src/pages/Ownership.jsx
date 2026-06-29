import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Trash, Plus, Lightning } from "@phosphor-icons/react";
import { toast } from "sonner";

const FIELDS = ["tags", "environment", "platform", "criticality", "exposure", "department"];

export function AssignmentRules() {
  const [items, setItems] = useState([]);
  const [draft, setDraft] = useState({ name:"", priority:100, field:"tags", operator:"equals", value:"", assign_team:"", active:true });
  const load = () => api.get("/v1/admin/assignment-rules").then(r => setItems(r.data.items));
  useEffect(() => { load(); }, []);

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
    toast.success(`Applied — ${r.data.updated_assets} assets, ${r.data.updated_findings} findings updated`);
  };

  return (
    <Layout title="Assignment Rules" subtitle="Auto-route findings to teams based on asset attributes"
      actions={<button data-testid="apply-rules" onClick={apply}
        className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5"><Lightning size={14}/> Apply Rules</button>}>

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
  const load = () => api.get("/v1/ownership-mappings", { params: q ? { q } : {} }).then(r => setItems(r.data.items));
  useEffect(() => { load(); }, []);
  return (
    <Layout title="Ownership Mappings" subtitle="Assets, their inferred owner team, and confidence">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-2 mb-3 flex gap-2">
        <input placeholder="Search hostname or team…" data-testid="owner-search" value={q} onChange={(e)=>setQ(e.target.value)} onKeyDown={(e)=>e.key==='Enter'&&load()} className="flex-1 h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]"/>
        <button onClick={load} className="h-8 px-3 text-[12px] bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded">Search</button>
      </div>
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table className="dense w-full">
          <thead><tr><th className="text-left">Hostname</th><th>Env</th><th>Platform</th><th>Crit</th><th>Owner Team</th><th>Confidence</th><th className="text-left">Rationale</th></tr></thead>
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
                </div></td>
                <td className="text-slate-500 text-[11px] max-w-[400px]">{a.ownership_rationale}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}
