import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Plus, X, TreeStructure, Sparkle, Trash } from "@phosphor-icons/react";

export default function ThreatModeling() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);

  const load = async () => {
    try {
      const r = await api.get("/v1/threat-models");
      setItems(r.data.items || []);
    } catch (e) { toast.error("Failed to load threat models"); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const remove = async (m) => {
    if (!window.confirm(`Delete threat model "${m.name}" and all its threats?`)) return;
    await api.delete(`/v1/threat-models/${m.id}`);
    toast.success("Deleted");
    load();
  };

  return (
    <Layout title="Threat Modeling"
      subtitle="STRIDE-based threat models with data flow diagrams, attack trees, DREAD prioritization, and mitigation tracking — auto-populated from your own assets and findings"
      actions={
        <button onClick={() => setCreateOpen(true)}
          className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
          <Plus size={14}/> New model
        </button>
      }>
      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-12 text-center">
          <TreeStructure size={28} className="text-slate-600 mx-auto mb-2"/>
          <div className="text-[13px] text-slate-400">No threat models yet.</div>
          <div className="text-[12px] text-slate-500 mt-1">Start blank, or bootstrap one from your asset inventory and open findings.</div>
        </div>
      ) : (
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-3">
          {items.map(m => (
            <div key={m.id} className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 hover:border-slate-500 group relative">
              <Link to={`/threat-modeling/${m.id}`} className="block">
                <div className="text-[13.5px] text-slate-100 font-medium">{m.name}</div>
                <div className="text-[11.5px] text-slate-500 mt-1 line-clamp-2">{m.description || "No description"}</div>
                <div className="flex items-center gap-2 mt-3 text-[11px] text-slate-500">
                  <Chip color="slate">{(m.elements || []).length} elements</Chip>
                  <Chip color="slate">{(m.flows || []).length} flows</Chip>
                  <Chip color={m.open_threat_count > 0 ? "amber" : "emerald"}>{m.open_threat_count} open threat(s)</Chip>
                </div>
                <div className="text-[10.5px] text-slate-600 mt-2">Updated {new Date(m.updated_at).toLocaleDateString()}</div>
              </Link>
              <button onClick={() => remove(m)}
                className="absolute top-3 right-3 text-slate-600 hover:text-red-400 opacity-0 group-hover:opacity-100">
                <Trash size={14}/>
              </button>
            </div>
          ))}
        </div>
      )}
      {createOpen && <CreateModal onClose={() => setCreateOpen(false)} onSaved={() => { setCreateOpen(false); load(); }}/>}
    </Layout>
  );
}

function CreateModal({ onClose, onSaved }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [mode, setMode] = useState("bootstrap"); // bootstrap | blank
  const [team, setTeam] = useState("");
  const [teams, setTeams] = useState([]);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api.get("/v1/admin/teams").then(r => setTeams(r.data.items || [])).catch(() => {});
  }, []);

  const save = async () => {
    if (!name.trim()) { toast.error("Name required"); return; }
    setSaving(true);
    try {
      if (mode === "bootstrap") {
        const r = await api.post("/v1/threat-models/bootstrap", { name, owner_team: team || null });
        toast.success(`Model created — ${r.data.auto_threats_created ?? 0} threat(s) auto-drafted from open findings`);
      } else {
        await api.post("/v1/threat-models", { name, description });
        toast.success("Blank model created");
      }
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to create model");
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="text-[14px] text-slate-100 font-medium">New Threat Model</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Name</label>
            <input value={name} onChange={e => setName(e.target.value)} placeholder='e.g. "County web services"'
              className="w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100"/>
          </div>
          <div className="flex gap-2">
            <button onClick={() => setMode("bootstrap")}
              className={`flex-1 border rounded-md p-3 text-left ${mode === "bootstrap" ? "border-blue-500/50 bg-blue-500/10" : "border-[#30363D]"}`}>
              <div className="text-[12.5px] text-slate-200 inline-flex items-center gap-1.5"><Sparkle size={13} className="text-blue-300"/> Bootstrap from platform</div>
              <div className="text-[11px] text-slate-500 mt-1">Builds the DFD from your asset inventory and drafts threats from open findings (CWE → STRIDE).</div>
            </button>
            <button onClick={() => setMode("blank")}
              className={`flex-1 border rounded-md p-3 text-left ${mode === "blank" ? "border-blue-500/50 bg-blue-500/10" : "border-[#30363D]"}`}>
              <div className="text-[12.5px] text-slate-200">Start blank</div>
              <div className="text-[11px] text-slate-500 mt-1">Empty canvas — draw the system by hand.</div>
            </button>
          </div>
          {mode === "bootstrap" && (
            <div>
              <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Limit to team (optional)</label>
              <select value={team} onChange={e => setTeam(e.target.value)}
                className="w-full mt-1 h-9 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200">
                <option value="">All teams (top 30 assets by exposure/criticality)</option>
                {teams.map(t => <option key={t.id || t.name} value={t.name}>{t.name}</option>)}
              </select>
            </div>
          )}
          {mode === "blank" && (
            <div>
              <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Description</label>
              <textarea value={description} onChange={e => setDescription(e.target.value)} rows={2}
                className="w-full mt-1 px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100"/>
            </div>
          )}
        </div>
        <div className="flex justify-end gap-2 px-5 py-3.5 border-t border-[#30363D]">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={save} disabled={saving}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">
            {saving ? "Creating…" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}
