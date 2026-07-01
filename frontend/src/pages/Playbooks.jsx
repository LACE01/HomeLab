import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Plus, X, Trash, PencilSimple, BookOpen } from "@phosphor-icons/react";
import { toast } from "sonner";

function StepListInput({ label, items, onChange, placeholder }) {
  const update = (i, v) => { const next = [...items]; next[i] = v; onChange(next); };
  const remove = (i) => onChange(items.filter((_, idx) => idx !== i));
  const add = () => onChange([...items, ""]);
  return (
    <div>
      <label className="text-[11px] uppercase font-mono text-slate-500">{label}</label>
      <div className="space-y-1.5 mt-1">
        {items.map((v, i) => (
          <div key={i} className="flex items-center gap-1.5">
            <span className="text-[11px] text-slate-500 font-mono w-4 shrink-0">{i+1}.</span>
            <input value={v} onChange={(e)=>update(i, e.target.value)} placeholder={placeholder}
              className="flex-1 h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200"/>
            <button onClick={()=>remove(i)} className="text-slate-500 hover:text-red-400 shrink-0"><X size={14}/></button>
          </div>
        ))}
        <button onClick={add} className="text-[11px] text-blue-300 hover:text-blue-200 inline-flex items-center gap-1"><Plus size={12}/> Add step</button>
      </div>
    </div>
  );
}

function PlaybookFormModal({ initial, onClose, onSaved }) {
  const [form, setForm] = useState(initial || {
    title: "", description: "", cve: "", cwe: "", steps: [""], rollback_notes: "", validation_checks: [""],
  });
  const [saving, setSaving] = useState(false);
  const isEdit = !!initial?.id;

  const save = async () => {
    if (!form.title.trim()) { toast.error("Title is required"); return; }
    if (!form.cve && !form.cwe) { toast.error("Set a CVE or a CWE for this playbook to match against"); return; }
    setSaving(true);
    try {
      const body = {
        title: form.title, description: form.description,
        cve: form.cve || null, cwe: form.cwe || null,
        steps: form.steps.filter(s => s.trim()),
        rollback_notes: form.rollback_notes,
        validation_checks: form.validation_checks.filter(s => s.trim()),
      };
      if (isEdit) await api.put(`/v1/playbooks/${initial.id}`, body);
      else await api.post("/v1/playbooks", body);
      toast.success(isEdit ? "Playbook updated." : "Playbook created.");
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to save playbook");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4 py-8 overflow-y-auto" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-xl my-auto" onClick={e=>e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between">
          <h3 className="text-[13px] font-medium text-slate-100">{isEdit ? "Edit playbook" : "New playbook"}</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16}/></button>
        </div>
        <div className="p-4 space-y-3 max-h-[70vh] overflow-y-auto">
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Title</label>
            <input data-testid="playbook-form-title" value={form.title} onChange={e=>setForm({...form, title:e.target.value})}
              className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200"/>
          </div>
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Description</label>
            <textarea value={form.description} onChange={e=>setForm({...form, description:e.target.value})}
              rows={2} className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200"/>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] uppercase font-mono text-slate-500">Matches CVE (exact, highest priority)</label>
              <input data-testid="playbook-form-cve" placeholder="CVE-2024-43629" value={form.cve||""} onChange={e=>setForm({...form, cve:e.target.value})}
                className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200 font-mono"/>
            </div>
            <div>
              <label className="text-[11px] uppercase font-mono text-slate-500">Or matches CWE (whole class)</label>
              <input data-testid="playbook-form-cwe" placeholder="CWE-89" value={form.cwe||""} onChange={e=>setForm({...form, cwe:e.target.value})}
                className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200 font-mono"/>
            </div>
          </div>
          <StepListInput label="Remediation steps" items={form.steps} onChange={(v)=>setForm({...form, steps:v})} placeholder="e.g. Apply the vendor patch..."/>
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Rollback notes</label>
            <textarea value={form.rollback_notes} onChange={e=>setForm({...form, rollback_notes:e.target.value})}
              rows={2} className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200"
              placeholder="What to do if the fix breaks something"/>
          </div>
          <StepListInput label="Validation checks" items={form.validation_checks} onChange={(v)=>setForm({...form, validation_checks:v})} placeholder="e.g. Scanner no longer reports the CVE"/>
        </div>
        <div className="px-4 py-3 border-t border-[#30363D] flex justify-end gap-2">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button data-testid="playbook-form-save" onClick={save} disabled={saving}
            className="h-8 px-3 text-[12px] bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/40 text-blue-200 rounded disabled:opacity-50">
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function Playbooks() {
  const [items, setItems] = useState([]);
  const [q, setQ] = useState("");
  const [searchParams] = useSearchParams();
  const [showForm, setShowForm] = useState(searchParams.get("new") === "1");
  const [editing, setEditing] = useState(searchParams.get("new") === "1" ? {
    title: "", description: "",
    cve: searchParams.get("cve") || "", cwe: searchParams.get("cwe") || "",
    steps: [""], rollback_notes: "", validation_checks: [""],
  } : null);

  const load = () => api.get("/v1/playbooks", { params: q ? {q} : {} }).then(r => setItems(r.data.items));
  useEffect(() => { load(); }, []); // eslint-disable-line

  const remove = async (p) => {
    if (!window.confirm(`Delete playbook "${p.title}"?`)) return;
    await api.delete(`/v1/playbooks/${p.id}`);
    toast.success("Playbook deleted.");
    load();
  };

  return (
    <Layout title="Remediation Playbooks" subtitle="Step-by-step fix guidance, rollback notes, and validation checks by CVE or CWE"
      actions={<button data-testid="new-playbook-btn" onClick={()=>setShowForm(true)}
        className="h-8 px-3 text-[12px] bg-blue-500/15 border border-blue-500/40 hover:bg-blue-500/25 text-blue-300 rounded inline-flex items-center gap-1.5">
        <Plus size={14}/> New playbook
      </button>}>
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-2 mb-3 flex gap-2">
        <input placeholder="Search title, CVE, or CWE…" value={q} onChange={(e)=>setQ(e.target.value)} onKeyDown={(e)=>e.key==='Enter'&&load()}
          className="flex-1 h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]"/>
        <button onClick={load} className="h-8 px-3 text-[12px] bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded">Search</button>
      </div>

      {items.length === 0 && (
        <div className="text-[12.5px] text-slate-500 border border-[#30363D] bg-[#0D1117] rounded-md p-6 text-center">
          No playbooks yet. Create one and attach it to a CVE or a CWE class.
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {items.map(p => (
          <div key={p.id} className="border border-[#30363D] bg-[#0D1117] rounded-md p-4" data-testid={`playbook-${p.id}`}>
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <BookOpen size={16} className="text-blue-300 shrink-0"/>
                <div className="text-[13.5px] font-medium text-slate-100 truncate">{p.title}</div>
              </div>
              <div className="flex items-center gap-1 shrink-0">
                <button onClick={()=>{setEditing(p); setShowForm(true);}} className="text-slate-500 hover:text-slate-200"><PencilSimple size={14}/></button>
                <button onClick={()=>remove(p)} className="text-slate-500 hover:text-red-400"><Trash size={14}/></button>
              </div>
            </div>
            <div className="text-[12px] text-slate-500 mt-1">{p.description}</div>
            <div className="flex gap-1.5 mt-2">
              {p.cve && <Chip color="blue">{p.cve}</Chip>}
              {p.cwe && <Chip>{p.cwe}</Chip>}
              <Chip color="slate">{p.steps?.length || 0} step{p.steps?.length===1?"":"s"}</Chip>
            </div>
          </div>
        ))}
      </div>

      {showForm && (
        <PlaybookFormModal
          initial={editing}
          onClose={()=>{setShowForm(false); setEditing(null);}}
          onSaved={()=>{setShowForm(false); setEditing(null); load();}}
        />
      )}
    </Layout>
  );
}
