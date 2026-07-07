import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Plus, X, Trash, CaretUp, CaretDown, FloppyDisk, PencilSimple, Megaphone } from "@phosphor-icons/react";
import { toast } from "sonner";

const TABS = ["Plan Phases", "Roles", "Classification", "Wizard Questions", "Reporting Obligations", "Tool Catalog"];

function StepListInput({ items, onChange, placeholder }) {
  const update = (i, v) => { const next = [...items]; next[i] = v; onChange(next); };
  const remove = (i) => onChange(items.filter((_, idx) => idx !== i));
  const add = () => onChange([...items, ""]);
  return (
    <div className="space-y-1">
      {items.map((v, i) => (
        <div key={i} className="flex items-center gap-1.5">
          <span className="text-[10px] text-slate-600 font-mono w-4 shrink-0">{i + 1}.</span>
          <input value={v} onChange={(e) => update(i, e.target.value)} placeholder={placeholder}
            className="flex-1 h-7 bg-[#161B22] border border-[#30363D] rounded px-2 text-[11.5px] text-slate-200" />
          <button onClick={() => remove(i)} className="text-slate-500 hover:text-red-400 shrink-0"><X size={12} /></button>
        </div>
      ))}
      <button onClick={add} className="text-[11px] text-blue-300 hover:text-blue-200 inline-flex items-center gap-1"><Plus size={11} /> Add</button>
    </div>
  );
}

function SectionSave({ onSave, saving }) {
  return (
    <button onClick={onSave} disabled={saving} className="h-8 px-3 text-[12px] bg-blue-500/20 border border-blue-500/40 text-blue-200 rounded inline-flex items-center gap-1.5 disabled:opacity-50">
      <FloppyDisk size={14} /> {saving ? "Saving…" : "Save changes"}
    </button>
  );
}

function PhasesTab() {
  const [phases, setPhases] = useState(null);
  const [saving, setSaving] = useState(false);
  useEffect(() => { api.get("/v1/admin/ir/plan").then(r => setPhases(r.data.phases)); }, []);
  if (!phases) return <div className="text-slate-500 text-[12.5px]">Loading…</div>;

  const update = (i, patch) => { const next = [...phases]; next[i] = { ...next[i], ...patch }; setPhases(next); };
  const move = (i, dir) => {
    const j = i + dir; if (j < 0 || j >= phases.length) return;
    const next = [...phases]; [next[i], next[j]] = [next[j], next[i]]; setPhases(next);
  };
  const remove = (i) => setPhases(phases.filter((_, idx) => idx !== i));
  const addPhase = () => setPhases([...phases, { name: "New phase", responsible_party: "", tasks: [], objectives: [], things_needed: [] }]);

  const save = async () => {
    setSaving(true);
    try {
      const r = await api.put("/v1/admin/ir/plan", { phases });
      setPhases(r.data.phases);
      toast.success("IR plan phases saved.");
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to save"); } finally { setSaving(false); }
  };

  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <div className="text-[12px] text-slate-500">Phases run in this order for every new case. Add, remove, reorder, or rewrite any of them for how your org actually works.</div>
        <SectionSave onSave={save} saving={saving} />
      </div>
      {phases.map((p, i) => (
        <div key={p.id || i} className="border border-[#30363D] bg-[#0D1117] rounded-md p-3.5">
          <div className="flex items-center gap-2 mb-2">
            <div className="flex flex-col">
              <button onClick={() => move(i, -1)} disabled={i === 0} className="text-slate-500 hover:text-slate-200 disabled:opacity-30"><CaretUp size={12} /></button>
              <button onClick={() => move(i, 1)} disabled={i === phases.length - 1} className="text-slate-500 hover:text-slate-200 disabled:opacity-30"><CaretDown size={12} /></button>
            </div>
            <input value={p.name} onChange={e => update(i, { name: e.target.value })}
              className="flex-1 h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-100 font-medium" />
            <button onClick={() => remove(i)} className="text-slate-500 hover:text-red-400 shrink-0"><Trash size={14} /></button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="text-[10.5px] uppercase font-mono text-slate-500">Responsible party</label>
              <input value={p.responsible_party || ""} onChange={e => update(i, { responsible_party: e.target.value })}
                className="w-full h-7 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[11.5px] text-slate-200" />
            </div>
            <div>
              <label className="text-[10.5px] uppercase font-mono text-slate-500">Objectives</label>
              <div className="mt-1"><StepListInput items={p.objectives || []} onChange={v => update(i, { objectives: v })} placeholder="Objective…" /></div>
            </div>
          </div>
          <div className="mt-2">
            <label className="text-[10.5px] uppercase font-mono text-slate-500">Tasks</label>
            <div className="mt-1"><StepListInput items={p.tasks || []} onChange={v => update(i, { tasks: v })} placeholder="Task…" /></div>
          </div>
          <div className="mt-2">
            <label className="text-[10.5px] uppercase font-mono text-slate-500">Things you'll need</label>
            <div className="mt-1"><StepListInput items={p.things_needed || []} onChange={v => update(i, { things_needed: v })} placeholder="Resource…" /></div>
          </div>
        </div>
      ))}
      <button onClick={addPhase} className="h-8 px-3 text-[12px] border border-dashed border-[#30363D] hover:border-[#484F58] text-slate-400 rounded inline-flex items-center gap-1.5">
        <Plus size={14} /> Add phase
      </button>
    </div>
  );
}

function RolesTab() {
  const [roles, setRoles] = useState(null);
  const [saving, setSaving] = useState(false);
  useEffect(() => { api.get("/v1/admin/ir/roles").then(r => setRoles(r.data.roles)); }, []);
  if (!roles) return <div className="text-slate-500 text-[12.5px]">Loading…</div>;

  const update = (i, patch) => { const next = [...roles]; next[i] = { ...next[i], ...patch }; setRoles(next); };
  const remove = (i) => setRoles(roles.filter((_, idx) => idx !== i));
  const addRole = () => setRoles([...roles, { name: "New role", kind: "optional", description: "", contacts: [] }]);

  const save = async () => {
    setSaving(true);
    try {
      const r = await api.put("/v1/admin/ir/roles", { roles });
      setRoles(r.data.roles);
      toast.success("Roles saved.");
    } catch (e) { toast.error("Failed to save"); } finally { setSaving(false); }
  };

  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <div className="text-[12px] text-slate-500">These are the roles offered when assigning people to a case.</div>
        <SectionSave onSave={save} saving={saving} />
      </div>
      {roles.map((r, i) => (
        <div key={r.id || i} className="border border-[#30363D] bg-[#0D1117] rounded-md p-3 grid grid-cols-1 md:grid-cols-[1fr_140px_1fr_auto] gap-2 items-start">
          <input value={r.name} onChange={e => update(i, { name: e.target.value })} placeholder="Role name"
            className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200" />
          <select value={r.kind} onChange={e => update(i, { kind: e.target.value })}
            className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200">
            <option value="standing">standing</option>
            <option value="mandatory">mandatory</option>
            <option value="optional">optional</option>
          </select>
          <input value={r.description || ""} onChange={e => update(i, { description: e.target.value })} placeholder="Description"
            className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200" />
          <button onClick={() => remove(i)} className="text-slate-500 hover:text-red-400 h-8 flex items-center"><Trash size={14} /></button>
        </div>
      ))}
      <button onClick={addRole} className="h-8 px-3 text-[12px] border border-dashed border-[#30363D] hover:border-[#484F58] text-slate-400 rounded inline-flex items-center gap-1.5">
        <Plus size={14} /> Add role
      </button>
    </div>
  );
}

function ClassificationTab() {
  const [levels, setLevels] = useState(null);
  const [saving, setSaving] = useState(false);
  useEffect(() => { api.get("/v1/admin/ir/classification").then(r => setLevels(r.data.levels)); }, []);
  if (!levels) return <div className="text-slate-500 text-[12.5px]">Loading…</div>;

  const update = (i, patch) => { const next = [...levels]; next[i] = { ...next[i], ...patch }; setLevels(next); };
  const remove = (i) => setLevels(levels.filter((_, idx) => idx !== i));
  const addLevel = () => setLevels([...levels, { level: "New Level", criteria: "", response: "" }]);

  const save = async () => {
    setSaving(true);
    try {
      const r = await api.put("/v1/admin/ir/classification", { levels });
      setLevels(r.data.levels);
      toast.success("Classification levels saved.");
    } catch (e) { toast.error("Failed to save"); } finally { setSaving(false); }
  };

  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <div className="text-[12px] text-slate-500">Drives the wizard's auto-classification and shows on the case detail's classification picker.</div>
        <SectionSave onSave={save} saving={saving} />
      </div>
      {levels.map((l, i) => (
        <div key={i} className="border border-[#30363D] bg-[#0D1117] rounded-md p-3.5">
          <div className="flex items-center gap-2 mb-2">
            <input value={l.level} onChange={e => update(i, { level: e.target.value })}
              className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-100 font-medium w-48" />
            <button onClick={() => remove(i)} className="text-slate-500 hover:text-red-400 ml-auto"><Trash size={14} /></button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="text-[10.5px] uppercase font-mono text-slate-500">Criteria</label>
              <textarea rows={2} value={l.criteria} onChange={e => update(i, { criteria: e.target.value })}
                className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1 text-[11.5px] text-slate-200" />
            </div>
            <div>
              <label className="text-[10.5px] uppercase font-mono text-slate-500">Response</label>
              <textarea rows={2} value={l.response} onChange={e => update(i, { response: e.target.value })}
                className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1 text-[11.5px] text-slate-200" />
            </div>
          </div>
        </div>
      ))}
      <button onClick={addLevel} className="h-8 px-3 text-[12px] border border-dashed border-[#30363D] hover:border-[#484F58] text-slate-400 rounded inline-flex items-center gap-1.5">
        <Plus size={14} /> Add level
      </button>
    </div>
  );
}

function WizardTab() {
  const [cfg, setCfg] = useState(null);
  const [saving, setSaving] = useState(false);
  useEffect(() => { api.get("/v1/admin/ir/wizard-config").then(r => setCfg(r.data)); }, []);
  if (!cfg) return <div className="text-slate-500 text-[12.5px]">Loading…</div>;

  const updateQ = (qi, patch) => {
    const questions = [...cfg.questions]; questions[qi] = { ...questions[qi], ...patch }; setCfg({ ...cfg, questions });
  };
  const updateOpt = (qi, oi, patch) => {
    const questions = [...cfg.questions];
    const options = [...questions[qi].options]; options[oi] = { ...options[oi], ...patch };
    questions[qi] = { ...questions[qi], options };
    setCfg({ ...cfg, questions });
  };
  const addOption = (qi) => {
    const questions = [...cfg.questions];
    questions[qi] = { ...questions[qi], options: [...questions[qi].options, { label: "New option", weights: {} }] };
    setCfg({ ...cfg, questions });
  };
  const removeOption = (qi, oi) => {
    const questions = [...cfg.questions];
    questions[qi] = { ...questions[qi], options: questions[qi].options.filter((_, idx) => idx !== oi) };
    setCfg({ ...cfg, questions });
  };
  const addQuestion = () => setCfg({ ...cfg, questions: [...cfg.questions, { text: "New question", help_text: "", options: [{ label: "Yes", weights: {} }, { label: "No", weights: {} }] }] });
  const removeQuestion = (qi) => setCfg({ ...cfg, questions: cfg.questions.filter((_, idx) => idx !== qi) });

  const updateCategory = (ci, label) => {
    const categories = [...cfg.categories]; categories[ci] = { ...categories[ci], label }; setCfg({ ...cfg, categories });
  };
  const updateActionPlan = (catId, patch) => {
    setCfg({ ...cfg, action_plans: { ...cfg.action_plans, [catId]: { ...(cfg.action_plans[catId] || {}), ...patch } } });
  };

  const save = async () => {
    setSaving(true);
    try {
      const r = await api.put("/v1/admin/ir/wizard-config", cfg);
      setCfg(r.data);
      toast.success("Wizard configuration saved.");
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to save"); } finally { setSaving(false); }
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <div className="text-[12px] text-slate-500">Every question is shown once. Each option adds weight toward one or more outcome categories, and can add severity points or trigger the immediate-containment fast path.</div>
        <SectionSave onSave={save} saving={saving} />
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3.5">
        <div className="text-[12px] font-medium text-slate-100 mb-2">Outcome categories &amp; action plans</div>
        <div className="space-y-3">
          {cfg.categories.map((c, ci) => (
            <div key={c.id} className="border border-[#21262D] rounded p-2.5">
              <input value={c.label} onChange={e => updateCategory(ci, e.target.value)}
                className="h-7 mb-1.5 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200 font-medium" />
              <label className="text-[10px] uppercase font-mono text-slate-500">Immediate actions</label>
              <div className="mt-1">
                <StepListInput items={cfg.action_plans[c.id]?.immediate_actions || []}
                  onChange={v => updateActionPlan(c.id, { immediate_actions: v })} placeholder="Action…" />
              </div>
            </div>
          ))}
        </div>
      </div>

      {cfg.questions.map((q, qi) => (
        <div key={q.id || qi} className="border border-[#30363D] bg-[#0D1117] rounded-md p-3.5">
          <div className="flex items-center gap-2 mb-2">
            <input value={q.text} onChange={e => updateQ(qi, { text: e.target.value })}
              className="flex-1 h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-100" />
            <button onClick={() => removeQuestion(qi)} className="text-slate-500 hover:text-red-400 shrink-0"><Trash size={14} /></button>
          </div>
          <input value={q.help_text || ""} onChange={e => updateQ(qi, { help_text: e.target.value })} placeholder="Help text (optional)"
            className="w-full h-7 mb-2 bg-[#161B22] border border-[#30363D] rounded px-2 text-[11px] text-slate-400" />
          <div className="space-y-2">
            {q.options.map((opt, oi) => (
              <div key={opt.id || oi} className="border border-[#21262D] rounded p-2">
                <div className="flex items-center gap-2 mb-1.5">
                  <input value={opt.label} onChange={e => updateOpt(qi, oi, { label: e.target.value })}
                    className="flex-1 h-7 bg-[#161B22] border border-[#30363D] rounded px-2 text-[11.5px] text-slate-200" />
                  <label className="text-[10px] text-slate-500 flex items-center gap-1 shrink-0">
                    <input type="checkbox" checked={!!opt.immediate_containment} onChange={e => updateOpt(qi, oi, { immediate_containment: e.target.checked })} /> containment
                  </label>
                  <input type="number" value={opt.severity_points || 0} onChange={e => updateOpt(qi, oi, { severity_points: Number(e.target.value) })}
                    title="Severity points" className="w-14 h-7 bg-[#161B22] border border-[#30363D] rounded px-1 text-[11px] text-slate-200 shrink-0" />
                  <button onClick={() => removeOption(qi, oi)} className="text-slate-500 hover:text-red-400 shrink-0"><X size={13} /></button>
                </div>
                <div className="flex flex-wrap gap-2">
                  {cfg.categories.map(c => (
                    <label key={c.id} className="text-[10px] text-slate-500 flex items-center gap-1">
                      {c.label.split(" ")[0]}
                      <input type="number" value={opt.weights?.[c.id] || 0}
                        onChange={e => updateOpt(qi, oi, { weights: { ...(opt.weights || {}), [c.id]: Number(e.target.value) } })}
                        className="w-12 h-6 bg-[#161B22] border border-[#30363D] rounded px-1 text-[10.5px] text-slate-200" />
                    </label>
                  ))}
                </div>
              </div>
            ))}
            <button onClick={() => addOption(qi)} className="text-[11px] text-blue-300 hover:text-blue-200 inline-flex items-center gap-1"><Plus size={11} /> Add option</button>
          </div>
        </div>
      ))}
      <button onClick={addQuestion} className="h-8 px-3 text-[12px] border border-dashed border-[#30363D] hover:border-[#484F58] text-slate-400 rounded inline-flex items-center gap-1.5">
        <Plus size={14} /> Add question
      </button>
    </div>
  );
}

function ContactsEditor({ contacts, onChange }) {
  const update = (i, patch) => { const next = [...contacts]; next[i] = { ...next[i], ...patch }; onChange(next); };
  const remove = (i) => onChange(contacts.filter((_, idx) => idx !== i));
  const add = () => onChange([...contacts, { name: "", team: "", email: "", phone: "", portal_url: "" }]);
  return (
    <div className="space-y-1.5">
      {contacts.map((c, i) => (
        <div key={i} className="grid grid-cols-1 md:grid-cols-[1fr_1fr_1fr_1fr_auto] gap-1.5">
          <input value={c.name || ""} onChange={e => update(i, { name: e.target.value })} placeholder="Contact/agency name"
            className="h-7 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11px] text-slate-200" />
          <input value={c.team || ""} onChange={e => update(i, { team: e.target.value })} placeholder="Team/dept"
            className="h-7 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11px] text-slate-200" />
          <input value={c.email || ""} onChange={e => update(i, { email: e.target.value })} placeholder="Email"
            className="h-7 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11px] text-slate-200" />
          <input value={c.phone || ""} onChange={e => update(i, { phone: e.target.value })} placeholder="Phone"
            className="h-7 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11px] text-slate-200" />
          <button onClick={() => remove(i)} className="text-slate-500 hover:text-red-400"><X size={13} /></button>
        </div>
      ))}
      <button onClick={add} className="text-[11px] text-blue-300 hover:text-blue-200 inline-flex items-center gap-1"><Plus size={11} /> Add contact</button>
    </div>
  );
}

const EMPTY_OBLIGATION = {
  name: "", trigger_description: "", reporting_target: "", timeline_hours: "", timeline_text: "",
  contacts: [], auto_notify: false, notify_webhook_url: "", active: true,
};

function ObligationsTab() {
  const [items, setItems] = useState([]);
  const [form, setForm] = useState(EMPTY_OBLIGATION);
  const [editingId, setEditingId] = useState(null);

  const load = () => api.get("/v1/admin/ir/obligations").then(r => setItems(r.data.items));
  useEffect(() => { load(); }, []);

  const startEdit = (o) => {
    setEditingId(o.id);
    setForm({ ...EMPTY_OBLIGATION, ...o, timeline_hours: o.timeline_hours ?? "" });
  };
  const cancelEdit = () => { setEditingId(null); setForm(EMPTY_OBLIGATION); };

  const save = async () => {
    if (!form.name.trim()) { toast.error("Name is required"); return; }
    const body = { ...form, timeline_hours: form.timeline_hours === "" ? null : Number(form.timeline_hours) };
    try {
      if (editingId) { await api.put(`/v1/admin/ir/obligations/${editingId}`, body); toast.success("Obligation updated."); }
      else { await api.post("/v1/admin/ir/obligations", body); toast.success("Obligation added."); }
      cancelEdit();
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to save"); }
  };

  const remove = async (id) => {
    if (!window.confirm("Remove this reporting obligation from the library? Cases that already attached it keep their own copy.")) return;
    await api.delete(`/v1/admin/ir/obligations/${id}`);
    if (editingId === id) cancelEdit();
    load();
  };

  return (
    <div className="space-y-4">
      <div className="text-[12px] text-slate-500 flex items-start gap-1.5">
        <Megaphone size={14} className="text-slate-500 shrink-0 mt-0.5"/>
        <span>Mandatory and internal reporting/notification requirements -- who needs to be told, on what deadline, when an incident happens.
        Add or remove frameworks freely (CISA/CIRCIA, HIPAA, PCI, CJIS, state breach law, airport/TSA, elections, insurance, your own
        internal leadership notification, or anything else specific to your org). Attached to a case under "Reporting obligations" --
        each one can be notified manually ("Notify now") or automatically the moment it's attached, per obligation.</span>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3.5 space-y-2">
        {editingId && <div className="text-[11px] text-amber-300">Editing existing obligation — <button onClick={cancelEdit} className="underline">cancel</button></div>}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Framework / obligation name (e.g. HIPAA Breach — 500+ records)"
            className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200" />
          <input value={form.reporting_target} onChange={e => setForm({ ...form, reporting_target: e.target.value })} placeholder="Who gets notified (agency/target)"
            className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200" />
        </div>
        <textarea rows={2} value={form.trigger_description} onChange={e => setForm({ ...form, trigger_description: e.target.value })} placeholder="What triggers this obligation"
          className="w-full bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12px] text-slate-200" />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <input type="number" value={form.timeline_hours} onChange={e => setForm({ ...form, timeline_hours: e.target.value })} placeholder="Deadline in hours (for a due-date countdown; leave blank if not fixed)"
            className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200" />
          <input value={form.timeline_text} onChange={e => setForm({ ...form, timeline_text: e.target.value })} placeholder="Human-readable deadline (e.g. Within 72 hours)"
            className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200" />
        </div>
        <div>
          <label className="text-[10.5px] uppercase font-mono text-slate-500">Contacts</label>
          <div className="mt-1"><ContactsEditor contacts={form.contacts} onChange={v => setForm({ ...form, contacts: v })} /></div>
        </div>
        <div className="flex items-center gap-4 flex-wrap">
          <label className="text-[11.5px] text-slate-400 flex items-center gap-1.5">
            <input type="checkbox" checked={!!form.auto_notify} onChange={e => setForm({ ...form, auto_notify: e.target.checked })} />
            Auto-notify contacts the moment this is attached to a case
          </label>
          <input value={form.notify_webhook_url || ""} onChange={e => setForm({ ...form, notify_webhook_url: e.target.value })} placeholder="Optional webhook URL (chat/Teams/Slack) to also notify"
            className="flex-1 min-w-[220px] h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200" />
          <label className="text-[11.5px] text-slate-400 flex items-center gap-1.5">
            <input type="checkbox" checked={form.active !== false} onChange={e => setForm({ ...form, active: e.target.checked })} /> Active
          </label>
        </div>
        <button onClick={save} className="h-8 px-3 text-[12px] bg-blue-500/20 border border-blue-500/40 text-blue-200 rounded inline-flex items-center gap-1.5">
          <Plus size={13} /> {editingId ? "Save changes" : "Add obligation"}
        </button>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
        {items.map(o => (
          <div key={o.id} className="p-3 flex items-center justify-between gap-2">
            <div className="min-w-0">
              <div className="text-[12.5px] text-slate-200 flex items-center gap-1.5">
                {o.name}
                {!o.active && <Chip color="slate">disabled</Chip>}
                {o.auto_notify && <Chip color="amber">auto-notify</Chip>}
              </div>
              <div className="text-[11px] text-slate-500">{o.reporting_target} — {o.timeline_text}</div>
            </div>
            <div className="flex items-center gap-1 shrink-0">
              <button onClick={() => startEdit(o)} className="text-slate-500 hover:text-blue-300"><PencilSimple size={14} /></button>
              <button onClick={() => remove(o.id)} className="text-slate-500 hover:text-red-400"><Trash size={14} /></button>
            </div>
          </div>
        ))}
        {items.length === 0 && <div className="p-4 text-center text-[11.5px] text-slate-600">No reporting obligations configured yet.</div>}
      </div>
    </div>
  );
}


const EMPTY_TOOL = { name: "", description: "", location: "", applicable_categories: [], linked_integration: "", vendor: "" };

function ToolsTab() {
  const [items, setItems] = useState([]);
  const [categories, setCategories] = useState([]);
  const [integrations, setIntegrations] = useState([]);
  const [form, setForm] = useState(EMPTY_TOOL);
  const [editingId, setEditingId] = useState(null);

  const load = () => api.get("/v1/admin/ir/tools").then(r => setItems(r.data.items));
  useEffect(() => {
    load();
    api.get("/v1/admin/ir/wizard-config").then(r => setCategories(r.data.categories));
    api.get("/v1/integrations").then(r => setIntegrations(r.data.items)).catch(() => setIntegrations([]));
  }, []);

  const toggleCat = (catId) => {
    const has = form.applicable_categories.includes(catId);
    setForm({ ...form, applicable_categories: has ? form.applicable_categories.filter(c => c !== catId) : [...form.applicable_categories, catId] });
  };

  const startEdit = (t) => {
    setEditingId(t.id);
    setForm({ name: t.name, description: t.description || "", location: t.location || "", applicable_categories: t.applicable_categories || [],
      linked_integration: t.linked_integration || "", vendor: t.vendor || "" });
  };
  const cancelEdit = () => { setEditingId(null); setForm(EMPTY_TOOL); };

  const save = async () => {
    if (!form.name.trim()) { toast.error("Name is required"); return; }
    try {
      if (editingId) {
        await api.put(`/v1/admin/ir/tools/${editingId}`, form);
        toast.success("Tool updated.");
      } else {
        await api.post("/v1/admin/ir/tools", form);
        toast.success("Tool added.");
      }
      cancelEdit();
      load();
    } catch (e) { toast.error("Failed to save tool"); }
  };

  const remove = async (id) => {
    if (!window.confirm("Remove this tool?")) return;
    await api.delete(`/v1/admin/ir/tools/${id}`);
    if (editingId === id) cancelEdit();
    load();
  };

  return (
    <div className="space-y-4">
      <div className="text-[12px] text-slate-500">What tools/resources responders have available, tagged by which incident category they help with, and optionally linked to a real connector (Qualys, CrowdStrike, etc.) or a vendor name (Palo Alto, Google Workspace Admin Console, on-prem Domain Controllers…) so people know exactly what system to check. Surfaced automatically on the wizard's result screen.</div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3.5 space-y-2">
        {editingId && <div className="text-[11px] text-amber-300">Editing existing tool — <button onClick={cancelEdit} className="underline">cancel</button></div>}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Tool/resource name"
            className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200" />
          <input value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} placeholder="Description"
            className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200" />
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          <select value={form.linked_integration || ""} onChange={e => setForm({ ...form, linked_integration: e.target.value })}
            className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200">
            <option value="">Not a configured connector…</option>
            {integrations.map(i => <option key={i.id} value={i.name}>{i.name}</option>)}
          </select>
          <input value={form.vendor} onChange={e => setForm({ ...form, vendor: e.target.value })} placeholder="Or vendor/product name (e.g. Palo Alto)"
            className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200" />
          <input value={form.location} onChange={e => setForm({ ...form, location: e.target.value })} placeholder="URL / location / instructions"
            className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200" />
        </div>
        <div className="flex flex-wrap gap-1.5">
          {categories.map(c => (
            <button key={c.id} onClick={() => toggleCat(c.id)}
              className={`h-6 px-2 rounded-full text-[10.5px] border ${form.applicable_categories.includes(c.id) ? "bg-blue-500/20 border-blue-500/50 text-blue-200" : "border-[#30363D] text-slate-500"}`}>
              {c.label}
            </button>
          ))}
        </div>
        <button onClick={save} className="h-8 px-3 text-[12px] bg-blue-500/20 border border-blue-500/40 text-blue-200 rounded inline-flex items-center gap-1.5">
          <Plus size={13} /> {editingId ? "Save changes" : "Add tool"}
        </button>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
        {items.map(t => (
          <div key={t.id} className="p-3 flex items-center justify-between gap-2">
            <div className="min-w-0">
              <div className="text-[12.5px] text-slate-200 flex items-center gap-1.5">
                {t.name}
                {(t.linked_integration || t.vendor) && <Chip color="blue">{t.linked_integration || t.vendor}</Chip>}
              </div>
              <div className="text-[11px] text-slate-500">{t.description}</div>
              <div className="flex flex-wrap gap-1 mt-1">
                {(t.applicable_categories || []).map(cid => {
                  const c = categories.find(cc => cc.id === cid);
                  return <Chip key={cid} color="slate">{c?.label || cid}</Chip>;
                })}
              </div>
            </div>
            <div className="flex items-center gap-1 shrink-0">
              <button onClick={() => startEdit(t)} className="text-slate-500 hover:text-blue-300"><PencilSimple size={14} /></button>
              <button onClick={() => remove(t.id)} className="text-slate-500 hover:text-red-400"><Trash size={14} /></button>
            </div>
          </div>
        ))}
        {items.length === 0 && <div className="p-4 text-center text-[11.5px] text-slate-600">No tools configured yet.</div>}
      </div>
    </div>
  );
}

export default function IRAdminSetup() {
  const [tab, setTab] = useState(TABS[0]);
  return (
    <Layout title="Incident Response Setup" subtitle="Configure the IR plan phases, roles, classification levels, triage wizard, and tool catalog for your org">
      <div className="flex gap-1.5 mb-4 flex-wrap">
        {TABS.map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`h-8 px-3 rounded text-[12px] border ${tab === t ? "bg-blue-500/20 border-blue-500/50 text-blue-200" : "border-[#30363D] text-slate-400 hover:border-[#484F58]"}`}>
            {t}
          </button>
        ))}
      </div>
      {tab === "Plan Phases" && <PhasesTab />}
      {tab === "Roles" && <RolesTab />}
      {tab === "Classification" && <ClassificationTab />}
      {tab === "Wizard Questions" && <WizardTab />}
      {tab === "Reporting Obligations" && <ObligationsTab />}
      {tab === "Tool Catalog" && <ToolsTab />}
    </Layout>
  );
}
