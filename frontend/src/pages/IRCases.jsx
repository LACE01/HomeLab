import { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams, Link } from "react-router-dom";
import { api, API } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { useAuth } from "@/lib/auth";
import NewRiskModal from "@/components/NewRiskModal";
import {
  Plus, X, ArrowLeft, CheckSquare, Square, Notepad, Camera, Package as PackageIcon,
  UsersThree, FileArrowDown, Lock, CaretRight, Megaphone, Bell, ClockCountdown,
  Flag, PencilSimple, DownloadSimple, UserPlus, UploadSimple, Trash, FolderSimple,
  ArrowClockwise, Warning, DesktopTower, Globe, Handshake, User as UserIcon, LinkSimple, ListChecks,
} from "@phosphor-icons/react";
import { toast } from "sonner";

const CLASSIFICATION_COLOR = {
  Critical: "red", Significant: "orange", Moderate: "amber", Minor: "blue", Negligible: "slate",
};
const CLASSIFICATION_LEVELS = ["Critical", "Significant", "Moderate", "Minor", "Negligible"];

function NewCaseModal({ onClose, onSaved }) {
  const [form, setForm] = useState({ title: "", classification: "Moderate", initial_intake: "", reporter_contact: "" });
  const [saving, setSaving] = useState(false);
  const save = async () => {
    if (!form.title.trim()) { toast.error("Title is required"); return; }
    setSaving(true);
    try {
      const r = await api.post("/v1/ir/cases", form);
      toast.success(`Case ${r.data.case_number} opened.`);
      onSaved(r.data);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to open case");
    } finally { setSaving(false); }
  };
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-md" onClick={e=>e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between">
          <h3 className="text-[13px] font-medium text-slate-100">Open an IR case manually</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16}/></button>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Title</label>
            <input value={form.title} onChange={e=>setForm({...form, title: e.target.value})}
              className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200"/>
          </div>
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Classification</label>
            <select value={form.classification} onChange={e=>setForm({...form, classification: e.target.value})}
              className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200">
              {CLASSIFICATION_LEVELS.map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Initial intake notes</label>
            <textarea rows={3} value={form.initial_intake} onChange={e=>setForm({...form, initial_intake: e.target.value})}
              className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200"/>
          </div>
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Reporter contact</label>
            <input value={form.reporter_contact} onChange={e=>setForm({...form, reporter_contact: e.target.value})}
              className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200"/>
          </div>
        </div>
        <div className="px-4 py-3 border-t border-[#30363D] flex justify-end gap-2">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={save} disabled={saving} className="h-8 px-3 text-[12px] bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/40 text-blue-200 rounded disabled:opacity-50">
            {saving ? "Opening…" : "Open case"}
          </button>
        </div>
      </div>
    </div>
  );
}

export function IRCases() {
  const navigate = useNavigate();
  const { canEdit } = useAuth();
  const [items, setItems] = useState([]);
  const [status, setStatus] = useState("open");
  const [showNew, setShowNew] = useState(false);

  const load = useCallback(() => {
    api.get("/v1/ir/cases", { params: status ? { status } : {} }).then(r => setItems(r.data.items));
  }, [status]);
  useEffect(() => { load(); }, [load]);

  return (
    <Layout title="Incident Response Cases" subtitle="Every incident opened by the triage wizard or manually, from open to closed"
      actions={canEdit("/ir/cases") && (
        <button onClick={()=>setShowNew(true)} className="h-8 px-3 text-[12px] bg-blue-500/15 border border-blue-500/40 hover:bg-blue-500/25 text-blue-300 rounded inline-flex items-center gap-1.5">
          <Plus size={14}/> New case
        </button>
      )}>
      <div className="flex gap-1.5 mb-3">
        {["open", "closed", ""].map(s => (
          <button key={s || "all"} onClick={()=>setStatus(s)}
            className={`h-7 px-2.5 rounded-full text-[11px] border ${status===s ? "bg-blue-500/20 border-blue-500/50 text-blue-200" : "border-[#30363D] text-slate-500 hover:border-[#484F58]"}`}>
            {s ? s[0].toUpperCase()+s.slice(1) : "All"}
          </button>
        ))}
      </div>

      {items.length === 0 && (
        <div className="text-[12.5px] text-slate-500 border border-[#30363D] bg-[#0D1117] rounded-md p-6 text-center">
          No cases here. Cases open automatically from the Triage Wizard, or you can open one manually.
        </div>
      )}

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
        {items.map(c => (
          <div key={c.id} onClick={()=>navigate(`/ir/cases/${c.id}`)}
            className="p-3.5 flex items-center justify-between gap-3 cursor-pointer hover:bg-[#161B22] transition-colors">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-mono text-slate-500">{c.case_number}</span>
                <span className="text-[13px] text-slate-100 truncate">{c.title}</span>
              </div>
              <div className="text-[11px] text-slate-500 mt-0.5">
                Opened {new Date(c.opened_at).toLocaleString()} {c.closed_at && `— Closed ${new Date(c.closed_at).toLocaleDateString()}`}
              </div>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              <Chip color={CLASSIFICATION_COLOR[c.classification] || "slate"}>{c.classification}</Chip>
              <Chip color={c.status === "open" ? "green" : "slate"}>{c.status}</Chip>
              <CaretRight size={14} className="text-slate-600"/>
            </div>
          </div>
        ))}
      </div>

      {showNew && <NewCaseModal onClose={()=>setShowNew(false)} onSaved={(c)=>{setShowNew(false); navigate(`/ir/cases/${c.id}`);}}/>}
    </Layout>
  );
}

function PhaseChecklist({ caseId, phases, canEditCase, onChanged }) {
  const toggle = async (phaseId, taskIndex, done) => {
    try {
      await api.put(`/v1/ir/cases/${caseId}/phases/${phaseId}/tasks`, { task_index: taskIndex, done });
      onChanged();
    } catch (e) { toast.error("Failed to update task"); }
  };
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md">
      <div className="px-4 py-3 border-b border-[#30363D] text-[13px] font-medium text-slate-100">
        Phase checklist ({phases.filter(p=>p.completed_at).length}/{phases.length} complete)
      </div>
      <div className="divide-y divide-[#30363D] max-h-[420px] overflow-y-auto">
        {phases.map((p) => (
          <details key={p.phase_id} className="p-3.5" open={!p.completed_at}>
            <summary className="cursor-pointer flex items-center justify-between text-[12.5px] text-slate-200">
              <span>{p.order + 1}. {p.phase_name}</span>
              {p.completed_at ? <Chip color="green">done</Chip> : <Chip color="slate">{p.tasks_done?.length || 0} done</Chip>}
            </summary>
            <div className="mt-2 space-y-1.5 pl-1">
              {(p.tasks || []).map((t, i) => {
                const done = (p.tasks_done || []).includes(i);
                return (
                  <button key={i} disabled={!canEditCase} onClick={() => toggle(p.phase_id, i, !done)}
                    className="flex items-start gap-2 text-[12px] text-left w-full text-slate-300 hover:text-slate-100 disabled:cursor-default">
                    {done ? <CheckSquare size={15} className="text-emerald-400 shrink-0 mt-0.5"/> : <Square size={15} className="text-slate-600 shrink-0 mt-0.5"/>}
                    <span className={done ? "line-through text-slate-500" : ""}>{t}</span>
                  </button>
                );
              })}
              {(!p.tasks || p.tasks.length === 0) && <div className="text-[11.5px] text-slate-600">No tasks configured for this phase.</div>}
            </div>
          </details>
        ))}
      </div>
    </div>
  );
}

function ObligationsPanel({ caseId, canEditCase, onChanged }) {
  const [library, setLibrary] = useState([]);
  const [attached, setAttached] = useState([]);
  const [pickerId, setPickerId] = useState("");

  const load = useCallback(() => {
    api.get("/v1/ir/obligations-lite").then(r => setLibrary(r.data.items));
    api.get(`/v1/ir/cases/${caseId}/obligations`).then(r => setAttached(r.data.items));
  }, [caseId]);
  useEffect(() => { load(); }, [load]);

  const attach = async () => {
    if (!pickerId) return;
    try {
      await api.post(`/v1/ir/cases/${caseId}/obligations`, { obligation_id: pickerId });
      setPickerId("");
      load(); onChanged?.();
      toast.success("Reporting obligation attached.");
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to attach"); }
  };

  const notifyNow = async (instanceId) => {
    try {
      const r = await api.post(`/v1/ir/cases/${caseId}/obligations/${instanceId}/notify`);
      toast.success(`Notified — sent to ${r.data.sent.length}${r.data.failed.length ? `, ${r.data.failed.length} failed` : ""}.`);
      load(); onChanged?.();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to send notification"); }
  };

  const markDone = async (instanceId) => {
    try {
      await api.put(`/v1/ir/cases/${caseId}/obligations/${instanceId}`, { status: "done" });
      load(); onChanged?.();
    } catch (e) { toast.error("Failed to update"); }
  };

  const remove = async (instanceId) => {
    if (!window.confirm("Remove this obligation from the case?")) return;
    await api.delete(`/v1/ir/cases/${caseId}/obligations/${instanceId}`);
    load(); onChanged?.();
  };

  const attachedIds = new Set(attached.map(a => a.obligation_id));
  const available = library.filter(o => !attachedIds.has(o.id));

  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md">
      <div className="px-4 py-3 border-b border-[#30363D] text-[13px] font-medium text-slate-100 flex items-center gap-1.5">
        <Megaphone size={15}/> Reporting obligations
      </div>
      {canEditCase && (
        <div className="p-3.5 border-b border-[#30363D] flex gap-2">
          <select value={pickerId} onChange={e=>setPickerId(e.target.value)}
            className="flex-1 h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200">
            <option value="">Add a reporting/notification obligation…</option>
            {available.map(o => <option key={o.id} value={o.id}>{o.name} — {o.reporting_target}</option>)}
          </select>
          <button onClick={attach} className="h-8 px-3 text-[12px] bg-blue-500/20 border border-blue-500/40 text-blue-200 rounded">Attach</button>
        </div>
      )}
      <div className="divide-y divide-[#30363D]">
        {attached.map(a => {
          const overdue = a.due_at && a.status !== "done" && new Date(a.due_at) < new Date();
          return (
            <div key={a.id} className="p-3.5">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="text-[12.5px] text-slate-200">{a.name}</div>
                  <div className="text-[11px] text-slate-500">{a.reporting_target}</div>
                  <div className="flex items-center gap-1.5 mt-1 flex-wrap">
                    <Chip color={a.status === "done" ? "green" : a.status === "notified" ? "blue" : overdue ? "red" : "slate"}>
                      {overdue ? "overdue" : a.status}
                    </Chip>
                    {a.due_at && (
                      <span className="text-[10.5px] text-slate-500 inline-flex items-center gap-1">
                        <ClockCountdown size={11}/> due {new Date(a.due_at).toLocaleString()}
                      </span>
                    )}
                    {!a.due_at && a.timeline_text && <span className="text-[10.5px] text-slate-500">{a.timeline_text}</span>}
                  </div>
                </div>
                {canEditCase && (
                  <div className="flex items-center gap-1 shrink-0">
                    {a.status !== "done" && (
                      <button onClick={()=>notifyNow(a.id)} title="Notify now" className="h-7 px-2 text-[11px] border border-[#30363D] hover:border-blue-500/50 text-slate-300 rounded inline-flex items-center gap-1">
                        <Bell size={12}/> Notify
                      </button>
                    )}
                    {a.status !== "done" && (
                      <button onClick={()=>markDone(a.id)} title="Mark done" className="h-7 px-2 text-[11px] border border-emerald-500/40 text-emerald-300 rounded">Done</button>
                    )}
                    <button onClick={()=>remove(a.id)} className="text-slate-500 hover:text-red-400"><X size={13}/></button>
                  </div>
                )}
              </div>
            </div>
          );
        })}
        {attached.length === 0 && <div className="p-4 text-center text-[11.5px] text-slate-600">No reporting obligations attached yet.</div>}
      </div>
    </div>
  );
}

const EVENT_ICON = {
  case_opened: { Icon: Flag, color: "text-blue-400" },
  case_updated: { Icon: PencilSimple, color: "text-slate-400" },
  case_closed: { Icon: Lock, color: "text-amber-400" },
  note: { Icon: Notepad, color: "text-slate-400" },
  screenshot: { Icon: Camera, color: "text-blue-400" },
  task_checked: { Icon: CheckSquare, color: "text-emerald-400" },
  task_unchecked: { Icon: Square, color: "text-slate-500" },
  evidence_added: { Icon: PackageIcon, color: "text-violet-400" },
  roles_assigned: { Icon: UsersThree, color: "text-blue-400" },
  obligation_attached: { Icon: Megaphone, color: "text-amber-400" },
  obligation_notified: { Icon: Bell, color: "text-orange-400" },
  obligation_done: { Icon: CheckSquare, color: "text-emerald-400" },
  case_reopened: { Icon: ArrowClockwise, color: "text-blue-400" },
  entity_linked: { Icon: LinkSimple, color: "text-violet-400" },
};

function VisualTimeline({ events }) {
  const sorted = [...events].sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
      <div className="text-[13px] font-medium text-slate-100 mb-3">Full incident timeline</div>
      {sorted.length === 0 ? (
        <div className="text-[12px] text-slate-600 text-center py-6">Nothing recorded yet.</div>
      ) : (
        <div className="relative pl-6">
          <div className="absolute left-[9px] top-1 bottom-1 w-px bg-[#30363D]"/>
          <div className="space-y-4">
            {sorted.map(ev => {
              const { Icon, color } = EVENT_ICON[ev.type] || { Icon: Notepad, color: "text-slate-400" };
              return (
                <div key={ev.id} className="relative flex items-start gap-3">
                  <div className={`absolute -left-6 top-0 rounded-full bg-[#0D1117] border border-[#30363D] p-1 ${color}`}>
                    <Icon size={12} weight="bold"/>
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-[11px] text-slate-500">
                      <span className="text-slate-300">{ev.author}</span> • {new Date(ev.created_at).toLocaleString()}
                    </div>
                    <div className="text-[12px] text-slate-300 whitespace-pre-wrap">{ev.text}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function ProgressBar({ progress }) {
  if (!progress) return null;
  const pct = Math.max(0, Math.min(100, progress.pct ?? 0));
  const color = pct >= 100 ? "from-emerald-500 to-emerald-400" : pct >= 60 ? "from-blue-500 to-blue-400" : pct >= 30 ? "from-amber-500 to-amber-400" : "from-red-500 to-red-400";
  const parts = [];
  if (progress.phase_tasks_total) parts.push(`${progress.phase_tasks_done}/${progress.phase_tasks_total} phase tasks`);
  if (progress.role_tasks_total) parts.push(`${progress.role_tasks_done}/${progress.role_tasks_total} role tasks`);
  if (progress.follow_ups_total) parts.push(`${progress.follow_ups_done}/${progress.follow_ups_total} follow-ups`);
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] uppercase font-mono text-slate-500">Case progress</span>
        <span className="text-[13px] font-medium text-slate-100">{pct.toFixed(1)}%</span>
      </div>
      <div className="h-2.5 bg-slate-800 rounded-full overflow-hidden">
        <div className={`h-full bg-gradient-to-r ${color} rounded-full transition-all duration-500`} style={{ width: `${pct}%` }} />
      </div>
      {parts.length > 0 && <div className="text-[10.5px] text-slate-500 mt-1.5">{parts.join(" · ")}</div>}
      {progress.follow_ups_total > 0 && progress.follow_ups_done < progress.follow_ups_total && (
        <div className="text-[10.5px] text-amber-400 mt-1">Follow-up actions still open — not fully resolved yet.</div>
      )}
    </div>
  );
}

function RoleAssignRow({ role, assigned, users, canEditCase, onAssign, onToggleTask }) {
  // Stored assignments use "contact" for the email/phone value (external contacts
  // don't have a real "email" field to key off of) -- checking assigned?.email here
  // was the bug: it was always undefined, so the dropdown could never show the
  // just-assigned user and looked like the assignment silently failed.
  const isKnownUser = assigned?.contact && users.some(u => u.email === assigned.contact) && !assigned?.external;
  const [mode, setMode] = useState(assigned?.external ? "external" : "user");
  const [extName, setExtName] = useState(assigned?.external ? assigned.name || "" : "");
  const [extContact, setExtContact] = useState(assigned?.external ? assigned.contact || "" : "");

  const pickUser = (email) => {
    if (!email) { onAssign(role.id, { name: "", contact: "", external: false }); return; }
    const u = users.find(x => x.email === email);
    onAssign(role.id, { name: u.name, contact: u.email, external: false });
  };
  const saveExternal = () => onAssign(role.id, { name: extName, contact: extContact, external: true });
  const tasks = role.tasks || [];
  const tasksDone = new Set(assigned?.tasks_done || []);
  const hasAssignment = !!assigned?.name;

  const checklist = tasks.length > 0 && hasAssignment && (
    <details className="mt-1.5" open={tasksDone.size < tasks.length}>
      <summary className="cursor-pointer text-[10.5px] text-slate-500 hover:text-slate-300 inline-flex items-center gap-1">
        <ListChecks size={11}/> Checklist ({tasksDone.size}/{tasks.length})
      </summary>
      <div className="mt-1 space-y-1 pl-1">
        {tasks.map((t, i) => {
          const done = tasksDone.has(i);
          return (
            <button key={i} disabled={!canEditCase} onClick={() => onToggleTask(role.id, i, !done)}
              className="flex items-start gap-1.5 text-[11px] text-left w-full text-slate-300 hover:text-slate-100 disabled:cursor-default">
              {done ? <CheckSquare size={13} className="text-emerald-400 shrink-0 mt-0.5"/> : <Square size={13} className="text-slate-600 shrink-0 mt-0.5"/>}
              <span className={done ? "line-through text-slate-500" : ""}>{t}</span>
            </button>
          );
        })}
      </div>
    </details>
  );

  if (!canEditCase) {
    return (
      <div className="text-[11.5px] pb-2 border-b border-[#30363D] last:border-0">
        <div className="text-slate-400">{role.name} <span className="text-slate-600">({role.kind})</span></div>
        {role.description && <div className="text-[10.5px] text-slate-600 mt-0.5">{role.description}</div>}
        <div className="text-slate-300 mt-0.5">{assigned?.name ? `${assigned.name}${assigned.external ? " (external)" : ""}` : "—"}</div>
        {checklist}
      </div>
    );
  }

  return (
    <div className="text-[11.5px] pb-2.5 border-b border-[#30363D] last:border-0">
      <div className="flex items-center justify-between">
        <div className="text-slate-400">{role.name} <span className="text-slate-600">({role.kind})</span></div>
        <button onClick={()=>setMode(mode === "user" ? "external" : "user")} className="text-blue-300 hover:text-blue-200 inline-flex items-center gap-1 text-[10.5px]">
          <UserPlus size={11}/> {mode === "user" ? "external?" : "use a user"}
        </button>
      </div>
      {role.description && <div className="text-[10.5px] text-slate-600 mt-0.5 mb-1">{role.description}</div>}
      {mode === "user" ? (
        <select value={isKnownUser ? assigned.contact : ""} onChange={e=>pickUser(e.target.value)}
          className="w-full h-7 mt-0.5 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11.5px] text-slate-200">
          <option value="">Unassigned</option>
          {users.map(u => <option key={u.id} value={u.email}>{u.name} — {u.email}</option>)}
        </select>
      ) : (
        <div className="flex gap-1 mt-0.5">
          <input value={extName} onChange={e=>setExtName(e.target.value)} onBlur={saveExternal} placeholder="Name (external)"
            className="flex-1 h-7 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11px] text-slate-200"/>
          <input value={extContact} onChange={e=>setExtContact(e.target.value)} onBlur={saveExternal} placeholder="Email/phone"
            className="flex-1 h-7 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11px] text-slate-200"/>
        </div>
      )}
      {checklist}
    </div>
  );
}

function ArtifactsPanel({ caseId, canEditCase }) {
  const [items, setItems] = useState([]);
  const [folder, setFolder] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);

  const load = useCallback(() => {
    api.get(`/v1/ir/cases/${caseId}/artifacts`).then(r => setItems(r.data.items)).catch(() => setItems([]));
  }, [caseId]);
  useEffect(() => { load(); }, [load]);

  const upload = async (files) => {
    const arr = Array.from(files || []);
    if (arr.length === 0) return;
    const form = new FormData();
    arr.forEach(f => form.append("files", f));
    if (folder.trim()) form.append("folder", folder.trim());
    setUploading(true);
    try {
      await api.post(`/v1/ir/cases/${caseId}/artifacts`, form, { headers: { "Content-Type": "multipart/form-data" } });
      toast.success(`${arr.length} file${arr.length===1?"":"s"} attached.`);
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Upload failed"); } finally { setUploading(false); }
  };

  const onDrop = (e) => { e.preventDefault(); e.stopPropagation(); setDragOver(false); upload(e.dataTransfer.files); };

  const download = (a) => {
    const token = localStorage.getItem("vulnops_token");
    fetch(`${API}/v1/ir/cases/${caseId}/artifacts/${a.id}/download`, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
      .then(r => r.blob()).then(blob => {
        const url = URL.createObjectURL(blob);
        const el = document.createElement("a");
        el.href = url; el.download = a.filename; document.body.appendChild(el); el.click(); el.remove();
        URL.revokeObjectURL(url);
      }).catch(() => toast.error("Download failed"));
  };

  const remove = async (id) => {
    if (!window.confirm("Delete this artifact?")) return;
    await api.delete(`/v1/ir/cases/${caseId}/artifacts/${id}`);
    load();
  };

  const grouped = items.reduce((acc, a) => { const k = a.folder || ""; (acc[k] = acc[k] || []).push(a); return acc; }, {});
  const fmtSize = (n) => n < 1024*1024 ? `${(n/1024).toFixed(1)} KB` : `${(n/1024/1024).toFixed(1)} MB`;

  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md">
      <div className="px-4 py-3 border-b border-[#30363D] text-[13px] font-medium text-slate-100 flex items-center gap-1.5">
        <FolderSimple size={15}/> Artifacts <span className="text-slate-500 font-normal">({items.length})</span>
      </div>
      {canEditCase && (
        <div className="p-3.5 border-b border-[#30363D] space-y-2">
          <div
            onDragOver={(e)=>{e.preventDefault(); setDragOver(true);}}
            onDragLeave={()=>setDragOver(false)}
            onDrop={onDrop}
            className={`rounded border-2 border-dashed p-3 text-center transition-colors ${dragOver ? "border-blue-500/60 bg-blue-500/5" : "border-[#30363D]"}`}>
            <div className="text-[11.5px] text-slate-500">Drag &amp; drop any files here (txt, csv, xlsx, docx, pdf, etc.)</div>
          </div>
          <div className="flex items-center gap-2">
            <input value={folder} onChange={e=>setFolder(e.target.value)} placeholder="Optional folder/group name (for multi-file batches)"
              className="flex-1 h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200"/>
            <label className={`h-8 px-3 text-[12px] border border-[#30363D] hover:border-blue-500/50 text-slate-300 rounded inline-flex items-center gap-1.5 cursor-pointer ${uploading ? "opacity-50 pointer-events-none" : ""}`}>
              <UploadSimple size={13}/> {uploading ? "Uploading…" : "Upload"}
              <input type="file" multiple className="hidden" onChange={e=>upload(e.target.files)}/>
            </label>
          </div>
        </div>
      )}
      <div className="divide-y divide-[#30363D]">
        {Object.entries(grouped).map(([folderName, files]) => (
          <div key={folderName || "_none"} className="p-3.5">
            {folderName && <div className="text-[10.5px] uppercase font-mono text-slate-500 mb-1.5 flex items-center gap-1"><FolderSimple size={11}/> {folderName}</div>}
            <div className="space-y-1.5">
              {files.map(a => (
                <div key={a.id} className="flex items-center justify-between gap-2 text-[12px]">
                  <button onClick={()=>download(a)} className="text-blue-300 hover:underline truncate text-left">{a.filename}</button>
                  <div className="flex items-center gap-2 shrink-0 text-slate-500">
                    <span className="text-[10.5px]">{fmtSize(a.size)}</span>
                    <span className="text-[10.5px]">{a.uploaded_by}</span>
                    {canEditCase && <button onClick={()=>remove(a.id)} className="hover:text-red-400"><Trash size={12}/></button>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
        {items.length === 0 && <div className="p-4 text-center text-[11.5px] text-slate-600">No artifacts attached yet.</div>}
      </div>
    </div>
  );
}

const ENTITY_TYPE_META = {
  asset: { label: "Asset", Icon: DesktopTower },
  server: { label: "Server", Icon: DesktopTower },
  website: { label: "Website", Icon: Globe },
  user: { label: "User", Icon: UserIcon },
  external_vendor: { label: "External vendor", Icon: Handshake },
  other: { label: "Other", Icon: LinkSimple },
};

function RelatedEntitiesPanel({ caseId, canEditCase }) {
  const [items, setItems] = useState([]);
  const [assetsLite, setAssetsLite] = useState([]);
  const [form, setForm] = useState({ type: "asset", name: "", asset_id: "", notes: "" });

  const load = useCallback(() => {
    api.get(`/v1/ir/cases/${caseId}/entities`).then(r => setItems(r.data.items)).catch(() => setItems([]));
  }, [caseId]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { api.get("/v1/ir/assets-lite").then(r => setAssetsLite(r.data.items)).catch(() => setAssetsLite([])); }, []);

  const add = async () => {
    if (!form.name.trim()) { toast.error("Name/identifier required"); return; }
    try {
      await api.post(`/v1/ir/cases/${caseId}/entities`, { type: form.type, name: form.name.trim(), asset_id: form.asset_id || null, notes: form.notes.trim() });
      setForm({ type: form.type, name: "", asset_id: "", notes: "" });
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to link"); }
  };

  const remove = async (id) => {
    await api.delete(`/v1/ir/cases/${caseId}/entities/${id}`);
    load();
  };

  const pickAsset = (assetId) => {
    const a = assetsLite.find(x => x.id === assetId);
    setForm({ ...form, asset_id: assetId, name: a ? (a.hostname || a.ip_address || assetId) : "" });
  };

  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
      <div className="text-[11px] uppercase font-mono text-slate-500 mb-2 flex items-center gap-1.5"><LinkSimple size={13}/> Related assets / entities</div>
      {canEditCase && (
        <div className="space-y-1.5 mb-3 pb-3 border-b border-[#30363D]">
          <select value={form.type} onChange={e=>setForm({...form, type: e.target.value, asset_id: "", name: ""})}
            className="w-full h-7 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11.5px] text-slate-200">
            {Object.entries(ENTITY_TYPE_META).map(([k,v]) => <option key={k} value={k}>{v.label}</option>)}
          </select>
          {form.type === "asset" ? (
            <select value={form.asset_id} onChange={e=>pickAsset(e.target.value)}
              className="w-full h-7 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11.5px] text-slate-200">
              <option value="">Pick an asset…</option>
              {assetsLite.map(a => <option key={a.id} value={a.id}>{a.hostname || a.ip_address || a.id}{a.criticality ? ` (${a.criticality})` : ""}</option>)}
            </select>
          ) : (
            <input value={form.name} onChange={e=>setForm({...form, name: e.target.value})} placeholder="Name / identifier"
              className="w-full h-7 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11.5px] text-slate-200"/>
          )}
          <input value={form.notes} onChange={e=>setForm({...form, notes: e.target.value})} placeholder="Notes (optional)"
            className="w-full h-7 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11.5px] text-slate-200"/>
          <button onClick={add} className="w-full h-7 text-[11.5px] bg-blue-500/20 border border-blue-500/40 text-blue-200 rounded">Link</button>
        </div>
      )}
      <div className="space-y-2">
        {items.map(it => {
          const meta = ENTITY_TYPE_META[it.type] || ENTITY_TYPE_META.other;
          const Icon = meta.Icon;
          return (
            <div key={it.id} className="flex items-start justify-between gap-2 text-[11.5px]">
              <div className="min-w-0 flex items-start gap-1.5">
                <Icon size={13} className="text-slate-500 shrink-0 mt-0.5"/>
                <div className="min-w-0">
                  <div className="text-slate-200 truncate">{it.name} <span className="text-slate-600">({meta.label})</span></div>
                  {it.notes && <div className="text-[10.5px] text-slate-500">{it.notes}</div>}
                </div>
              </div>
              {canEditCase && <button onClick={()=>remove(it.id)} className="text-slate-500 hover:text-red-400 shrink-0"><X size={12}/></button>}
            </div>
          );
        })}
        {items.length === 0 && <div className="text-[11.5px] text-slate-600">Nothing linked yet.</div>}
      </div>
    </div>
  );
}

function FollowUpsPanel({ caseId, followUps, canEditCase, onChanged }) {
  const [text, setText] = useState("");

  const add = async () => {
    if (!text.trim()) return;
    try { await api.post(`/v1/ir/cases/${caseId}/follow-ups`, { text: text.trim() }); setText(""); onChanged(); }
    catch (e) { toast.error("Failed to add"); }
  };
  const toggle = async (id, done) => {
    try { await api.put(`/v1/ir/cases/${caseId}/follow-ups/${id}`, { done }); onChanged(); }
    catch (e) { toast.error("Failed to update"); }
  };
  const remove = async (id) => {
    try { await api.delete(`/v1/ir/cases/${caseId}/follow-ups/${id}`); onChanged(); }
    catch (e) { toast.error("Failed to remove"); }
  };

  const items = followUps || [];
  const openCount = items.filter(a => !a.done).length;

  return (
    <div>
      <div className="text-[10.5px] uppercase text-slate-500 flex items-center justify-between">
        <span>Follow-up actions</span>
        {items.length > 0 && <span className={openCount > 0 ? "text-amber-400" : "text-emerald-400"}>{items.length - openCount}/{items.length} done</span>}
      </div>
      <div className="mt-1 space-y-1">
        {items.map(a => (
          <div key={a.id} className="flex items-center justify-between gap-1.5 group">
            <button disabled={!canEditCase} onClick={()=>toggle(a.id, !a.done)} className="flex items-start gap-1.5 text-[11.5px] text-left flex-1 min-w-0 disabled:cursor-default">
              {a.done ? <CheckSquare size={13} className="text-emerald-400 shrink-0 mt-0.5"/> : <Square size={13} className="text-slate-600 shrink-0 mt-0.5"/>}
              <span className={a.done ? "line-through text-slate-500" : "text-slate-300"}>{a.text}</span>
            </button>
            {canEditCase && <button onClick={()=>remove(a.id)} className="text-slate-600 hover:text-red-400 opacity-0 group-hover:opacity-100 shrink-0"><X size={11}/></button>}
          </div>
        ))}
        {items.length === 0 && <div className="text-[11.5px] text-slate-600">None recorded.</div>}
      </div>
      {canEditCase && (
        <div className="flex gap-1 mt-1.5">
          <input value={text} onChange={e=>setText(e.target.value)} onKeyDown={e=>{if(e.key==="Enter"){e.preventDefault(); add();}}} placeholder="Add a follow-up action…"
            className="flex-1 h-7 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11px] text-slate-200"/>
          <button onClick={add} className="h-7 px-2 text-[11px] bg-blue-500/20 border border-blue-500/40 text-blue-200 rounded">Add</button>
        </div>
      )}
    </div>
  );
}

function RiskRegisterPanel({ caseId, caseNumber, caseTitle, caseClassification }) {
  const [linkedRisks, setLinkedRisks] = useState([]);
  const [showRiskModal, setShowRiskModal] = useState(false);

  const load = useCallback(() => {
    api.get("/v1/risk-register", { params: { ir_case_id: caseId } }).then(r => setLinkedRisks(r.data)).catch(() => setLinkedRisks([]));
  }, [caseId]);
  useEffect(() => { load(); }, [load]);

  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
      <div className="flex items-center justify-between mb-2">
        <div className="text-[11px] uppercase font-mono text-slate-500 flex items-center gap-1.5"><Flag size={13}/> Risk Register</div>
        <button onClick={() => setShowRiskModal(true)} className="text-[11px] text-blue-300 hover:text-blue-200 inline-flex items-center gap-1">
          <LinkSimple size={11}/> Add to Risk Register
        </button>
      </div>
      <div className="space-y-1.5">
        {linkedRisks.map(r => (
          <Link key={r.id} to={`/risk-register/${r.id}`} className="flex items-center justify-between border border-[#30363D] rounded px-2.5 py-1.5 hover:border-[#484F58]">
            <span className="text-[12px] text-slate-200 truncate flex-1">{r.title}</span>
            <Chip color="slate">{r.status}</Chip>
          </Link>
        ))}
        {linkedRisks.length === 0 && <div className="text-[12px] text-slate-500">Not tracked in the Risk Register yet.</div>}
      </div>
      {showRiskModal && (
        <NewRiskModal onClose={() => setShowRiskModal(false)}
          prefill={{
            title: `${caseNumber}: ${caseTitle}`,
            description: `Risk tracked from IR case ${caseNumber}.`,
            category: "Operational",
            likelihood: caseClassification === "Severe" || caseClassification === "Critical" ? 4 : 3,
            impact: caseClassification === "Severe" || caseClassification === "Critical" ? 4 : 3,
            linked_ir_case_ids: [caseId],
            tags: ["ir-case"],
            contextLabel: `From IR case ${caseNumber} — ${caseTitle}`,
          }}
          onCreated={() => {
            setShowRiskModal(false);
            toast.success("Linked to Risk Register");
            load();
          }}
        />
      )}
    </div>
  );
}

export function IRCaseDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { canEdit } = useAuth();
  const canEditCase = canEdit("/ir/cases");
  const canApprove = canEdit("/ir/case-approval");
  const [data, setData] = useState(null);
  const [report, setReport] = useState(null);
  const [users, setUsers] = useState([]);
  const [noteText, setNoteText] = useState("");
  const [noteAttachments, setNoteAttachments] = useState([]);
  const [dragOver, setDragOver] = useState(false);
  const [evidenceForm, setEvidenceForm] = useState({ description: "", location: "" });

  const load = useCallback(() => {
    api.get(`/v1/ir/cases/${id}`).then(r => setData(r.data)).catch(() => setData(false));
    api.get(`/v1/ir/cases/${id}/report`).then(r => setReport(r.data)).catch(() => setReport(null));
  }, [id]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { api.get("/v1/ir/users-lite").then(r => setUsers(r.data.items)).catch(() => setUsers([])); }, []);

  // Auto-refresh so simultaneous responders see each other's updates without a
  // realtime backend -- matches the rest of the app's collaboration model.
  useEffect(() => {
    const t = setInterval(load, 8000);
    return () => clearInterval(t);
  }, [load]);

  const handleFiles = async (files) => {
    const arr = Array.from(files || []);
    const out = [...noteAttachments];
    for (const file of arr) {
      if (!file.type.startsWith("image/") && file.type !== "application/pdf") { toast.error(`${file.name}: only images/PDFs allowed`); continue; }
      if (file.size > 1_000_000) { toast.error(`${file.name} > 1MB — skipped`); continue; }
      const reader = new FileReader();
      const data_url = await new Promise((res) => { reader.onload = () => res(reader.result); reader.readAsDataURL(file); });
      out.push({ name: file.name, mime: file.type, data_url });
    }
    setNoteAttachments(out);
  };

  const onDrop = (e) => {
    e.preventDefault(); e.stopPropagation(); setDragOver(false);
    handleFiles(e.dataTransfer.files);
  };

  const addNote = async () => {
    if (!noteText.trim() && noteAttachments.length === 0) return;
    try {
      await api.post(`/v1/ir/cases/${id}/events`, { type: noteAttachments.length ? "screenshot" : "note", text: noteText, attachments: noteAttachments });
      setNoteText(""); setNoteAttachments([]);
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to add note"); }
  };

  const setClassification = async (classification) => {
    try { await api.patch(`/v1/ir/cases/${id}`, { classification }); load(); }
    catch (e) { toast.error("Failed to update classification"); }
  };

  const assignRole = async (roleId, assignment) => {
    const next = { ...(data.case.assigned_roles || {}), [roleId]: assignment };
    try { await api.put(`/v1/ir/cases/${id}/roles`, { assigned_roles: next }); load(); }
    catch (e) { toast.error("Failed to assign role"); }
  };

  const toggleRoleTask = async (roleId, taskIndex, done) => {
    try { await api.put(`/v1/ir/cases/${id}/roles/${roleId}/tasks`, { task_index: taskIndex, done }); load(); }
    catch (e) { toast.error("Failed to update task"); }
  };

  const reopenCase = async () => {
    if (!window.confirm("Reopen this case? Status will go back to open.")) return;
    try { await api.post(`/v1/ir/cases/${id}/reopen`); load(); toast.success("Case reopened."); }
    catch (e) { toast.error(e.response?.data?.detail || "Failed to reopen"); }
  };

  const addEvidence = async () => {
    if (!evidenceForm.description.trim()) { toast.error("Description required"); return; }
    try {
      await api.post(`/v1/ir/cases/${id}/evidence`, evidenceForm);
      setEvidenceForm({ description: "", location: "" });
      load();
    } catch (e) { toast.error("Failed to log evidence"); }
  };

  const closeCase = async () => {
    if (!window.confirm("Close this case and generate the closure report draft?")) return;
    try { const r = await api.post(`/v1/ir/cases/${id}/close`); setReport(r.data); load(); toast.success("Case closed. Report drafted for review."); }
    catch (e) { toast.error(e.response?.data?.detail || "Failed to close case"); }
  };

  const saveReport = async (fields) => {
    try { const r = await api.put(`/v1/ir/cases/${id}/report`, fields); setReport(r.data); toast.success("Report saved."); }
    catch (e) { toast.error(e.response?.data?.detail || "Failed to save report"); }
  };

  const approveReport = async () => {
    if (!window.confirm("Approve this report? It will be locked from further edits.")) return;
    try { const r = await api.post(`/v1/ir/cases/${id}/report/approve`); setReport(r.data); toast.success("Report approved and archived."); }
    catch (e) { toast.error(e.response?.data?.detail || "Failed to approve"); }
  };

  const exportDocx = () => {
    const token = localStorage.getItem("vulnops_token");
    fetch(`${API}/v1/ir/cases/${id}/export.docx`, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
      .then(r => r.blob())
      .then(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = `${data.case.case_number}.docx`;
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(url);
      })
      .catch(() => toast.error("Failed to export"));
  };

  const exportRiskDocx = () => {
    const token = localStorage.getItem("vulnops_token");
    fetch(`${API}/v1/ir/cases/${id}/risk-export.docx`, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
      .then(r => r.blob())
      .then(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = `${data.case.case_number}-risk-report.docx`;
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(url);
      })
      .catch(() => toast.error("Failed to export"));
  };

  if (data === false) return <Layout title="IR Case"><div className="text-slate-500 text-center py-10">Not found.</div></Layout>;
  if (!data) return <Layout title="IR Case"><div className="text-slate-500 text-center py-10">Loading…</div></Layout>;

  const { case: c, phase_progress, events, evidence, roles } = data;

  return (
    <Layout title={c.title} subtitle={`${c.case_number} — opened ${new Date(c.opened_at).toLocaleString()}`}
      actions={
        <div className="flex items-center gap-2">
          <button onClick={exportDocx} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300">
            <DownloadSimple size={14}/> Export Word doc
          </button>
          <button onClick={exportRiskDocx} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 rounded inline-flex items-center gap-1.5 text-slate-300">
            <FileArrowDown size={14}/> Export Risk Register report
          </button>
          <button onClick={()=>navigate("/ir/cases")} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300"><ArrowLeft size={14}/> Back</button>
        </div>
      }>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-4">

          {/* Timeline / activity feed */}
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md">
            <div className="px-4 py-3 border-b border-[#30363D] text-[13px] font-medium text-slate-100">Timeline &amp; activity</div>
            {canEditCase && c.status === "open" && (
              <div className="p-3.5 border-b border-[#30363D] space-y-2">
                <div
                  onDragOver={(e)=>{e.preventDefault(); setDragOver(true);}}
                  onDragLeave={()=>setDragOver(false)}
                  onDrop={onDrop}
                  className={`rounded border-2 border-dashed transition-colors ${dragOver ? "border-blue-500/60 bg-blue-500/5" : "border-transparent"}`}>
                  <textarea value={noteText} onChange={e=>setNoteText(e.target.value)} rows={2} placeholder="Add a note, action taken, or update… (drag & drop screenshots anywhere here)"
                    className="w-full bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200"/>
                </div>
                {noteAttachments.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {noteAttachments.map((a, i) => (
                      <div key={i} className="flex items-center gap-1 bg-slate-800/40 border border-[#30363D] rounded px-1.5 py-1">
                        {a.mime?.startsWith("image/") && <img src={a.data_url} alt="" className="h-5 w-5 object-cover rounded"/>}
                        <span className="text-[10.5px] text-slate-400">{a.name}</span>
                        <button onClick={()=>setNoteAttachments(noteAttachments.filter((_,idx)=>idx!==i))}><X size={11} className="text-slate-500"/></button>
                      </div>
                    ))}
                  </div>
                )}
                <div className="flex items-center justify-between">
                  <label className="text-[11.5px] text-blue-300 hover:underline cursor-pointer inline-flex items-center gap-1">
                    <Camera size={13}/> Attach screenshot/PDF (or drag &amp; drop above)
                    <input type="file" accept="image/*,application/pdf" multiple className="hidden" onChange={e=>handleFiles(e.target.files)}/>
                  </label>
                  <button onClick={addNote} className="h-7 px-3 text-[11.5px] bg-blue-500/20 border border-blue-500/40 text-blue-200 rounded">Post</button>
                </div>
              </div>
            )}
            <div className="divide-y divide-[#30363D] max-h-[520px] overflow-y-auto">
              {events.map(ev => (
                <div key={ev.id} className="p-3.5">
                  <div className="flex items-center gap-2 text-[11px] text-slate-500 mb-1">
                    <Notepad size={12}/> {ev.author} • {new Date(ev.created_at).toLocaleString()} • <span className="uppercase font-mono">{ev.type.replace("_"," ")}</span>
                  </div>
                  <div className="text-[12.5px] text-slate-200 whitespace-pre-wrap">{ev.text}</div>
                  {(ev.attachments||[]).length > 0 && (
                    <div className="flex flex-wrap gap-2 mt-2">
                      {ev.attachments.map((a,i) => a.mime?.startsWith("image/") ? (
                        <a key={i} href={a.data_url} target="_blank" rel="noopener noreferrer">
                          <img src={a.data_url} alt={a.name} className="max-h-28 rounded border border-[#30363D] hover:border-blue-500/50"/>
                        </a>
                      ) : (
                        <a key={i} href={a.data_url} download={a.name} className="text-[11.5px] text-blue-300 hover:underline">📎 {a.name}</a>
                      ))}
                    </div>
                  )}
                </div>
              ))}
              {events.length === 0 && <div className="p-6 text-center text-[12px] text-slate-600">No activity yet.</div>}
            </div>
          </div>

          {/* Evidence manifest -- moved here, right below Timeline & Activity */}
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md">
            <div className="px-4 py-3 border-b border-[#30363D] text-[13px] font-medium text-slate-100 flex items-center gap-1.5"><PackageIcon size={15}/> Evidence manifest</div>
            {canEditCase && c.status === "open" && (
              <div className="p-3.5 border-b border-[#30363D] grid grid-cols-1 md:grid-cols-[1fr_1fr_auto] gap-2">
                <input value={evidenceForm.description} onChange={e=>setEvidenceForm({...evidenceForm, description:e.target.value})} placeholder="Item description"
                  className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200"/>
                <input value={evidenceForm.location} onChange={e=>setEvidenceForm({...evidenceForm, location:e.target.value})} placeholder="Storage location"
                  className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200"/>
                <button onClick={addEvidence} className="h-8 px-3 text-[12px] bg-blue-500/20 border border-blue-500/40 text-blue-200 rounded">Log item</button>
              </div>
            )}
            <div className="divide-y divide-[#30363D]">
              {evidence.map(ev => (
                <div key={ev.id} className="p-3 flex items-center justify-between text-[12px]">
                  <div><span className="text-slate-500 font-mono mr-2">#{String(ev.item_no).padStart(3,"0")}</span><span className="text-slate-200">{ev.description}</span></div>
                  <div className="text-slate-500">{ev.location}</div>
                </div>
              ))}
              {evidence.length === 0 && <div className="p-4 text-center text-[11.5px] text-slate-600">No evidence logged yet.</div>}
            </div>
          </div>

          <ObligationsPanel caseId={id} canEditCase={canEditCase && c.status === "open"} onChanged={load}/>

          <PhaseChecklist caseId={id} phases={phase_progress} canEditCase={canEditCase && c.status === "open"} onChanged={load}/>

          <ArtifactsPanel caseId={id} canEditCase={canEditCase}/>

          <RelatedEntitiesPanel caseId={id} canEditCase={canEditCase}/>

          <RiskRegisterPanel caseId={id} caseNumber={c.case_number} caseTitle={c.title} caseClassification={c.classification}/>
        </div>

        <div className="space-y-4">
          <ProgressBar progress={data.progress}/>

          {/* Case info */}
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] uppercase font-mono text-slate-500">Classification</span>
              <select disabled={!canEditCase} value={c.classification} onChange={e=>setClassification(e.target.value)}
                className="h-7 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11.5px] text-slate-200">
                {CLASSIFICATION_LEVELS.map(l => <option key={l} value={l}>{l}</option>)}
              </select>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[11px] uppercase font-mono text-slate-500">Status</span>
              <Chip color={c.status === "open" ? "green" : "slate"}>{c.status}</Chip>
            </div>
            {c.outcome_category && (
              <div className="flex items-center justify-between">
                <span className="text-[11px] uppercase font-mono text-slate-500">Wizard confidence</span>
                <span className="text-[11.5px] text-slate-300">{c.confidence_pct}%</span>
              </div>
            )}
            {c.reporter_contact && (
              <div className="text-[11.5px] text-slate-400">Reported by: {c.reporter_contact}</div>
            )}
            {c.initial_intake && (
              <div className="pt-2 border-t border-[#30363D]">
                <div className="text-[11px] uppercase font-mono text-slate-500 mb-1">Initial intake</div>
                <div className="text-[12px] text-slate-300 whitespace-pre-wrap max-h-40 overflow-y-auto">{c.initial_intake}</div>
              </div>
            )}
            {c.recommended_actions?.length > 0 && (
              <div className="pt-2 border-t border-[#30363D]">
                <div className="text-[11px] uppercase font-mono text-slate-500 mb-1">Recommended actions</div>
                <ul className="space-y-1">
                  {c.recommended_actions.map((a,i) => <li key={i} className="text-[11.5px] text-slate-300">• {a}</li>)}
                </ul>
              </div>
            )}
          </div>

          {/* Roles */}
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="text-[11px] uppercase font-mono text-slate-500 mb-2 flex items-center gap-1.5"><UsersThree size={13}/> Assigned roles</div>
            <div className="space-y-2.5">
              {roles.map(r => (
                <RoleAssignRow key={r.id} role={r} assigned={(c.assigned_roles || {})[r.id]} users={users}
                  canEditCase={canEditCase} onAssign={assignRole} onToggleTask={toggleRoleTask}/>
              ))}
            </div>
          </div>

          {/* Closure / report */}
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="text-[11px] uppercase font-mono text-slate-500 mb-2 flex items-center gap-1.5"><FileArrowDown size={13}/> Closure &amp; report</div>
            {c.status === "open" && canEditCase && (
              <button onClick={closeCase} className="w-full h-8 text-[12px] bg-amber-500/15 border border-amber-500/40 text-amber-300 rounded mb-2">Close case</button>
            )}
            {c.status === "closed" && canEditCase && (
              <button onClick={reopenCase} className="w-full h-8 text-[12px] border border-[#30363D] hover:border-blue-500/50 text-slate-300 rounded mb-2 inline-flex items-center justify-center gap-1.5">
                <ArrowClockwise size={13}/> Reopen case
              </button>
            )}
            {report ? (
              <div className="space-y-2">
                <Chip color={report.status === "approved" ? "green" : "amber"}>{report.status}</Chip>
                {report.status === "approved" && !data.progress?.fully_resolved && (
                  <div className="border border-amber-500/40 bg-amber-900/20 rounded-md p-2.5 flex items-start gap-2">
                    <Warning size={15} className="text-amber-400 shrink-0 mt-0.5"/>
                    <div className="text-[11px] text-amber-300/90">Approved, but not truly closed yet — open follow-up actions below still need to be completed.</div>
                  </div>
                )}
                <div>
                  <div className="text-[10.5px] uppercase text-slate-500">Root cause</div>
                  {report.status === "draft" && canEditCase ? (
                    <textarea defaultValue={report.root_cause || ""} rows={2} onBlur={e=>saveReport({root_cause: e.target.value})}
                      className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1 text-[11.5px] text-slate-200"/>
                  ) : <div className="text-[11.5px] text-slate-300 mt-0.5">{report.root_cause || "—"}</div>}
                </div>
                <FollowUpsPanel caseId={id} followUps={c.follow_up_actions} canEditCase={canEditCase} onChanged={load}/>
                {report.status === "draft" && canApprove && (
                  <button onClick={approveReport} className="w-full h-8 text-[12px] bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 rounded inline-flex items-center justify-center gap-1.5">
                    <Lock size={13}/> Approve &amp; archive
                  </button>
                )}
                {report.status === "draft" && !canApprove && (
                  <div className="text-[10.5px] text-slate-500 text-center">Only security admins can approve case closure.</div>
                )}
                {report.status === "approved" && (
                  <div className="text-[11px] text-slate-500">Approved by {report.approved_by} on {new Date(report.approved_at).toLocaleString()}</div>
                )}
              </div>
            ) : (
              <div className="text-[11.5px] text-slate-600">Close the case to generate the closure report draft.</div>
            )}
          </div>
        </div>
      </div>

      <div className="mt-4">
        <VisualTimeline events={events}/>
      </div>
    </Layout>
  );
}
