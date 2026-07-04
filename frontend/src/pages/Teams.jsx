import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { toast } from "sonner";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { useAuth } from "@/lib/auth";
import { Plus, Trash, PencilSimple, Users, X, Check } from "@phosphor-icons/react";

const PRESET_COLORS = ["#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899", "#64748b", "#06b6d4"];

export default function Teams() {
  const { user, canEdit } = useAuth();
  const canEditTeams = canEdit("/admin/teams");
  const [teams, setTeams] = useState([]);
  const [users, setUsers] = useState([]);
  const [showCreate, setShowCreate] = useState(false);
  const [newTeam, setNewTeam] = useState({ name: "", color: PRESET_COLORS[0], description: "", members: [] });
  const [editingId, setEditingId] = useState(null);
  const [editForm, setEditForm] = useState({ name: "", color: "", members: [] });

  const load = async () => {
    try {
      const [t, u] = await Promise.all([
        api.get("/v1/admin/teams"),
        api.get("/v1/admin/users"),
      ]);
      setTeams(t.data.items || []);
      setUsers(u.data.items || []);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to load teams");
    }
  };
  useEffect(() => { load(); }, []);

  const createTeam = async () => {
    if (!newTeam.name.trim()) { toast.error("Name required"); return; }
    try {
      await api.post("/v1/admin/teams", newTeam);
      toast.success(`Team '${newTeam.name}' created`);
      setShowCreate(false);
      setNewTeam({ name: "", color: PRESET_COLORS[0], description: "", members: [] });
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Create failed");
    }
  };

  const startEdit = (t) => {
    setEditingId(t.id);
    setEditForm({ name: t.name, color: t.color || PRESET_COLORS[0], members: t.members || [] });
  };

  const saveEdit = async (id) => {
    try {
      await api.patch(`/v1/admin/teams/${id}`, editForm);
      toast.success("Saved");
      setEditingId(null);
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Save failed");
    }
  };

  const deleteTeam = async (t) => {
    if (!window.confirm(`Delete team "${t.name}"? Members will be detached but their assigned findings remain.`)) return;
    try {
      await api.delete(`/v1/admin/teams/${t.id}`);
      toast.success("Deleted");
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Delete failed");
    }
  };

  const toggleMember = (form, setForm, userId) => {
    const set = new Set(form.members || []);
    if (set.has(userId)) set.delete(userId); else set.add(userId);
    setForm({ ...form, members: [...set] });
  };

  return (
    <Layout title="Teams" subtitle="Create teams, attach users — only members see their team's findings"
      actions={
        canEditTeams && (
          <button data-testid="teams-new"
            onClick={() => setShowCreate(true)}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
            <Plus size={14}/> New Team
          </button>
        )
      }>

      {showCreate && (
        <div data-testid="teams-create-form" className="border border-blue-500/30 bg-blue-500/5 rounded-md p-4 mb-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="block text-[10px] uppercase font-mono text-slate-500 mb-1">Name</label>
              <input data-testid="new-team-name" value={newTeam.name} onChange={(e)=>setNewTeam({...newTeam, name: e.target.value})}
                placeholder="e.g. NetSec, AppSec, Cloud Ops"
                className="w-full h-8 bg-[#161B22] border border-[#30363D] rounded px-2.5 text-[12.5px] text-slate-100"/>
            </div>
            <div>
              <label className="block text-[10px] uppercase font-mono text-slate-500 mb-1">Color</label>
              <div className="flex gap-1.5">
                {PRESET_COLORS.map(c => (
                  <button key={c} onClick={()=>setNewTeam({...newTeam, color: c})}
                    className={`w-6 h-6 rounded-full border-2 ${newTeam.color === c ? "border-white" : "border-transparent"}`}
                    style={{ background: c }}/>
                ))}
              </div>
            </div>
            <div className="md:col-span-2">
              <label className="block text-[10px] uppercase font-mono text-slate-500 mb-1">Description</label>
              <input value={newTeam.description} onChange={(e)=>setNewTeam({...newTeam, description: e.target.value})}
                placeholder="What this team owns…"
                className="w-full h-8 bg-[#161B22] border border-[#30363D] rounded px-2.5 text-[12.5px] text-slate-100"/>
            </div>
            <div className="md:col-span-2">
              <label className="block text-[10px] uppercase font-mono text-slate-500 mb-1">Members ({newTeam.members.length} selected)</label>
              <div className="border border-[#30363D] rounded-md bg-[#0D1117] max-h-[200px] overflow-y-auto">
                {users.map(u => (
                  <label key={u.id} className="flex items-center gap-2 px-3 py-1.5 hover:bg-slate-800/30 cursor-pointer text-[12px]">
                    <input type="checkbox" checked={newTeam.members.includes(u.id)} onChange={()=>toggleMember(newTeam, setNewTeam, u.id)}/>
                    <span className="text-slate-200 flex-1">{u.name || u.email}</span>
                    <span className="text-slate-500 text-[11px]">{u.email}</span>
                    <Chip color={u.role === "admin" ? "red" : u.role === "manager" ? "orange" : "slate"}>{u.role}</Chip>
                    {u.team && <span className="text-[10.5px] text-amber-300 font-mono">currently: {u.team}</span>}
                  </label>
                ))}
              </div>
            </div>
          </div>
          <div className="mt-3 flex gap-2">
            <button data-testid="new-team-create" onClick={createTeam}
              className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
              <Check size={14}/> Create
            </button>
            <button onClick={()=>setShowCreate(false)} className="h-8 px-3 text-[12px] border border-[#30363D] text-slate-300 rounded">Cancel</button>
          </div>
        </div>
      )}

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table className="dense w-full">
          <thead>
            <tr>
              <th className="text-left">Team</th>
              <th className="text-left">Description</th>
              <th className="text-left">Members</th>
              <th className="text-left w-[140px]">Actions</th>
            </tr>
          </thead>
          <tbody>
            {teams.map(t => (
              <tr key={t.id || t.name} data-testid={`team-row-${t.name}`} className="border-t border-[#30363D]">
                {editingId && editingId === t.id ? (
                  <>
                    <td className="py-2">
                      <div className="flex items-center gap-2">
                        <input value={editForm.color} onChange={(e)=>setEditForm({...editForm, color: e.target.value})}
                          type="color" className="w-6 h-6 bg-transparent"/>
                        <input value={editForm.name} onChange={(e)=>setEditForm({...editForm, name: e.target.value})}
                          className="h-7 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-100"/>
                      </div>
                    </td>
                    <td colSpan={2}>
                      <details className="text-[12px]" data-testid={`team-edit-members-${t.name}`}>
                        <summary className="cursor-pointer text-blue-300">Edit members ({editForm.members.length})</summary>
                        <div className="mt-2 max-h-[200px] overflow-y-auto border border-[#30363D] rounded bg-[#0a0d12]">
                          {users.map(u => (
                            <label key={u.id} className="flex items-center gap-2 px-2 py-1 hover:bg-slate-800/30 cursor-pointer text-[12px]">
                              <input type="checkbox" checked={editForm.members.includes(u.id)} onChange={()=>toggleMember(editForm, setEditForm, u.id)}/>
                              <span className="text-slate-200 flex-1">{u.name || u.email}</span>
                              <Chip color={u.role === "admin" ? "red" : "slate"}>{u.role}</Chip>
                            </label>
                          ))}
                        </div>
                      </details>
                    </td>
                    <td>
                      <div className="flex gap-1">
                        <button data-testid={`team-save-${t.name}`} onClick={()=>saveEdit(t.id)} className="h-7 px-2 text-[11.5px] bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 rounded inline-flex items-center gap-1"><Check size={12}/> Save</button>
                        <button onClick={()=>setEditingId(null)} className="h-7 px-2 text-[11.5px] text-slate-400 hover:text-slate-200"><X size={12}/></button>
                      </div>
                    </td>
                  </>
                ) : (
                  <>
                    <td>
                      <div className="flex items-center gap-2">
                        <span className="w-2.5 h-2.5 rounded-full" style={{ background: t.color || "#64748b" }}/>
                        <span className="text-[13px] text-slate-100 font-medium">{t.name}</span>
                        {t.implicit && <Chip color="amber">Implicit (used but not formally defined)</Chip>}
                      </div>
                    </td>
                    <td className="text-slate-400 text-[12px]">{t.description || "—"}</td>
                    <td>
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <Users size={12} className="text-slate-500"/>
                        <span className="text-[12px] text-slate-300 font-mono">{t.member_count}</span>
                        {(t.member_users || []).slice(0, 4).map(u => (
                          <Chip key={u.id}>{u.email.split("@")[0]}</Chip>
                        ))}
                        {(t.member_users || []).length > 4 && (
                          <span className="text-[10.5px] text-slate-500">+{t.member_users.length - 4} more</span>
                        )}
                      </div>
                    </td>
                    <td>
                      <div className="flex gap-1">
                        {t.id && canEditTeams && (
                          <button data-testid={`team-edit-${t.name}`} onClick={()=>startEdit(t)} className="h-7 px-2 text-[11.5px] text-slate-300 hover:text-slate-100 inline-flex items-center gap-1"><PencilSimple size={12}/> Edit</button>
                        )}
                        {/* Deleting a team is admin-only regardless of Role Access -- unchanged from before this feature existed. */}
                        {t.id && user?.role === "admin" && (
                          <button data-testid={`team-delete-${t.name}`} onClick={()=>deleteTeam(t)} className="h-7 px-2 text-[11.5px] text-red-300 hover:text-red-200 inline-flex items-center gap-1"><Trash size={12}/></button>
                        )}
                      </div>
                    </td>
                  </>
                )}
              </tr>
            ))}
            {teams.length === 0 && (
              <tr><td colSpan={4} className="px-4 py-6 text-center text-[12px] text-slate-500">No teams. Click "New Team" to create one.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}
