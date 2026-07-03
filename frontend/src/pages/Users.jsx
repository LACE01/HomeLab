import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Plus, Trash, PencilSimple, X } from "@phosphor-icons/react";
import { toast } from "sonner";

const ROLES = ["admin", "manager", "analyst", "executive"];

export default function Users() {
  const [items, setItems] = useState([]);
  const [editing, setEditing] = useState(null);  // user object being edited, or "new"
  const [form, setForm] = useState({});
  const load = () => api.get("/v1/admin/users").then(r => setItems(r.data.items));
  useEffect(() => { load(); }, []);

  const openNew = () => { setEditing("new"); setForm({email:"", name:"", role:"analyst", team:"", department:"", password:""}); };
  const openEdit = (u) => { setEditing(u); setForm({email:u.email||"", name:u.name||"", role:u.role, team:u.team||"", department:u.department||"", active:u.active!==false, password:""}); };
  const close = () => setEditing(null);

  const save = async () => {
    try {
      if (editing === "new") {
        if (!form.email || !form.name) { toast.error("Email and name required"); return; }
        await api.post("/v1/admin/users", form);
        toast.success("User created");
      } else {
        const payload = Object.fromEntries(Object.entries(form).filter(([_,v]) => v !== "" && v !== null && v !== undefined));
        await api.patch(`/v1/admin/users/${editing.id}`, payload);
        toast.success("User updated");
      }
      close(); await load();
    } catch (e) { toast.error(e.response?.data?.detail || "Save failed"); }
  };

  const del = async (u) => {
    if (!window.confirm(`Delete ${u.email}?`)) return;
    try { await api.delete(`/v1/admin/users/${u.id}`); toast.success("Deleted"); await load(); }
    catch (e) { toast.error(e.response?.data?.detail || "Delete failed"); }
  };

  return (
    <Layout title="User Management" subtitle="Add, edit, disable, and remove users"
      actions={<button data-testid="user-new" onClick={openNew}
        className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
        <Plus size={14}/> Add user
      </button>}>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table className="dense w-full">
          <thead><tr><th className="text-left">Email</th><th className="text-left">Name</th><th>Role</th><th>Team</th><th>Department</th><th>Active</th><th>Created</th><th></th></tr></thead>
          <tbody>
            {items.map(u => (
              <tr key={u.id} className="border-t border-[#30363D]">
                <td className="font-mono text-[12px]">{u.email}</td>
                <td className="text-slate-200">{u.name}</td>
                <td><Chip color={u.role==="admin"?"red":u.role==="manager"?"amber":u.role==="executive"?"blue":"slate"}>{u.role}</Chip></td>
                <td className="text-slate-400">{u.team || "—"}</td>
                <td className="text-slate-400">{u.department || "—"}</td>
                <td><Chip color={u.active===false?"slate":"green"}>{u.active===false?"disabled":"active"}</Chip></td>
                <td className="font-mono text-[10.5px] text-slate-500">{(u.created_at||"").slice(0,10)}</td>
                <td className="flex gap-1 justify-end pr-2 py-1">
                  <button data-testid={`edit-${u.id}`} onClick={()=>openEdit(u)} className="text-blue-300 hover:text-blue-200"><PencilSimple size={14}/></button>
                  <button data-testid={`del-${u.id}`} onClick={()=>del(u)} className="text-red-400 hover:text-red-300"><Trash size={14}/></button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {editing && (
        <div data-testid="user-modal" className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50" onClick={close}>
          <div className="w-full max-w-[480px] border border-[#30363D] bg-[#0D1117] rounded-md" onClick={e=>e.stopPropagation()}>
            <div className="px-4 py-3 border-b border-[#30363D] flex justify-between items-center">
              <h3 className="text-[14px] font-medium">{editing==="new"?"Create user":"Edit "+editing.email}</h3>
              <button onClick={close}><X size={16}/></button>
            </div>
            <div className="p-4 space-y-3">
              <div><label className="text-[10px] uppercase font-mono text-slate-500">Email</label>
                <input data-testid="u-email" type="email" value={form.email||""} onChange={(e)=>setForm({...form, email:e.target.value})} className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px]"/>
                {editing !== "new" && <div className="text-[10.5px] text-slate-500 mt-1">Changing this updates their login email and any approval-routing steps set to their address.</div>}
              </div>
              <div><label className="text-[10px] uppercase font-mono text-slate-500">Name</label>
                <input data-testid="u-name" value={form.name||""} onChange={(e)=>setForm({...form, name:e.target.value})} className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px]"/>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div><label className="text-[10px] uppercase font-mono text-slate-500">Role</label>
                  <select data-testid="u-role" value={form.role||"analyst"} onChange={(e)=>setForm({...form, role:e.target.value})} className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px]">
                    {ROLES.map(r=> <option key={r}>{r}</option>)}
                  </select>
                </div>
                <div><label className="text-[10px] uppercase font-mono text-slate-500">Department</label>
                  <input data-testid="u-dept" value={form.department||""} onChange={(e)=>setForm({...form, department:e.target.value})} className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px]"/>
                </div>
              </div>
              <div><label className="text-[10px] uppercase font-mono text-slate-500">Team</label>
                <input data-testid="u-team" value={form.team||""} onChange={(e)=>setForm({...form, team:e.target.value})} placeholder="e.g. Platform Eng" className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px]"/>
              </div>
              <div><label className="text-[10px] uppercase font-mono text-slate-500">{editing==="new"?"Password (optional — blank = OAuth-only)":"New password (leave blank to keep current)"}</label>
                <input data-testid="u-password" type="password" value={form.password||""} onChange={(e)=>setForm({...form, password:e.target.value})} className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] font-mono"/>
              </div>
              {editing !== "new" && (
                <label className="flex items-center gap-2 text-[12px]">
                  <input type="checkbox" checked={form.active!==false} onChange={(e)=>setForm({...form, active:e.target.checked})}/> Active
                </label>
              )}
            </div>
            <div className="px-4 py-3 border-t border-[#30363D] flex justify-end gap-2">
              <button onClick={close} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
              <button data-testid="u-save" onClick={save} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">Save</button>
            </div>
          </div>
        </div>
      )}
    </Layout>
  );
}
