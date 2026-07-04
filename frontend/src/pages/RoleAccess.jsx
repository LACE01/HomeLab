import { useEffect, useState, Fragment } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { ArrowsClockwise, Info, Check } from "@phosphor-icons/react";
import { toast } from "sonner";

// Role Access -- decides which modules (pages) each non-admin role can see and use.
// Module key == the route path (see backend/rbac.py) so there's one canonical list
// for "what is a module" shared by the Sidebar, the route guards, and this settings
// page. "admin" is intentionally not a column here -- it always has everything and
// that can't be configured away, so there's no way to accidentally lock every admin
// out of this very page.

export default function RoleAccess() {
  const [modules, setModules] = useState([]);
  const [roles, setRoles] = useState([]);
  const [access, setAccess] = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [resetting, setResetting] = useState(false);

  const load = () => {
    setLoading(true);
    api.get("/v1/admin/rbac-config")
      .then(r => { setModules(r.data.modules); setRoles(r.data.roles); setAccess(r.data.access || {}); })
      .finally(() => setLoading(false));
  };
  useEffect(() => { load(); }, []);

  const toggle = (role, key) => {
    setAccess(prev => {
      const current = new Set(prev[role] || []);
      if (current.has(key)) current.delete(key); else current.add(key);
      return { ...prev, [role]: [...current] };
    });
  };

  const toggleAllInGroup = (role, groupKeys, makeOn) => {
    setAccess(prev => {
      const current = new Set(prev[role] || []);
      groupKeys.forEach(k => { if (makeOn) current.add(k); else current.delete(k); });
      return { ...prev, [role]: [...current] };
    });
  };

  const save = async () => {
    setSaving(true);
    try {
      await api.put("/v1/admin/rbac-config", { access });
      toast.success("Role access saved");
    } catch (e) { toast.error(e.response?.data?.detail || "Save failed"); }
    finally { setSaving(false); }
  };

  const resetDefaults = async () => {
    if (!window.confirm("Replace the current role access mapping with the starter defaults?")) return;
    setResetting(true);
    try {
      const r = await api.post("/v1/admin/rbac-config/reset-defaults");
      setAccess(r.data.access);
      toast.success("Reset to starter defaults");
    } catch (e) { toast.error("Reset failed"); }
    finally { setResetting(false); }
  };

  if (loading) return <Layout title="Role Access"><div className="text-slate-500 py-8 text-center">Loading…</div></Layout>;

  const groups = [...new Set(modules.map(m => m.group))];

  return (
    <Layout title="Role Access" subtitle="Decide which modules each role can see and use — enforced on both the nav and the backend"
      actions={
        <div className="flex gap-2">
          <button onClick={resetDefaults} disabled={resetting}
            className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] text-slate-300 rounded inline-flex items-center gap-1.5 disabled:opacity-50">
            <ArrowsClockwise size={13} className={resetting ? "animate-spin" : ""}/> Reset to defaults
          </button>
          <button onClick={save} disabled={saving}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded inline-flex items-center gap-1.5">
            <Check size={13}/> {saving ? "Saving…" : "Save"}
          </button>
        </div>
      }>
      <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3 py-2.5 mb-4 text-[12px] text-blue-200 leading-relaxed flex items-start gap-2 max-w-3xl">
        <Info size={16} className="shrink-0 mt-0.5"/>
        <div>
          <strong>admin</strong> always has access to every module, unconditionally — that's not editable here, so there's no way to lock every
          admin out of this page. The starter mapping below is a reasonable default, not a fixed policy: tune it however your org actually
          wants "manager", "analyst", and "executive" scoped. This is enforced on the nav (hidden items) and on each module's main backend
          endpoint — not just a UI hint.
        </div>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden max-w-4xl">
        <table className="dense w-full">
          <thead>
            <tr>
              <th className="text-left">Module</th>
              <th className="text-center w-20">admin</th>
              {roles.map(r => <th key={r} className="text-center w-24 capitalize">{r}</th>)}
            </tr>
          </thead>
          <tbody>
            {groups.map(group => {
              const groupModules = modules.filter(m => m.group === group);
              const groupKeys = groupModules.map(m => m.key);
              return (
                <Fragment key={group}>
                  <tr className="border-t border-[#30363D] bg-[#161B22]">
                    <td className="text-[10.5px] uppercase font-mono text-slate-500 tracking-wider py-1.5">{group}</td>
                    <td></td>
                    {roles.map(role => (
                      <td key={role} className="text-center">
                        <div className="flex items-center justify-center gap-1">
                          <button onClick={() => toggleAllInGroup(role, groupKeys, true)}
                            title={`Grant all of ${group} to ${role}`}
                            className="text-[9.5px] text-emerald-400/70 hover:text-emerald-300">all</button>
                          <span className="text-slate-700">/</span>
                          <button onClick={() => toggleAllInGroup(role, groupKeys, false)}
                            title={`Revoke all of ${group} from ${role}`}
                            className="text-[9.5px] text-red-400/70 hover:text-red-300">none</button>
                        </div>
                      </td>
                    ))}
                  </tr>
                  {groupModules.map(m => (
                    <tr key={m.key} className="border-t border-[#30363D]/60">
                      <td className="text-slate-300 pl-4">{m.label}</td>
                      <td className="text-center"><Chip color="slate">always</Chip></td>
                      {roles.map(role => (
                        <td key={role} className="text-center">
                          <input type="checkbox" checked={(access[role] || []).includes(m.key)}
                            onChange={() => toggle(role, m.key)}/>
                        </td>
                      ))}
                    </tr>
                  ))}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}
