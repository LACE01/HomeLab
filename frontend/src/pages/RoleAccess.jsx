import { useEffect, useState, Fragment } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { ArrowsClockwise, Info, Check } from "@phosphor-icons/react";
import { toast } from "sonner";

// Role Access -- decides which modules (pages) each non-admin role can see (view) and
// use create/update/delete actions on (edit). Module key == the route path (see
// backend/rbac.py) so there's one canonical list shared by the Sidebar, the route
// guards, and this settings page. "admin" is intentionally not a column here -- it
// always has everything at edit level and that can't be configured away, so there's
// no way to accidentally lock every admin out of this very page.

const LEVEL_ORDER = [null, "view", "edit"]; // click cycles through these
const LEVEL_META = {
  null: { label: "—", className: "text-slate-700" },
  view: { label: "view", className: "text-blue-300 bg-blue-500/10 border-blue-500/30" },
  edit: { label: "edit", className: "text-emerald-300 bg-emerald-500/10 border-emerald-500/30" },
};

function LevelCell({ level, onClick }) {
  const meta = LEVEL_META[level || "null"] || LEVEL_META.null;
  return (
    <button onClick={onClick}
      className={`w-14 h-6 text-[10.5px] rounded border font-mono transition-colors ${level ? meta.className : "border-[#30363D] text-slate-700 hover:border-[#484F58]"}`}>
      {meta.label}
    </button>
  );
}

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

  const cycle = (role, key) => {
    setAccess(prev => {
      const roleMap = { ...(prev[role] || {}) };
      const current = roleMap[key] || null;
      const next = LEVEL_ORDER[(LEVEL_ORDER.indexOf(current) + 1) % LEVEL_ORDER.length];
      if (next === null) delete roleMap[key]; else roleMap[key] = next;
      return { ...prev, [role]: roleMap };
    });
  };

  const setAllInGroup = (role, groupKeys, level) => {
    setAccess(prev => {
      const roleMap = { ...(prev[role] || {}) };
      groupKeys.forEach(k => { if (level === null) delete roleMap[k]; else roleMap[k] = level; });
      return { ...prev, [role]: roleMap };
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
    <Layout title="Role Access" subtitle="Decide which modules each role can view and edit — enforced on both the nav and the backend"
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
          Click a cell to cycle <span className="font-mono">— → view → edit → —</span>. <strong>view</strong> can see the module and its
          data; <strong>edit</strong> can also create/update/delete on it. <strong>admin</strong> always has edit everywhere, unconditionally —
          that's not editable here, so there's no way to lock every admin out of this page. The starter mapping is a reasonable default, not a
          fixed policy: tune it however your org actually wants these roles scoped. Changes here are recorded in the Audit Log.
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
                          <button onClick={() => setAllInGroup(role, groupKeys, "edit")}
                            title={`Grant edit on all of ${group} to ${role}`}
                            className="text-[9.5px] text-emerald-400/70 hover:text-emerald-300">edit</button>
                          <span className="text-slate-700">/</span>
                          <button onClick={() => setAllInGroup(role, groupKeys, "view")}
                            title={`Grant view on all of ${group} to ${role}`}
                            className="text-[9.5px] text-blue-400/70 hover:text-blue-300">view</button>
                          <span className="text-slate-700">/</span>
                          <button onClick={() => setAllInGroup(role, groupKeys, null)}
                            title={`Revoke all of ${group} from ${role}`}
                            className="text-[9.5px] text-red-400/70 hover:text-red-300">none</button>
                        </div>
                      </td>
                    ))}
                  </tr>
                  {groupModules.map(m => (
                    <tr key={m.key} className="border-t border-[#30363D]/60">
                      <td className="text-slate-300 pl-4">{m.label}</td>
                      <td className="text-center"><span className="text-[10.5px] font-mono text-slate-600">always</span></td>
                      {roles.map(role => (
                        <td key={role} className="text-center py-1">
                          <LevelCell level={(access[role] || {})[m.key] || null} onClick={() => cycle(role, m.key)}/>
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
