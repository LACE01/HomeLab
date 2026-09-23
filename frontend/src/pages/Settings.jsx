import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { fmtRel } from "@/lib/utils-fmt";
import { Warning } from "@phosphor-icons/react";

function TunableRow({ item, onSaved }) {
  const [val, setVal] = useState(item.value);
  const [saving, setSaving] = useState(false);
  useEffect(() => { setVal(item.value); }, [item.value]);
  const dirty = String(val) !== String(item.value);
  const save = async () => {
    setSaving(true);
    try {
      await api.patch(`/v1/settings/tunables/${item.key}`, { value: Number(val) });
      toast.success(`${item.label} set to ${val} ${item.unit || ""}`.trim());
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to update");
    } finally { setSaving(false); }
  };
  return (
    <div className="px-4 py-3 flex items-start justify-between gap-4">
      <div className="min-w-0">
        <div className="text-[13px] text-slate-200">{item.label}</div>
        <div className="text-[11.5px] text-slate-500 mt-0.5 leading-relaxed">{item.description}</div>
        <div className="text-[10px] text-slate-600 mt-1">
          Allowed: {item.min}&#8211;{item.max} {item.unit}
          {item.updated_at && <> &#183; Changed {fmtRel(item.updated_at)} by {item.updated_by || "unknown"}</>}
        </div>
      </div>
      <div className="shrink-0 flex items-center gap-2">
        <input
          type="number" min={item.min} max={item.max} value={val}
          onChange={e => setVal(e.target.value)}
          className="h-8 w-24 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-100 text-right"
        />
        <span className="text-[11px] text-slate-500 w-14">{item.unit}</span>
        <button
          onClick={save} disabled={!dirty || saving}
          className={`h-8 px-3 text-[12px] rounded border ${dirty ? "border-blue-500/40 text-blue-300 hover:bg-blue-500/10" : "border-[#30363D] text-slate-600"} disabled:opacity-50`}
        >Save</button>
      </div>
    </div>
  );
}

function PasswordPolicyCard() {
  const [pol, setPol] = useState(null);
  const [saving, setSaving] = useState(false);
  const load = () => api.get("/v1/settings/password-policy").then(r => setPol(r.data)).catch(() => setPol(null));
  useEffect(() => { load(); }, []);
  if (!pol) return null;
  const set = (k, v) => setPol({ ...pol, [k]: v });
  const toggleRole = (role) => {
    const cur = pol.mfa_required_roles || [];
    set("mfa_required_roles", cur.includes(role) ? cur.filter(r => r !== role) : [...cur, role]);
  };
  const save = async () => {
    setSaving(true);
    try {
      const r = await api.patch("/v1/settings/password-policy", {
        min_length: Number(pol.min_length),
        require_upper: !!pol.require_upper, require_lower: !!pol.require_lower,
        require_digit: !!pol.require_digit, require_symbol: !!pol.require_symbol,
        breached_check: !!pol.breached_check, breached_fail_closed: !!pol.breached_fail_closed,
        mfa_required_roles: pol.mfa_required_roles || [],
      });
      setPol(r.data); toast.success("Password & MFA policy saved");
    } catch (e) { toast.error(e.response?.data?.detail || "Save failed"); }
    finally { setSaving(false); }
  };
  const Chk = ({ k, label }) => (
    <label className="flex items-center gap-2 text-[12px] text-slate-300">
      <input type="checkbox" checked={!!pol[k]} onChange={e => set(k, e.target.checked)} /> {label}
    </label>
  );
  return (
    <div className="mb-5">
      <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-2">Security policy</div>
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 space-y-3">
        <div className="flex items-center gap-3">
          <span className="text-[12.5px] text-slate-200 w-48">Minimum password length</span>
          <input type="number" min="8" value={pol.min_length}
            onChange={e => set("min_length", e.target.value === "" ? "" : Number(e.target.value))}
            className="h-8 w-24 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-100 text-right" />
          <span className="text-[10.5px] text-slate-500">CJIS floor: 8 with complexity, 20 without</span>
        </div>
        <div className="flex flex-wrap gap-x-5 gap-y-1.5">
          <Chk k="require_upper" label="Uppercase" /><Chk k="require_lower" label="Lowercase" />
          <Chk k="require_digit" label="Number" /><Chk k="require_symbol" label="Symbol" />
        </div>
        <div className="border-t border-[#30363D] pt-2 space-y-1.5">
          <Chk k="breached_check" label="Screen against known-breached passwords (HaveIBeenPwned k-anonymity)" />
          {pol.breached_check && <Chk k="breached_fail_closed" label="Block if the breach service is unreachable (fail-closed)" />}
        </div>
        <div className="border-t border-[#30363D] pt-2">
          <div className="text-[12px] text-slate-300 mb-1.5">Require MFA for roles</div>
          <div className="flex flex-wrap gap-x-4 gap-y-1.5">
            {["admin", "manager", "analyst"].map(r => (
              <label key={r} className="flex items-center gap-2 text-[12px] text-slate-300 capitalize">
                <input type="checkbox" checked={(pol.mfa_required_roles || []).includes(r)} onChange={() => toggleRole(r)} /> {r}
              </label>
            ))}
          </div>
          <div className="text-[10.5px] text-slate-500 mt-1">Users in these roles must enroll MFA at first login before the app is usable.</div>
        </div>
        <button onClick={save} disabled={saving}
          className="h-8 px-3 text-[12px] rounded border border-blue-500/40 text-blue-300 hover:bg-blue-500/10 disabled:opacity-50">Save policy</button>
      </div>
    </div>
  );
}

export default function Settings() {
  const [flags, setFlags] = useState([]);
  const [tunables, setTunables] = useState([]);
  const [saving, setSaving] = useState(null);

  const loadFlags = () => api.get("/v1/settings/feature-flags").then(r => setFlags(r.data.items));
  const loadTunables = () => api.get("/v1/settings/tunables").then(r => setTunables(r.data.items)).catch(() => {});
  useEffect(() => { loadFlags(); loadTunables(); }, []);

  const toggle = async (flag) => {
    setSaving(flag.key);
    try {
      await api.patch(`/v1/settings/feature-flags/${flag.key}`, { enabled: !flag.enabled });
      toast.success(`${flag.label}: ${!flag.enabled ? "enabled" : "disabled"}`);
      await loadFlags();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to update");
    } finally { setSaving(null); }
  };

  const flagGroups = flags.reduce((acc, f) => {
    (acc[f.group] = acc[f.group] || []).push(f);
    return acc;
  }, {});
  const tunableGroups = tunables.reduce((acc, t) => {
    (acc[t.group] = acc[t.group] || []).push(t);
    return acc;
  }, {});

  return (
    <Layout title="Settings" subtitle="Tune performance and alerting, and turn optional platform behaviors on or off">
      <PasswordPolicyCard />
      {Object.entries(tunableGroups).map(([group, items]) => (
        <div key={group} className="mb-5">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-2">{group}</div>
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
            {items.map(t => <TunableRow key={t.key} item={t} onSaved={loadTunables} />)}
          </div>
        </div>
      ))}

      {Object.entries(flagGroups).map(([group, items]) => (
        <div key={group} className="mb-5">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-2">{group}</div>
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
            {items.map(f => (
              <div key={f.key} className="px-4 py-3 flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="text-[13px] text-slate-200">{f.label}</div>
                  <div className="text-[11.5px] text-slate-500 mt-0.5 leading-relaxed">{f.description}</div>
                  {f.updated_at && (
                    <div className="text-[10px] text-slate-600 mt-1">
                      Changed {fmtRel(f.updated_at)} by {f.updated_by || "unknown"}
                    </div>
                  )}
                </div>
                <button
                  data-testid={`flag-${f.key}`}
                  onClick={() => toggle(f)}
                  disabled={saving === f.key}
                  className={`shrink-0 h-6 w-11 rounded-full relative transition-colors disabled:opacity-50 ${f.enabled ? "bg-emerald-500/70" : "bg-slate-700"}`}
                  title={f.enabled ? "Enabled — click to disable" : "Disabled — click to enable"}
                >
                  <span className={`absolute left-0 top-0.5 h-5 w-5 rounded-full bg-white transition-transform ${f.enabled ? "translate-x-[22px]" : "translate-x-0.5"}`} />
                </button>
              </div>
            ))}
          </div>
        </div>
      ))}

      {flags.length === 0 && tunables.length === 0 && (
        <div className="text-[12px] text-slate-500 flex items-center gap-2">
          <Warning size={14} /> No settings loaded.
        </div>
      )}
    </Layout>
  );
}
