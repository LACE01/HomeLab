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
