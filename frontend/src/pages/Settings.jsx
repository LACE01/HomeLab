import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { fmtRel } from "@/lib/utils-fmt";
import { Warning } from "@phosphor-icons/react";

export default function Settings() {
  const [flags, setFlags] = useState([]);
  const [saving, setSaving] = useState(null);

  const load = () => api.get("/v1/settings/feature-flags").then(r => setFlags(r.data.items));
  useEffect(() => { load(); }, []);

  const toggle = async (flag) => {
    setSaving(flag.key);
    try {
      await api.patch(`/v1/settings/feature-flags/${flag.key}`, { enabled: !flag.enabled });
      toast.success(`${flag.label}: ${!flag.enabled ? "enabled" : "disabled"}`);
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to update");
    } finally { setSaving(null); }
  };

  const groups = flags.reduce((acc, f) => {
    (acc[f.group] = acc[f.group] || []).push(f);
    return acc;
  }, {});

  return (
    <Layout title="Settings" subtitle="Turn optional platform behaviors on or off &#8212; every flag defaults to on">
      {Object.entries(groups).map(([group, items]) => (
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
      {flags.length === 0 && (
        <div className="text-[12px] text-slate-500 flex items-center gap-2">
          <Warning size={14} /> No feature flags loaded.
        </div>
      )}
    </Layout>
  );
}
