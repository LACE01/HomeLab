import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { FloppyDisk, ArrowCounterClockwise, ShieldCheck } from "@phosphor-icons/react";

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];
const CRITICALITIES = ["crown_jewel", "critical", "high", "medium", "low"];
const CRIT_LABEL = {
  crown_jewel: "Crown Jewel", critical: "Critical", high: "High",
  medium: "Medium", low: "Low",
};

const DEFAULTS = {
  Critical: { crown_jewel: 3, critical: 7, high: 14, medium: 21, low: 30 },
  High:     { crown_jewel: 7, critical: 14, high: 21, medium: 30, low: 45 },
  Medium:   { crown_jewel: 14, critical: 30, high: 45, medium: 60, low: 90 },
  Low:      { crown_jewel: 30, critical: 60, high: 90, medium: 120, low: 180 },
  Info:     { crown_jewel: 90, critical: 90, high: 180, medium: 180, low: 365 },
};

const sevColor = {
  Critical: "text-red-300 border-red-500/30 bg-red-500/10",
  High:     "text-orange-300 border-orange-500/30 bg-orange-500/10",
  Medium:   "text-amber-300 border-amber-500/30 bg-amber-500/10",
  Low:      "text-blue-300 border-blue-500/30 bg-blue-500/10",
  Info:     "text-slate-300 border-slate-500/30 bg-slate-500/10",
};

export default function SlaPolicies() {
  const [policies, setPolicies] = useState(null);
  const [original, setOriginal] = useState(null);
  const [saving, setSaving] = useState(false);

  const load = async () => {
    const r = await api.get("/v1/admin/sla-policies");
    setPolicies(r.data.policies);
    setOriginal(JSON.parse(JSON.stringify(r.data.policies)));
  };

  useEffect(() => { load(); }, []);

  const dirty = JSON.stringify(policies) !== JSON.stringify(original);

  const setCell = (sev, crit, val) => {
    const n = Math.max(1, Math.min(3650, parseInt(val) || 0));
    setPolicies({ ...policies, [sev]: { ...policies[sev], [crit]: n } });
  };

  const save = async () => {
    setSaving(true);
    try {
      const r = await api.put("/v1/admin/sla-policies", { policies });
      setPolicies(r.data.policies);
      setOriginal(JSON.parse(JSON.stringify(r.data.policies)));
      toast.success("SLA policies saved — new findings will use these targets immediately");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to save SLA policies");
    } finally { setSaving(false); }
  };

  const reset = () => setPolicies(JSON.parse(JSON.stringify(original)));
  const resetDefaults = () => setPolicies(JSON.parse(JSON.stringify(DEFAULTS)));

  if (!policies) return <Layout title="SLA Policies"><div className="text-slate-500 text-[12px] p-4">Loading…</div></Layout>;

  return (
    <Layout
      title="SLA Policies"
      subtitle="Remediation deadlines (days) by severity × asset criticality. New findings inherit these targets at ingest."
      actions={
        <>
          <button
            data-testid="sla-reset-defaults"
            onClick={resetDefaults}
            className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] hover:bg-slate-800/40 rounded inline-flex items-center gap-1.5 text-slate-300"
            title="Reset all cells to platform defaults"
          >
            <ArrowCounterClockwise size={13}/> Defaults
          </button>
          <button
            data-testid="sla-revert"
            disabled={!dirty}
            onClick={reset}
            className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300 disabled:opacity-40"
          >
            Revert
          </button>
          <button
            data-testid="sla-save"
            disabled={!dirty || saving}
            onClick={save}
            className="h-8 px-3 text-[12px] bg-blue-500/15 border border-blue-500/40 hover:bg-blue-500/25 rounded inline-flex items-center gap-1.5 text-blue-300 disabled:opacity-40"
          >
            <FloppyDisk size={13}/> {saving ? "Saving…" : "Save policies"}
          </button>
        </>
      }
    >
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <div className="px-4 py-2.5 border-b border-[#30363D] flex items-center gap-2">
          <ShieldCheck size={14} className="text-emerald-400"/>
          <div className="text-[12px] uppercase tracking-wider font-mono text-slate-400">Remediation SLA Matrix</div>
          {dirty && <span data-testid="sla-dirty" className="text-[10.5px] uppercase tracking-wider font-mono text-amber-300 ml-auto">unsaved changes</span>}
        </div>
        <table className="dense w-full">
          <thead>
            <tr>
              <th className="text-left w-[110px]">Severity ↓ / Criticality →</th>
              {CRITICALITIES.map(c => (
                <th key={c} className="text-center font-mono text-[11px]">{CRIT_LABEL[c]}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {SEVERITIES.map(sev => (
              <tr key={sev} className="border-t border-[#30363D]">
                <td>
                  <span className={`inline-block px-2 py-0.5 text-[10.5px] uppercase tracking-wider font-mono rounded border ${sevColor[sev]}`}>{sev}</span>
                </td>
                {CRITICALITIES.map(crit => (
                  <td key={crit} className="text-center py-2">
                    <input
                      data-testid={`sla-${sev}-${crit}`}
                      type="number"
                      min={1}
                      max={3650}
                      value={policies[sev]?.[crit] ?? ""}
                      onChange={(e) => setCell(sev, crit, e.target.value)}
                      className="w-16 h-7 bg-[#161B22] border border-[#30363D] hover:border-[#484F58] focus:border-blue-500/60 focus:outline-none rounded px-2 text-center font-mono text-[12.5px] text-slate-100 tabular-nums"
                    />
                    <span className="text-[10px] text-slate-600 ml-1">d</span>
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="mt-4 text-[11.5px] text-slate-500 leading-relaxed max-w-3xl">
        Tighter SLAs for Critical findings on Crown-Jewel assets enforce faster patching where stakes are highest.
        Changes apply to <strong className="text-slate-300">new ingest events</strong> immediately; existing open
        findings retain the SLA they were created with. To re-apply, use the nightly rescore admin action.
      </div>
    </Layout>
  );
}
