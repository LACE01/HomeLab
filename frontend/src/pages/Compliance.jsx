import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { SevBadge } from "@/components/Badges";
import { Info, DownloadSimple, CircleNotch, X, ArrowSquareOut, CheckCircle, WarningCircle, Circle } from "@phosphor-icons/react";

const STATUS_META = {
  gap: { label: "Gap", color: "text-red-400", bar: "bg-red-500" },
  at_risk: { label: "At risk", color: "text-orange-400", bar: "bg-orange-500" },
  monitor: { label: "Monitor", color: "text-amber-400", bar: "bg-amber-500" },
  clean: { label: "Clean", color: "text-emerald-400", bar: "bg-emerald-500" },
};

const OP_STATUS_META = {
  implemented: { label: "Implemented", color: "text-emerald-400", icon: CheckCircle },
  partial: { label: "Partial", color: "text-amber-400", icon: WarningCircle },
  gap: { label: "Gap", color: "text-red-400", icon: WarningCircle },
  at_risk: { label: "At risk", color: "text-orange-400", icon: WarningCircle },
  not_implemented: { label: "Not implemented", color: "text-slate-500", icon: Circle },
};

const downloadBlob = async (path, filename) => {
  const r = await api.get(path, { responseType: "blob" });
  const url = window.URL.createObjectURL(new Blob([r.data]));
  const a = document.createElement("a"); a.href = url; a.download = filename; a.click();
  window.URL.revokeObjectURL(url);
};

export default function Compliance() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [drillDown, setDrillDown] = useState(null); // { control_id, name, total, items } | "loading" | null
  const [drillDownFor, setDrillDownFor] = useState(null);

  useEffect(() => {
    api.get("/v1/compliance/summary").then(r => setSummary(r.data)).catch(() => toast.error("Failed to load compliance summary")).finally(() => setLoading(false));
  }, []);

  const openControl = async (c) => {
    setDrillDownFor(c);
    setDrillDown(null);
    try {
      const r = await api.get(`/v1/compliance/controls/${c.id}/findings`);
      setDrillDown(r.data);
    } catch (e) {
      toast.error("Failed to load findings for this control");
      setDrillDownFor(null);
    }
  };

  const download = async () => {
    setDownloading(true);
    try {
      await downloadBlob("/v1/reports/pdf/compliance", "compliance-coverage.pdf");
    } catch (e) {
      toast.error("Download failed");
    } finally { setDownloading(false); }
  };

  if (loading) return <Layout title="Compliance"><div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div></Layout>;
  if (!summary) return null;

  return (
    <Layout title="Compliance Coverage" subtitle="CIS Controls v8, NIST CSF 2.0, ISO 27001:2022, and SOC 2 coverage across findings and live security capabilities">
      <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3 py-2.5 mb-5 text-[12px] text-blue-200 leading-relaxed flex items-start gap-2 max-w-3xl">
        <Info size={15} className="shrink-0 mt-0.5"/>
        <div>{summary.methodology_note}</div>
      </div>

      <div className="flex items-center justify-between mb-5">
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-5 py-4 inline-flex items-center gap-4">
          <div>
            <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500">CIS Controls Coverage</div>
            <div className="text-[28px] text-slate-100 font-mono mt-0.5">
              {summary.coverage_pct != null ? `${summary.coverage_pct}%` : "—"}
            </div>
          </div>
          <div className="text-[11px] text-slate-500 max-w-[220px] leading-relaxed">
            of mapped controls with no Critical/High severity findings currently open against them
          </div>
        </div>
        <button onClick={download} disabled={downloading}
          className="h-9 px-3.5 text-[12.5px] bg-[#161B22] hover:bg-[#1c232c] disabled:opacity-40 text-slate-200 rounded inline-flex items-center gap-1.5 border border-[#30363D]">
          {downloading ? <CircleNotch size={15} className="animate-spin"/> : <DownloadSimple size={15}/>} Download PDF
        </button>
      </div>

      <div className="grid grid-cols-2 gap-5">
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md">
          <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">CIS Controls v8</h3></div>
          <div className="divide-y divide-[#30363D]">
            {summary.controls.map(c => {
              const meta = STATUS_META[c.status] || STATUS_META.clean;
              return (
                <div key={c.id} onClick={() => openControl(c)}
                  className={`px-4 py-3 ${c.total > 0 ? "cursor-pointer hover:bg-[#161B22] transition-colors" : ""}`}>
                  <div className="flex items-center justify-between gap-2">
                    <div className="min-w-0">
                      <span className="text-[12px] font-mono text-slate-500">{c.id}</span>{" "}
                      <span className="text-[12.5px] text-slate-200">{c.name}</span>
                    </div>
                    <span className={`text-[11px] font-mono ${meta.color}`}>{meta.label}</span>
                  </div>
                  {c.total > 0 && (
                    <div className="flex items-center gap-2 mt-1.5">
                      <div className="h-1.5 flex-1 bg-slate-800 rounded overflow-hidden flex">
                        {c.critical > 0 && <div className="bg-red-500 h-full" style={{ width: `${100 * c.critical / c.total}%` }}/>}
                        {c.high > 0 && <div className="bg-orange-500 h-full" style={{ width: `${100 * c.high / c.total}%` }}/>}
                        {c.medium > 0 && <div className="bg-amber-500 h-full" style={{ width: `${100 * c.medium / c.total}%` }}/>}
                        {c.low > 0 && <div className="bg-blue-500 h-full" style={{ width: `${100 * c.low / c.total}%` }}/>}
                      </div>
                      <span className="text-[10.5px] text-slate-500 font-mono shrink-0">{c.total} open</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        <div className="border border-[#30363D] bg-[#0D1117] rounded-md h-fit">
          <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">NIST CSF 2.0 Functions</h3></div>
          <div className="divide-y divide-[#30363D]">
            {summary.nist_functions.map(n => (
              <div key={n.function} className="px-4 py-3 flex items-center justify-between">
                <div>
                  <span className="text-[12px] font-mono text-slate-500">{n.function}</span>{" "}
                  <span className="text-[12.5px] text-slate-200">{n.label}</span>
                </div>
                <div className="text-[11px] text-slate-400 font-mono">
                  {n.critical > 0 && <span className="text-red-400">{n.critical} crit </span>}
                  {n.high > 0 && <span className="text-orange-400">{n.high} high </span>}
                  <span className="text-slate-500">· {n.total} total</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {summary.operational_controls && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md mt-5">
          <div className="px-4 py-2 border-b border-[#30363D] flex items-center justify-between">
            <h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">ISO 27001:2022 / SOC 2 -- Operational Controls</h3>
            <span className="text-[10.5px] text-slate-600">Capability &amp; usage based, not finding counts</span>
          </div>
          <div className="divide-y divide-[#30363D]">
            {summary.operational_controls.map(c => {
              const meta = OP_STATUS_META[c.status] || OP_STATUS_META.not_implemented;
              const StatusIcon = meta.icon;
              return (
                <div key={c.id} className="px-4 py-3 flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-[12.5px] text-slate-200">{c.label}</div>
                    <div className="text-[11px] text-slate-500 mt-0.5">{c.evidence}</div>
                    <div className="text-[10.5px] text-slate-600 font-mono mt-1">
                      ISO 27001: {c.iso27001.join(", ")} &middot; SOC 2: {c.soc2.join(", ")}
                    </div>
                  </div>
                  <span className={`text-[11px] font-mono shrink-0 inline-flex items-center gap-1 ${meta.color}`}>
                    <StatusIcon size={13}/> {meta.label}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {drillDownFor && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={() => setDrillDownFor(null)}>
          <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-2xl max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
              <div>
                <div className="text-[14px] text-slate-100 font-medium">
                  <span className="font-mono text-slate-500">{drillDownFor.id}</span> {drillDownFor.name}
                </div>
                {drillDown && drillDown !== "loading" && (
                  <div className="text-[11px] text-slate-500 mt-0.5">{drillDown.total} open finding(s) mapped to this control</div>
                )}
              </div>
              <button onClick={() => setDrillDownFor(null)} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
            </div>
            <div className="p-3">
              {!drillDown ? (
                <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
              ) : drillDown.items.length === 0 ? (
                <div className="text-[12.5px] text-slate-500 py-8 text-center">No open findings mapped to this control.</div>
              ) : (
                <div className="divide-y divide-[#30363D]">
                  {drillDown.items.map(f => (
                    <Link key={f.id} to={`/findings/${f.id}`}
                      className="flex items-center justify-between gap-3 px-2 py-2.5 hover:bg-[#161B22] transition-colors rounded">
                      <div className="min-w-0 flex items-center gap-2">
                        <SevBadge severity={f.severity}/>
                        <div className="min-w-0">
                          <div className="text-[12.5px] text-slate-200 truncate">{f.title}</div>
                          <div className="text-[10.5px] text-slate-500 font-mono">
                            {f.cve || f.cwe || "—"} {f.asset_hostname ? `· ${f.asset_hostname}` : ""}
                          </div>
                        </div>
                      </div>
                      <ArrowSquareOut size={13} className="text-slate-500 shrink-0"/>
                    </Link>
                  ))}
                  {drillDown.total > drillDown.items.length && (
                    <div className="text-[11px] text-slate-500 text-center py-2">
                      Showing first {drillDown.items.length} of {drillDown.total} — narrow this down from the Findings page for the rest.
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </Layout>
  );
}
