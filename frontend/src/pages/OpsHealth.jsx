import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Heartbeat, CheckCircle, XCircle, Clock, Database, X } from "@phosphor-icons/react";

const STATUS_META = {
  ok: { label: "Healthy", color: "green" },
  error: { label: "Errored last run", color: "red" },
  stale: { label: "Stale — overdue", color: "orange" },
  never_run: { label: "Never run", color: "slate" },
};

function timeAgo(iso) {
  if (!iso) return "never";
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.round(diffMs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}

function LoopDetailModal({ loop, onClose }) {
  const detail = loop.detail || {};
  const failures = Array.isArray(detail.failures) ? detail.failures : null;
  const entries = Object.entries(detail).filter(([k]) => k !== "failures");
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-lg max-h-[80vh] flex flex-col" onClick={e => e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between">
          <div>
            <h3 className="text-[13px] font-medium text-slate-100">{loop.label}</h3>
            <div className="text-[10.5px] font-mono text-slate-500">{loop.name} · last run {timeAgo(loop.last_run_at)}</div>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16}/></button>
        </div>
        <div className="p-4 overflow-y-auto space-y-3">
          {!loop.detail && <div className="text-[12px] text-slate-500">No detail recorded for this run.</div>}
          {entries.length > 0 && (
            <div className="grid grid-cols-2 gap-2">
              {entries.map(([k, v]) => (
                <div key={k} className="border border-[#30363D] rounded px-2.5 py-1.5">
                  <div className="text-[10px] uppercase font-mono text-slate-500">{k.replace(/_/g, " ")}</div>
                  <div className="text-[12px] text-slate-200 font-mono break-all">{typeof v === "object" ? JSON.stringify(v) : String(v)}</div>
                </div>
              ))}
            </div>
          )}
          {failures && failures.length > 0 && (
            <div>
              <div className="text-[11px] uppercase font-mono text-red-400 mb-1.5">{failures.length} failure(s)</div>
              <div className="space-y-1.5">
                {failures.map((f, i) => (
                  <div key={i} className="border border-red-500/30 bg-red-500/5 rounded px-2.5 py-1.5">
                    <div className="text-[11.5px] text-red-300 font-mono">{f.domain || f.name || f.id || `item ${i + 1}`}</div>
                    <div className="text-[11.5px] text-slate-300 mt-0.5 break-words">{f.error || f.message || JSON.stringify(f)}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
          <div className="pt-2 border-t border-[#30363D]">
            <div className="text-[10px] uppercase font-mono text-slate-500 mb-1">Raw detail</div>
            <pre className="text-[10.5px] text-slate-400 bg-[#161B22] border border-[#30363D] rounded p-2 overflow-x-auto whitespace-pre-wrap break-all">{JSON.stringify(loop.detail, null, 2)}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function OpsHealth() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedLoop, setSelectedLoop] = useState(null);
  const pollRef = useRef(null);

  const load = async () => {
    try {
      const r = await api.get("/v1/admin/health");
      setData(r.data);
    } catch (e) {
      toast.error("Failed to load system health");
    } finally { setLoading(false); }
  };

  useEffect(() => {
    load();
    pollRef.current = setInterval(load, 20000);
    return () => clearInterval(pollRef.current);
  }, []);

  if (loading) return <Layout title="System Health"><div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div></Layout>;
  if (!data) return null;

  return (
    <Layout title="System Health" subtitle="Background loops and database connectivity — is everything actually running?">
      <div className="grid grid-cols-2 gap-3 mb-5 max-w-xl">
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3">
          <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Loops Healthy</div>
          <div className="text-[22px] text-slate-100 font-mono mt-0.5">{data.healthy_count} / {data.total_count}</div>
        </div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3 flex items-center gap-2.5">
          <Database size={18} className={data.database?.status === "ok" ? "text-emerald-400" : "text-red-400"}/>
          <div>
            <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Database</div>
            <div className={`text-[13px] font-mono mt-0.5 ${data.database?.status === "ok" ? "text-emerald-400" : "text-red-400"}`}>
              {data.database?.status === "ok" ? "Connected" : "Unreachable"}
            </div>
          </div>
        </div>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
        {data.loops.map(l => {
          const meta = STATUS_META[l.status] || STATUS_META.never_run;
          return (
            <div key={l.name} onClick={() => setSelectedLoop(l)} data-testid={`loop-row-${l.name}`}
              className="px-4 py-3.5 flex items-center justify-between gap-3 cursor-pointer hover:bg-slate-800/20">
              <div className="flex items-center gap-2.5 min-w-0">
                {l.status === "ok" ? <CheckCircle size={16} className="text-emerald-400 shrink-0"/> :
                 l.status === "never_run" ? <Clock size={16} className="text-slate-600 shrink-0"/> :
                 <XCircle size={16} className={l.status === "stale" ? "text-orange-400 shrink-0" : "text-red-400 shrink-0"}/>}
                <div className="min-w-0">
                  <div className="text-[13px] text-slate-200">{l.label}</div>
                  <div className="text-[11px] text-slate-500 font-mono">{l.name}</div>
                </div>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <div className="text-right text-[11px] text-slate-500">
                  <div>Last run: {timeAgo(l.last_run_at)}</div>
                  <div>{l.run_count} run(s){l.error_count > 0 ? ` · ${l.error_count} error(s)` : ""}</div>
                </div>
                <Chip color={meta.color}>{meta.label}</Chip>
              </div>
            </div>
          );
        })}
      </div>

      <div className="mt-4 text-[11px] text-slate-500 leading-relaxed max-w-2xl">
        A loop is marked <span className="text-orange-400">stale</span> if it hasn't reported in for more than 2x its
        expected interval — a single slow run won't trip this, but a crashed or hung loop will. Click any row for its
        detailed per-step results (which specific sync failed and why) — the same data is also in the container logs.
      </div>

      {selectedLoop && <LoopDetailModal loop={selectedLoop} onClose={() => setSelectedLoop(null)} />}
    </Layout>
  );
}
