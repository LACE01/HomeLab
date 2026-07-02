import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  Plus, X, Trash, ArrowsClockwise, MagnifyingGlass, WifiHigh, CircleDashed,
  CheckCircle, XCircle, CircleNotch, ArrowSquareIn,
} from "@phosphor-icons/react";

export default function Easm() {
  const [domains, setDomains] = useState([]);
  const [candidates, setCandidates] = useState([]);
  const [counts, setCounts] = useState({ new: 0, promoted: 0, dismissed: 0 });
  const [statusFilter, setStatusFilter] = useState("new");
  const [loading, setLoading] = useState(true);
  const [domainInput, setDomainInput] = useState("");
  const [scanningIds, setScanningIds] = useState(new Set());
  const [busyRow, setBusyRow] = useState(null);
  const pollRef = useRef(null);

  const load = async () => {
    try {
      const [dRes, cRes] = await Promise.all([
        api.get("/v1/admin/easm/domains"),
        api.get(`/v1/admin/easm/candidates${statusFilter ? `?status=${statusFilter}` : ""}`),
      ]);
      setDomains(dRes.data.items || []);
      setCandidates(cRes.data.items || []);
      setCounts(cRes.data.counts || { new: 0, promoted: 0, dismissed: 0 });
    } catch (e) {
      toast.error("Failed to load EASM data");
    } finally { setLoading(false); }
  };

  useEffect(() => {
    load();
    pollRef.current = setInterval(load, 15000);
    return () => clearInterval(pollRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter]);

  const addDomain = async () => {
    if (!domainInput.trim()) return;
    try {
      await api.post("/v1/admin/easm/domains", { domain: domainInput.trim() });
      toast.success(`Now watching ${domainInput.trim()}`);
      setDomainInput("");
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to add domain");
    }
  };

  const scanNow = async (d) => {
    setScanningIds(prev => new Set(prev).add(d.id));
    try {
      const r = await api.post(`/v1/admin/easm/domains/${d.id}/scan-now`);
      toast.success(`${d.domain}: ${r.data.hostnames_found} hostname(s) found, ${r.data.new_candidates} new candidate(s)`);
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Scan failed");
    } finally {
      setScanningIds(prev => { const n = new Set(prev); n.delete(d.id); return n; });
    }
  };

  const removeDomain = async (d) => {
    if (!window.confirm(`Stop watching "${d.domain}"?`)) return;
    try {
      await api.delete(`/v1/admin/easm/domains/${d.id}`);
      load();
    } catch (e) { toast.error("Delete failed"); }
  };

  const promote = async (c) => {
    setBusyRow(c.id);
    try {
      await api.post(`/v1/admin/easm/candidates/${c.id}/promote`);
      toast.success(`${c.hostname} added to inventory`);
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Promote failed");
    } finally { setBusyRow(null); }
  };

  const dismiss = async (c) => {
    setBusyRow(c.id);
    try {
      await api.post(`/v1/admin/easm/candidates/${c.id}/dismiss`, { reason: null });
      toast.success(`${c.hostname} dismissed`);
      load();
    } catch (e) {
      toast.error("Dismiss failed");
    } finally { setBusyRow(null); }
  };

  return (
    <Layout title="External Attack Surface" subtitle="Passive subdomain discovery via certificate transparency logs — finds internet-facing hosts before they show up as a surprise">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 mb-5">
        <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-2.5">Watched domains</div>
        <div className="flex gap-2 mb-3">
          <input value={domainInput} onChange={e => setDomainInput(e.target.value)}
            onKeyDown={e => e.key === "Enter" && addDomain()}
            placeholder="example.com"
            className="h-9 flex-1 max-w-xs bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100 font-mono"/>
          <button onClick={addDomain} className="h-9 px-3.5 text-[12.5px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
            <Plus size={15}/> Watch
          </button>
        </div>
        {domains.length === 0 ? (
          <div className="text-[12px] text-slate-500">No domains being watched yet — add your root domain(s) above to discover subdomains via public CT logs.</div>
        ) : (
          <div className="space-y-1.5">
            {domains.map(d => (
              <div key={d.id} className="flex items-center justify-between gap-3 border border-[#30363D] rounded-md px-3 py-2">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="text-[12.5px] text-slate-200 font-mono">{d.domain}</span>
                  {d.last_scanned_at && <span className="text-[10.5px] text-slate-500">Last scan: {new Date(d.last_scanned_at).toLocaleString()}</span>}
                  {d.last_result && <span className="text-[10.5px] text-slate-500">· {d.last_result.hostnames_found} hostname(s) found</span>}
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  <button onClick={() => scanNow(d)} disabled={scanningIds.has(d.id)}
                    className="h-7 px-2.5 text-[11px] bg-blue-500/10 hover:bg-blue-500/20 disabled:opacity-40 text-blue-300 rounded inline-flex items-center gap-1.5 border border-blue-500/30">
                    {scanningIds.has(d.id) ? <CircleNotch size={12} className="animate-spin"/> : <MagnifyingGlass size={12}/>} Scan now
                  </button>
                  <button onClick={() => removeDomain(d)} className="h-7 w-7 flex items-center justify-center text-slate-500 hover:text-red-400 rounded border border-[#30363D]">
                    <Trash size={12}/>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="flex gap-1 border-b border-[#30363D] mb-4">
        {[
          { key: "new", label: `New (${counts.new})` },
          { key: "promoted", label: `Promoted (${counts.promoted})` },
          { key: "dismissed", label: `Dismissed (${counts.dismissed})` },
        ].map(t => (
          <button key={t.key} onClick={() => setStatusFilter(t.key)}
            className={`px-4 py-2 text-[13px] border-b-2 -mb-px transition-colors ${
              statusFilter === t.key ? "border-blue-500 text-blue-300" : "border-transparent text-slate-500 hover:text-slate-300"
            }`}>
            {t.label}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : candidates.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          Nothing here yet. Add a domain above and run a scan.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
          {candidates.map(c => (
            <div key={c.id} className="px-4 py-3 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2.5 min-w-0">
                {c.live ? <WifiHigh size={14} className="text-emerald-400 shrink-0"/> : <CircleDashed size={14} className="text-slate-600 shrink-0"/>}
                <div className="min-w-0">
                  <div className="text-[12.5px] text-slate-200 font-mono truncate">{c.hostname}</div>
                  <div className="text-[10.5px] text-slate-500">
                    {c.live ? `Resolves to ${c.resolved_ip}` : "Doesn't resolve — likely stale/decommissioned"}
                    {" · first seen "}{new Date(c.first_seen_at).toLocaleDateString()}
                  </div>
                </div>
                {!c.live && <Chip color="slate">Not live</Chip>}
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                {c.status === "new" && (
                  <>
                    <button onClick={() => promote(c)} disabled={busyRow === c.id}
                      className="h-8 px-2.5 text-[11.5px] bg-emerald-500/10 hover:bg-emerald-500/20 disabled:opacity-40 text-emerald-300 rounded inline-flex items-center gap-1.5 border border-emerald-500/30">
                      <ArrowSquareIn size={13}/> Add to inventory
                    </button>
                    <button onClick={() => dismiss(c)} disabled={busyRow === c.id}
                      className="h-8 px-2.5 text-[11.5px] bg-[#161B22] hover:bg-[#1c232c] disabled:opacity-40 text-slate-400 rounded inline-flex items-center gap-1.5 border border-[#30363D]">
                      <XCircle size={13}/> Dismiss
                    </button>
                  </>
                )}
                {c.status === "promoted" && <Chip color="green">In inventory</Chip>}
                {c.status === "dismissed" && <Chip color="slate">Dismissed</Chip>}
              </div>
            </div>
          ))}
        </div>
      )}
    </Layout>
  );
}
