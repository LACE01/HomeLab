import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Target, Warning, ArrowClockwise, CheckCircle, Plus, X, CaretDown, CaretRight } from "@phosphor-icons/react";

function ProgressBar({ pct }) {
  const color = pct >= 100 ? "bg-emerald-500" : pct >= 50 ? "bg-blue-500" : "bg-amber-500";
  return (
    <div className="h-2 w-full bg-[#161B22] rounded-full overflow-hidden">
      <div className={`h-full ${color}`} style={{ width: `${Math.min(100, pct)}%` }} />
    </div>
  );
}

export default function RemediationCampaigns() {
  const [items, setItems] = useState([]);
  const [alerts, setAlerts] = useState(null);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [expanded, setExpanded] = useState(null);
  const [detail, setDetail] = useState(null);

  const load = async () => {
    setLoading(true);
    try {
      const [r, al] = await Promise.all([
        api.get("/v1/remediation-campaigns"),
        api.get("/v1/remediation-campaigns/alerts"),
      ]);
      setItems(r.data.items || []); setAlerts(al.data);
    } catch { toast.error("Failed to load campaigns"); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const expand = async (id) => {
    if (expanded === id) { setExpanded(null); setDetail(null); return; }
    setExpanded(id); setDetail(null);
    try { const r = await api.get(`/v1/remediation-campaigns/${id}`); setDetail(r.data); } catch { /* ignore */ }
  };

  const remove = async (c) => {
    if (!window.confirm(`Delete campaign "${c.name}"? (findings are not affected)`)) return;
    await api.delete(`/v1/remediation-campaigns/${c.id}`); toast.success("Deleted"); load();
  };

  return (
    <Layout title="Remediation Campaigns" subtitle="Patch tracker — progress auto-driven by scanner status; no more weekly spreadsheet"
      actions={
        <button onClick={() => setOpen(true)}
          className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
          <Plus size={14}/> New campaign
        </button>
      }>
      {open && <CreateModal onClose={() => setOpen(false)} onCreated={() => { setOpen(false); load(); }} />}

      {alerts && (alerts.overdue.length || alerts.regressions.length || alerts.newly_complete.length) > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
          <AlertCard tone="red" icon={Warning} label="Overdue" items={alerts.overdue} render={x=>`${x.name} · ${x.open} open`}/>
          <AlertCard tone="amber" icon={ArrowClockwise} label="Regressions" items={alerts.regressions} render={x=>`${x.name} · ${x.regressions} reopened`}/>
          <AlertCard tone="green" icon={CheckCircle} label="Newly complete" items={alerts.newly_complete} render={x=>x.name}/>
        </div>
      )}

      {loading ? <div className="text-[12px] text-slate-500">Loading…</div>
      : items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-8 text-center text-[12.5px] text-slate-500">
          No campaigns yet. Create one to track a patch push.
        </div>
      ) : (
        <div className="space-y-2 max-w-5xl">
          {items.map((c) => {
            const p = c.progress;
            return (
              <div key={c.id} className="border border-[#30363D] bg-[#0D1117] rounded-md">
                <div className="p-3.5">
                  <div className="flex items-center justify-between gap-3">
                    <button onClick={() => expand(c.id)} className="flex items-center gap-2 min-w-0 text-left">
                      {expanded === c.id ? <CaretDown size={14} className="text-slate-500"/> : <CaretRight size={14} className="text-slate-500"/>}
                      <Target size={16} className="text-blue-400 shrink-0"/>
                      <span className="text-[13.5px] text-slate-100 truncate">{c.name}</span>
                      {c.owner_team && <Chip color="slate">{c.owner_team}</Chip>}
                      {p.overdue && <Chip color="red">Overdue</Chip>}
                      {p.complete && <Chip color="green">Complete</Chip>}
                      {p.regressions > 0 && <Chip color="orange">{p.regressions} regression{p.regressions>1?"s":""}</Chip>}
                    </button>
                    <div className="flex items-center gap-3 shrink-0">
                      <span className="text-[12px] text-slate-400">{p.patched}/{p.total} patched</span>
                      {c.due_date && <span className="text-[11px] text-slate-500">due {new Date(c.due_date).toLocaleDateString()}</span>}
                      <button onClick={() => remove(c)} className="text-slate-600 hover:text-red-400"><X size={13}/></button>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 mt-2.5">
                    <ProgressBar pct={p.percent_complete}/>
                    <span className="text-[12px] text-slate-300 w-10 text-right">{p.percent_complete}%</span>
                  </div>
                </div>
                {expanded === c.id && (
                  <div className="border-t border-[#30363D] p-3 max-h-72 overflow-y-auto">
                    {!detail ? <div className="text-[12px] text-slate-500">Loading…</div> : (
                      <table className="w-full text-[12px]">
                        <thead><tr className="text-left text-slate-500 text-[10.5px] uppercase tracking-wider">
                          <th className="py-1 px-2">Finding</th><th className="py-1 px-2">CVE/QID</th>
                          <th className="py-1 px-2">Severity</th><th className="py-1 px-2">Asset</th><th className="py-1 px-2">Status</th></tr></thead>
                        <tbody>
                          {(detail.findings || []).map(f => (
                            <tr key={f.id} className="border-t border-[#30363D]/60">
                              <td className="py-1 px-2 text-slate-200">{f.title}</td>
                              <td className="py-1 px-2 text-slate-400 font-mono">{f.cve || f.qid || "—"}</td>
                              <td className="py-1 px-2 text-slate-400">{f.severity}</td>
                              <td className="py-1 px-2 text-slate-400">{f.asset_hostname || "—"}</td>
                              <td className="py-1 px-2">{f.status}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </Layout>
  );
}

function AlertCard({ tone, icon: Icon, label, items, render }) {
  const c = tone === "red" ? "text-red-300 border-red-500/30 bg-red-500/[0.04]"
    : tone === "amber" ? "text-amber-300 border-amber-500/30 bg-amber-500/[0.04]"
    : "text-emerald-300 border-emerald-500/30 bg-emerald-500/[0.04]";
  return (
    <div className={`border rounded-md p-3 ${c}`}>
      <div className="flex items-center gap-1.5 text-[12px] font-medium mb-1"><Icon size={14}/> {label} ({items.length})</div>
      <ul className="text-[11.5px] text-slate-400 space-y-0.5">
        {items.slice(0,4).map((x,i) => <li key={i} className="truncate">{render(x)}</li>)}
        {items.length === 0 && <li className="text-slate-600">None</li>}
      </ul>
    </div>
  );
}

function CreateModal({ onClose, onCreated }) {
  const [name, setName] = useState("");
  const [team, setTeam] = useState("");
  const [due, setDue] = useState("");
  const [sev, setSev] = useState([]);
  const [kev, setKev] = useState(false);
  const [busy, setBusy] = useState(false);
  const toggleSev = (x) => setSev(s => s.includes(x) ? s.filter(y=>y!==x) : [...s, x]);
  const create = async () => {
    if (!name.trim()) { toast.error("Name required"); return; }
    const filter = {};
    if (team) filter.owner_team = team;
    if (sev.length) filter.severity = sev;
    if (kev) filter.kev = true;
    if (!Object.keys(filter).length) { toast.error("Pick at least one filter to populate the campaign"); return; }
    setBusy(true);
    try {
      await api.post("/v1/remediation-campaigns", {
        name: name.trim(), owner_team: team || null,
        due_date: due ? new Date(due).toISOString() : null, filter });
      toast.success("Campaign created"); onCreated();
    } catch (e) { toast.error(e.response?.data?.detail || "Create failed"); }
    finally { setBusy(false); }
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4" onClick={onClose}>
      <div className="w-full max-w-md bg-[#0D1117] border border-[#30363D] rounded-lg p-5" onClick={e=>e.stopPropagation()}>
        <div className="text-[15px] text-slate-100 font-medium mb-3">New remediation campaign</div>
        <label className="block text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-1">Name</label>
        <input value={name} onChange={e=>setName(e.target.value)} className="w-full h-8 px-2 mb-3 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/>
        <div className="grid grid-cols-2 gap-3 mb-3">
          <div><label className="block text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-1">Owner team</label>
            <input value={team} onChange={e=>setTeam(e.target.value)} placeholder="e.g. SecOps" className="w-full h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/></div>
          <div><label className="block text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-1">Due date</label>
            <input type="date" value={due} onChange={e=>setDue(e.target.value)} className="w-full h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/></div>
        </div>
        <label className="block text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-1">Scope (which findings)</label>
        <div className="flex gap-1.5 flex-wrap mb-2">
          {["Critical","High","Medium","Low"].map(x => (
            <button key={x} onClick={()=>toggleSev(x)} className={`h-7 px-2.5 text-[11.5px] rounded border ${sev.includes(x)?"border-blue-500/40 bg-blue-500/15 text-blue-300":"border-[#30363D] text-slate-400"}`}>{x}</button>
          ))}
          <button onClick={()=>setKev(v=>!v)} className={`h-7 px-2.5 text-[11.5px] rounded border ${kev?"border-red-500/40 bg-red-500/10 text-red-200":"border-[#30363D] text-slate-400"}`}>KEV only</button>
        </div>
        <div className="text-[11px] text-slate-500 mb-4">Members are snapshotted from these filters now; progress then tracks their live status.</div>
        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="h-8 px-3 text-[12px] text-slate-400 hover:text-slate-200 rounded border border-[#30363D]">Cancel</button>
          <button onClick={create} disabled={busy} className="h-8 px-4 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">{busy?"Creating…":"Create"}</button>
        </div>
      </div>
    </div>
  );
}
