import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Link } from "react-router-dom";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip, SevBadge } from "@/components/Badges";
import TeamCombobox from "@/components/TeamCombobox";
import { useAuth } from "@/lib/auth";
import { parseSearch, matchFinding, facetMatch, SEARCH_OPERATOR_HINT } from "@/lib/findingSearch";
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, Cell, LineChart, Line, Legend,
} from "recharts";
import {
  Target, Warning, ArrowClockwise, CheckCircle, Plus, X, CaretDown, CaretLeft,
  ClockCounterClockwise, NotePencil, Paperclip, LinkSimple, ArrowSquareOut,
} from "@phosphor-icons/react";

const SEVS = ["Critical", "High", "Medium", "Low"];
const STATUSES = ["New","Needs triage","Valid","Fixed pending validation","Fixed validated","Mitigated","Accepted risk","Reopened"];
const EXPLOIT = [["kev","KEV"],["active_attacks","Active attacks"],["public_exploit","Public exploit"],["epss_high","EPSS ≥ 0.5"]];
const RESOLVED = ["Fixed validated","Mitigated","False positive","Duplicate","Accepted risk","Closed administratively"];
const VERIFIED = ["Fixed validated"]; const ACCEPTED = ["Accepted risk"];
// "Patched" = a remediation was applied, INCLUDING provisional "Fixed pending
// validation" (mirrors backend PATCHED_STATUSES). "Verified" is the stricter gate.
// REMAINING_OPEN = still-to-do work (does NOT count pending-validation as open).
const PATCHED = ["Fixed pending validation","Fixed validated","Mitigated","Closed administratively"];
const REMAINING_OPEN = ["New","Needs triage","Valid","Reopened"];

// Client-side progress over a BASELINE (findings open at add-time), so the Admin
// vs My-work toggle can rescope stats/groups without another round-trip.
function ageDays(f) {
  if (!f.first_seen_at || !REMAINING_OPEN.includes(f.status)) return null;
  return Math.round((Date.now() - new Date(f.first_seen_at).getTime()) / 86400000);
}
function progressOf(findings, baseline) {
  const scope = baseline ? findings.filter(f => baseline.has(f.id)) : findings;
  const patched = scope.filter(f => PATCHED.includes(f.status)).length;
  const verified = scope.filter(f => VERIFIED.includes(f.status)).length;
  const accepted = scope.filter(f => ACCEPTED.includes(f.status)).length;
  const open = scope.filter(f => REMAINING_OPEN.includes(f.status)).length;
  const regressions = scope.filter(f => f.status === "Reopened").length;
  const total = scope.length;
  const now = Date.now();
  const ages = scope.filter(f => REMAINING_OPEN.includes(f.status) && f.first_seen_at)
    .map(f => (now - new Date(f.first_seen_at).getTime()) / 86400000);
  return {
    total, patched, verified, accepted, open, regressions,
    unverified_resolved: patched - verified,
    percent_complete: total ? Math.round(100 * patched / total) : 0,
    percent_verified: total ? Math.round(100 * verified / total) : 0,
    aging_over_30d: ages.filter(a => a > 30).length,
    avg_open_age_days: ages.length ? Math.round(ages.reduce((a,b)=>a+b,0)/ages.length) : 0,
    max_open_age_days: ages.length ? Math.round(Math.max(...ages)) : 0,
  };
}
function groupBreak(findings, by, baseline) {
  const keyer = by === "device" ? (f => f.asset_hostname || f.asset_id || "Unknown host")
    : by === "vulnerability" ? (f => f.cve || f.title || "Unknown vuln")
    : (f => f.owner_team || "Unassigned");
  const g = {};
  findings.forEach(f => { (g[keyer(f)] = g[keyer(f)] || []).push(f); });
  return Object.entries(g).map(([key, fs]) => ({ key, ...progressOf(fs, baseline) }))
    .sort((a,b) => (b.open - a.open) || (b.total - a.total));
}

function Typeahead({ label, field, selected, onChange }) {
  const [q, setQ] = useState(""); const [opts, setOpts] = useState([]); const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!q) { setOpts([]); return; }
    let live = true;
    const t = setTimeout(() => {
      api.get("/v1/findings/suggest", { params: { field, q, limit: 12 } })
        .then(r => { if (live) setOpts((r.data.items||[]).filter(o => !selected.includes(o))); }).catch(()=>{});
    }, 180);
    return () => { live = false; clearTimeout(t); };
  }, [q, field, selected]);
  const add = (v) => { onChange([...selected, v]); setQ(""); setOpts([]); setOpen(false); };
  return (
    <div>
      <div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1">{label}</div>
      {selected.length > 0 && <div className="flex flex-wrap gap-1 mb-1">
        {selected.map(v => <span key={v} className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[11px] rounded bg-blue-500/15 border border-blue-500/30 text-blue-200">{v}<button onClick={()=>onChange(selected.filter(x=>x!==v))} className="text-blue-300/70 hover:text-red-300"><X size={9}/></button></span>)}
      </div>}
      <div className="relative">
        <input value={q} onChange={e=>{setQ(e.target.value);setOpen(true);}} onFocus={()=>setOpen(true)}
          placeholder={`Type to search ${label.toLowerCase()}…`}
          className="w-full h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/>
        {open && opts.length > 0 && (
          <div className="absolute z-20 mt-1 w-full max-h-48 overflow-y-auto bg-[#161B22] border border-[#30363D] rounded-md p-1">
            {opts.map(o => <button key={o} onClick={()=>add(o)} className="block w-full text-left px-2 py-1.5 text-[12px] text-slate-200 hover:bg-slate-800/50 rounded truncate">{o}</button>)}
          </div>
        )}
      </div>
    </div>
  );
}

function Dropdown({ label, options, selected, onChange }) {
  const [open, setOpen] = useState(false);
  const count = selected.length;
  return (
    <div className="relative">
      <button type="button" onClick={()=>setOpen(o=>!o)}
        className={`h-8 w-full px-2 text-[12px] rounded border flex items-center justify-between ${count?"border-blue-500/40 bg-blue-500/10 text-blue-200":"border-[#30363D] text-slate-300"}`}>
        <span className="truncate">{count ? `${count} selected` : label}</span><CaretDown size={12}/>
      </button>
      {open && <>
        <div className="fixed inset-0 z-10" onClick={()=>setOpen(false)}/>
        <div className="absolute z-20 mt-1 w-full max-h-52 overflow-y-auto bg-[#161B22] border border-[#30363D] rounded-md p-1">
          {options.length===0 && <div className="px-2 py-1.5 text-[11.5px] text-slate-500">No options</div>}
          {options.map(o => { const on=selected.includes(o); return (
            <label key={o} className="flex items-center gap-2 px-2 py-1.5 text-[12px] cursor-pointer hover:bg-slate-800/40 rounded">
              <input type="checkbox" checked={on} onChange={()=>onChange(on?selected.filter(x=>x!==o):[...selected,o])}/>
              <span className={on?"text-blue-200":"text-slate-300"}>{o}</span>
            </label>
          );})}
        </div>
      </>}
    </div>
  );
}

function Bar2({ pct }) {
  const color = pct >= 100 ? "bg-emerald-500" : pct >= 50 ? "bg-blue-500" : "bg-amber-500";
  return <div className="h-2 w-full bg-[#161B22] rounded-full overflow-hidden"><div className={`h-full ${color}`} style={{width:`${Math.min(100,pct)}%`}}/></div>;
}

function MultiChips({ label, options, selected, onChange }) {
  return (
    <div>
      <div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1">{label}</div>
      <div className="flex flex-wrap gap-1.5">
        {options.map(o => {
          const [id, lbl] = Array.isArray(o) ? o : [o, o];
          const on = selected.includes(id);
          return <button key={id} type="button" onClick={()=>onChange(on?selected.filter(x=>x!==id):[...selected,id])}
            className={`h-7 px-2.5 text-[11.5px] rounded border ${on?"border-blue-500/40 bg-blue-500/15 text-blue-300":"border-[#30363D] text-slate-400"}`}>{lbl}</button>;
        })}
      </div>
    </div>
  );
}

function ReportModal({ report, onClose }) {
  const p = report.progress || {};
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4 print:bg-white" onClick={onClose}>
      <div className="w-full max-w-2xl bg-[#0D1117] border border-[#30363D] rounded-lg p-6 max-h-[85vh] overflow-y-auto print:bg-white print:text-black" onClick={e=>e.stopPropagation()} id="campaign-report">
        <div className="flex items-center justify-between mb-3">
          <div>
            <div className="text-[16px] text-slate-100 font-semibold print:text-black">{report.name}</div>
            <div className="text-[11px] text-slate-500">{report.owner_team||"—"} · {report.status} · generated {new Date(report.generated_at).toLocaleString()}</div>
          </div>
          <div className="print:hidden flex gap-2">
            <button onClick={()=>window.print()} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">Print / Save PDF</button>
            <button onClick={onClose} className="h-8 px-3 text-[12px] text-slate-400 rounded border border-[#30363D]">Close</button>
          </div>
        </div>
        <div className="grid grid-cols-4 gap-2 mb-4">
          {[["To patch",p.total],["Patched",p.patched],["Verified",p.verified],["Open",p.open]].map(([k,v])=>(
            <div key={k} className="border border-[#30363D] rounded p-2"><div className="text-[10px] uppercase text-slate-500">{k}</div><div className="text-[18px] text-slate-100 print:text-black">{v}</div></div>
          ))}
        </div>
        <div className="text-[12px] text-slate-300 print:text-black mb-1">{p.percent_complete}% complete · {p.regressions||0} regressions · {p.aging_over_30d||0} aging &gt;30d{p.overdue?" · OVERDUE":""}</div>
        {(report.exceptions||[]).length>0 && <div className="text-[12px] text-amber-300 mb-2">{report.exceptions.length} exception(s) filed</div>}
        <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mt-3 mb-1">By team</div>
        <div className="text-[12px] text-slate-300 print:text-black">{(report.groups?.team||[]).map(g=>`${g.key}: ${g.patched}/${g.total}`).join(" · ")||"—"}</div>
        <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mt-3 mb-1">Recent timeline</div>
        <ul className="text-[12px] text-slate-300 print:text-black list-disc ml-4">
          {(report.timeline||[]).slice(-8).reverse().map((e,i)=><li key={i}>{(e.at||"").slice(0,10)} — {e.type}: {e.detail}</li>)}
        </ul>
      </div>
    </div>
  );
}

function RecurringModal({ onClose, onChange }) {
  const [items, setItems] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [name, setName] = useState("Monthly patch {month}");
  const [tpl, setTpl] = useState("");
  const [cadence, setCadence] = useState("monthly");
  const [dueDays, setDueDays] = useState(30);
  const [assignees, setAssignees] = useState("");
  const load = () => api.get("/v1/remediation-campaigns/recurring").then(r=>setItems(r.data.items||[])).catch(()=>{});
  useEffect(()=>{ load(); api.get("/v1/remediation-campaigns/scope-templates").then(r=>setTemplates(r.data.items||[])).catch(()=>{}); },[]);
  const create = async () => {
    const t = templates.find(x=>x.id===tpl);
    if (!t) { toast.error("Pick a saved scope template"); return; }
    await api.post("/v1/remediation-campaigns/recurring", { name_template:name.trim()||"Recurring {month}", scope:t.filter,
      cadence, due_days:Number(dueDays)||30, assignees:assignees.split(",").map(x=>x.trim()).filter(Boolean) });
    toast.success("Recurring campaign scheduled"); setAssignees(""); load(); onChange && onChange();
  };
  const runNow = async (r) => { const x=await api.post(`/v1/remediation-campaigns/recurring/${r.id}/run-now`); toast.success(`Created a campaign (${x.data.findings} findings)`); onChange && onChange(); load(); };
  const del = async (r) => { if(!window.confirm(`Delete recurring "${r.name_template}"?`))return; await api.delete(`/v1/remediation-campaigns/recurring/${r.id}`); load(); };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4" onClick={onClose}>
      <div className="w-full max-w-2xl bg-[#0D1117] border border-[#30363D] rounded-lg p-5 max-h-[85vh] overflow-y-auto" onClick={e=>e.stopPropagation()}>
        <div className="text-[15px] text-slate-100 font-medium mb-3">Recurring campaigns</div>
        <div className="border border-[#30363D] rounded-md p-3 mb-4">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-2">Schedule a new one</div>
          <div className="grid grid-cols-2 gap-3">
            <div><div className="text-[10.5px] text-slate-500 mb-1">Name template</div><input value={name} onChange={e=>setName(e.target.value)} className="w-full h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/></div>
            <div><div className="text-[10.5px] text-slate-500 mb-1">Scope template</div>
              <select value={tpl} onChange={e=>setTpl(e.target.value)} className="w-full h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"><option value="">Pick…</option>{templates.map(t=><option key={t.id} value={t.id}>{t.name}</option>)}</select></div>
            <div><div className="text-[10.5px] text-slate-500 mb-1">Cadence</div><select value={cadence} onChange={e=>setCadence(e.target.value)} className="w-full h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"><option value="monthly">Monthly</option><option value="weekly">Weekly</option></select></div>
            <div><div className="text-[10.5px] text-slate-500 mb-1">Due in (days)</div><input type="number" value={dueDays} onChange={e=>setDueDays(e.target.value)} className="w-full h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/></div>
          </div>
          <div className="mt-2"><div className="text-[10.5px] text-slate-500 mb-1">Assignees (comma emails)</div><input value={assignees} onChange={e=>setAssignees(e.target.value)} className="w-full h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/></div>
          {templates.length===0 && <div className="text-[11px] text-amber-300 mt-2">Save a scope template first (in New campaign → Save scope).</div>}
          <div className="flex justify-end mt-3"><button onClick={create} className="h-8 px-4 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">Schedule</button></div>
        </div>
        <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-2">Scheduled ({items.length})</div>
        <div className="space-y-2">
          {items.map(r=>(
            <div key={r.id} className="border border-[#30363D] rounded p-2.5 flex items-center justify-between gap-2">
              <div className="min-w-0">
                <div className="text-[12.5px] text-slate-200 truncate">{r.name_template}</div>
                <div className="text-[11px] text-slate-500">{r.cadence} · next {(r.next_run_at||"").slice(0,10)} · due in {r.due_days}d{r.active?"":" · paused"}</div>
              </div>
              <div className="flex gap-2 shrink-0">
                <button onClick={()=>runNow(r)} className="h-7 px-2.5 text-[11.5px] rounded border border-[#30363D] text-blue-300">Run now</button>
                <button onClick={()=>del(r)} className="h-7 px-2 text-slate-500 hover:text-red-400"><X size={13}/></button>
              </div>
            </div>
          ))}
          {items.length===0 && <div className="text-[12px] text-slate-500">None scheduled.</div>}
        </div>
        <div className="flex justify-end mt-4"><button onClick={onClose} className="h-8 px-3 text-[12px] text-slate-400 rounded border border-[#30363D]">Close</button></div>
      </div>
    </div>
  );
}


export default function RemediationCampaigns() {
  const [selected, setSelected] = useState(null);
  if (selected) return <CampaignDetail id={selected} onBack={()=>setSelected(null)} />;
  return <CampaignList onOpen={setSelected} />;
}

function CampaignList({ onOpen }) {
  const { user } = useAuth();
  const [items, setItems] = useState([]);
  const [alerts, setAlerts] = useState(null);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [mine, setMine] = useState(false);
  const [workload, setWorkload] = useState(null);
  const [recurringOpen, setRecurringOpen] = useState(false);
  const load = async () => {
    setLoading(true);
    try {
      const [r, al] = await Promise.all([
        api.get("/v1/remediation-campaigns", { params: mine ? { mine: true } : {} }),
        api.get("/v1/remediation-campaigns/alerts"),
      ]);
      setItems(r.data.items || []); setAlerts(al.data);
    } catch { toast.error("Failed to load campaigns"); } finally { setLoading(false); }
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [mine]);
  const notify = async () => { const r = await api.post("/v1/remediation-campaigns/notify"); toast.success(`${r.data.sent} alert(s) sent to Notifications`); };

  return (
    <Layout title="Remediation Campaigns" subtitle="Patch tracker — progress auto-driven by scanner status; no more weekly spreadsheet"
      actions={<>
        <div className="flex items-center border border-[#30363D] rounded overflow-hidden">
          <button onClick={()=>setMine(false)} className={`px-3 h-8 text-[12px] ${!mine?"bg-blue-500/15 text-blue-300":"text-slate-400"}`}>All</button>
          <button onClick={()=>setMine(true)} className={`px-3 h-8 text-[12px] ${mine?"bg-blue-500/15 text-blue-300":"text-slate-400"}`}>My work</button>
        </div>
        <button onClick={()=>{ if(workload===null) api.get("/v1/remediation-campaigns/workload").then(r=>setWorkload(r.data.items||[])).catch(()=>{}); else setWorkload(null); }}
          className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded text-slate-300">Workload</button>
        <button onClick={notify} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded text-slate-300">Send alerts</button>
        <button onClick={()=>setRecurringOpen(true)} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded text-slate-300">Recurring</button>
        <button onClick={()=>setOpen(true)} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5"><Plus size={14}/> New campaign</button>
      </>}>
      {open && <CreateModal onClose={()=>setOpen(false)} onCreated={()=>{setOpen(false);load();}} />}
      {recurringOpen && <RecurringModal onClose={()=>setRecurringOpen(false)} onChange={load} />}
      {alerts && (alerts.overdue.length||alerts.regressions.length||alerts.newly_complete.length)>0 && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
          <AlertCard tone="red" icon={Warning} label="Overdue" items={alerts.overdue} render={x=>`${x.name} · ${x.open} open`} onOpen={onOpen}/>
          <AlertCard tone="amber" icon={ArrowClockwise} label="Regressions" items={alerts.regressions} render={x=>`${x.name} · ${x.regressions} reopened`} onOpen={onOpen}/>
          <AlertCard tone="green" icon={CheckCircle} label="Newly complete" items={alerts.newly_complete} render={x=>x.name} onOpen={onOpen}/>
        </div>
      )}
      {workload && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3 mb-4 max-w-3xl">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-2">Assignee workload (open campaigns)</div>
          {workload.length===0 ? <div className="text-[12px] text-slate-500">No assignees on open campaigns.</div> :
          <table className="w-full text-[12px]"><thead><tr className="text-left text-slate-500 text-[10.5px] uppercase tracking-wider"><th className="py-1 pr-3">Assignee</th><th className="py-1 pr-3">Campaigns</th><th className="py-1 pr-3">Open findings</th><th className="py-1">Overdue</th></tr></thead>
          <tbody>{workload.map(w=>(<tr key={w.assignee} className="border-t border-[#30363D]/50"><td className="py-1 pr-3 text-slate-200">{w.assignee}</td><td className="py-1 pr-3 text-slate-300">{w.campaigns}</td><td className="py-1 pr-3 text-slate-300">{w.open}</td><td className="py-1">{w.overdue_campaigns>0?<span className="text-red-300">{w.overdue_campaigns}</span>:<span className="text-slate-500">0</span>}</td></tr>))}</tbody></table>}
        </div>
      )}
      {loading ? <div className="text-[12px] text-slate-500">Loading…</div>
       : items.length===0 ? <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-8 text-center text-[12.5px] text-slate-500">No campaigns yet.</div>
       : <div className="space-y-2 max-w-5xl">
          {items.map(c => { const p=c.progress; return (
            <button key={c.id} onClick={()=>onOpen(c.id)} className="w-full text-left border border-[#30363D] bg-[#0D1117] hover:border-[#484F58] rounded-md p-3.5">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2 min-w-0">
                  <Target size={16} className="text-blue-400 shrink-0"/>
                  <span className="text-[13.5px] text-slate-100 truncate">{c.name}</span>
                  {c.owner_team && <Chip color="slate">{c.owner_team}</Chip>}
                  {c.status==="closed" ? <Chip color="green">Closed</Chip> : p.overdue && <Chip color="red">Overdue</Chip>}
                  {p.regressions>0 && <Chip color="orange">{p.regressions} regression{p.regressions>1?"s":""}</Chip>}
                  {p.aging_over_30d>0 && <Chip color="amber">{p.aging_over_30d} aging &gt;30d</Chip>}
                </div>
                <div className="flex items-center gap-3 shrink-0 text-[12px] text-slate-400">
                  <span>{p.patched}/{p.total} patched</span>
                  {c.due_date && <span className="text-[11px] text-slate-500">due {new Date(c.due_date).toLocaleDateString()}</span>}
                </div>
              </div>
              <div className="flex items-center gap-2 mt-2.5"><Bar2 pct={p.percent_complete}/><span className="text-[12px] text-slate-300 w-10 text-right">{p.percent_complete}%</span></div>
            </button>
          );})}
         </div>}
    </Layout>
  );
}

function AlertCard({ tone, icon:Icon, label, items, render, onOpen }) {
  const cls = tone==="red"?"text-red-300 border-red-500/30 bg-red-500/[0.04]":tone==="amber"?"text-amber-300 border-amber-500/30 bg-amber-500/[0.04]":"text-emerald-300 border-emerald-500/30 bg-emerald-500/[0.04]";
  return <div className={`border rounded-md p-3 ${cls}`}>
    <div className="flex items-center gap-1.5 text-[12px] font-medium mb-1"><Icon size={14}/> {label} ({items.length})</div>
    <ul className="text-[11.5px] text-slate-400 space-y-0.5">
      {items.slice(0,4).map((x,i)=><li key={i}><button onClick={()=>onOpen(x.id)} className="hover:underline text-left truncate">{render(x)}</button></li>)}
      {items.length===0 && <li className="text-slate-600">None</li>}
    </ul>
  </div>;
}

function CreateModal({ onClose, onCreated }) {
  const [name,setName]=useState(""); const [team,setTeam]=useState(""); const [due,setDue]=useState("");
  const [assignees,setAssignees]=useState([]); const [users,setUsers]=useState([]); const [busy,setBusy]=useState(false);
  const [sev,setSev]=useState([]); const [status,setStatus]=useState([]); const [exp,setExp]=useState([]);
  const [tags,setTags]=useState([]); const [devtype,setDevtype]=useState([]); const [q,setQ]=useState("");
  const [kev,setKev]=useState(false); const [inet,setInet]=useState(false);
  const [facets,setFacets]=useState({available_tags:[],available_asset_types:[]});
  const [cveSel,setCveSel]=useState([]); const [qidSel,setQidSel]=useState([]); const [hostSel,setHostSel]=useState([]); const [titleSel,setTitleSel]=useState([]);
  const [reqVerify,setReqVerify]=useState(true); const [mwStart,setMwStart]=useState(""); const [mwEnd,setMwEnd]=useState(""); const [chg,setChg]=useState("");
  const [preview,setPreview]=useState(null); const [templates,setTemplates]=useState([]);
  useEffect(()=>{api.get("/v1/findings/stats").then(r=>setFacets(r.data)).catch(()=>{});
    api.get("/v1/remediation-campaigns/assignable-users").then(r=>setUsers(r.data.items||[])).catch(()=>{});
    loadTemplates();},[]);
  const loadTemplates=()=>api.get("/v1/remediation-campaigns/scope-templates").then(r=>setTemplates(r.data.items||[])).catch(()=>{});
  const buildFilter=()=>{
    const f={};
    if(sev.length)f.severity=sev; if(status.length)f.status=status; if(exp.length)f.exploitability=exp;
    if(tags.length)f.tags=tags; if(devtype.length)f.asset_type=devtype;
    if(q.trim())f.q=q.trim(); if(kev)f.kev=true; if(inet)f.internet_facing=true; if(team)f.owner_team=team;
    if(cveSel.length)f.cve=cveSel; if(qidSel.length)f.qid=qidSel; if(hostSel.length)f.hostname=hostSel; if(titleSel.length)f.title=titleSel;
    return f;
  };
  const scopeKey=[sev,status,exp,tags,devtype,cveSel,qidSel,hostSel,titleSel].map(x=>x.join(",")).join("|")+`|${q}|${kev}|${inet}|${team}`;
  useEffect(()=>{
    const f=buildFilter();
    if(!Object.keys(f).length){setPreview(null);return;}
    let live=true; const t=setTimeout(()=>{
      api.post("/v1/remediation-campaigns/preview",{findings_filter:f}).then(r=>{if(live)setPreview(r.data);}).catch(()=>{});
    },300);
    return ()=>{live=false;clearTimeout(t);};
  /* eslint-disable-next-line */ },[scopeKey]);
  const applyTemplate=(tpl)=>{
    const f=tpl.filter||{};
    setSev(f.severity||[]); setStatus(f.status||[]); setExp(f.exploitability||[]);
    setTags(f.tags||[]); setDevtype(f.asset_type||[]); setQ(f.q||""); setKev(!!f.kev); setInet(!!f.internet_facing);
    setTeam(f.owner_team||""); setCveSel(f.cve||[]); setQidSel(f.qid||[]); setHostSel(f.hostname||[]); setTitleSel(f.title||[]);
    toast.success(`Loaded scope "${tpl.name}"`);
  };
  const saveTemplate=async()=>{
    const nm=window.prompt("Save this scope as a template named:"); if(!nm||!nm.trim())return;
    await api.post("/v1/remediation-campaigns/scope-templates",{name:nm.trim(),filter:buildFilter()});
    toast.success("Scope template saved"); loadTemplates();
  };
  const create=async()=>{
    if(!name.trim()){toast.error("Name required");return;}
    const f=buildFilter();
    if(!Object.keys(f).length){toast.error("Pick at least one filter so the campaign has members");return;}
    setBusy(true);
    try{
      await api.post("/v1/remediation-campaigns",{name:name.trim(),owner_team:team||null,
        due_date:due?new Date(due).toISOString():null,
        assignees:assignees,
        require_verification:reqVerify,
        maintenance_window:(mwStart&&mwEnd)?{start:new Date(mwStart).toISOString(),end:new Date(mwEnd).toISOString()}:null,
        change_ticket:chg.trim()||null,
        findings_filter:f});
      toast.success("Campaign created"); onCreated();
    }catch(e){toast.error(e.response?.data?.detail||"Create failed");}finally{setBusy(false);}
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4" onClick={onClose}>
      <div className="w-full max-w-2xl bg-[#0D1117] border border-[#30363D] rounded-lg p-5 max-h-[90vh] overflow-y-auto" onClick={e=>e.stopPropagation()}>
        <div className="text-[15px] text-slate-100 font-medium mb-3">New remediation campaign</div>
        <div className="grid grid-cols-2 gap-3 mb-3">
          <div><label className="block text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1">Name</label>
            <input value={name} onChange={e=>setName(e.target.value)} className="w-full h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/></div>
          <div><label className="block text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1">Due date</label>
            <input type="date" value={due} onChange={e=>setDue(e.target.value)} className="w-full h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/></div>
          <div><label className="block text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1">Owner team</label>
            <TeamCombobox value={team} onChange={setTeam} placeholder="Select team…"/></div>
          <div><label className="block text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1">Assignees</label>
            <Dropdown label="Pick users…" options={users.map(u=>u.email)} selected={assignees} onChange={setAssignees}/></div>
        </div>
        <div className="border-t border-[#30363D] pt-3 mb-1 text-[10.5px] uppercase tracking-wider font-mono text-slate-500">Scope — same filters as the Findings tab</div>
        <div className="flex items-center gap-2 my-2">
          <select onChange={e=>{const t=templates.find(x=>x.id===e.target.value); if(t)applyTemplate(t); e.target.value="";}} className="h-7 bg-[#161B22] border border-[#30363D] rounded px-2 text-[11.5px] text-slate-300">
            <option value="">Load scope template…</option>{templates.map(t=><option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
          <button type="button" onClick={saveTemplate} className="h-7 px-2.5 text-[11.5px] rounded border border-dashed border-[#30363D] text-blue-300">+ Save scope</button>
          {preview && <span className="ml-auto text-[12px] text-slate-300">Preview: <b className="text-blue-300">{preview.to_patch}</b> to patch{preview.already_resolved>0?` (+${preview.already_resolved} already resolved)`:""} · {preview.total} total</span>}
        </div>
        <input value={q} onChange={e=>setQ(e.target.value)} placeholder='Free-text search — supports qid: cve: owner: source: entity:' className="w-full h-8 px-2 my-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/>
        <div className="grid grid-cols-2 gap-3 mb-2">
          <Typeahead label="Vulnerability" field="title" selected={titleSel} onChange={setTitleSel}/>
          <Typeahead label="Device" field="hostname" selected={hostSel} onChange={setHostSel}/>
          <Typeahead label="CVE-ID" field="cve" selected={cveSel} onChange={setCveSel}/>
          <Typeahead label="QID" field="qid" selected={qidSel} onChange={setQidSel}/>
        </div>
        <div className="space-y-2.5">
          <MultiChips label="Severity" options={SEVS} selected={sev} onChange={setSev}/>
          <MultiChips label="Status" options={STATUSES} selected={status} onChange={setStatus}/>
          <MultiChips label="Exploitability" options={EXPLOIT} selected={exp} onChange={setExp}/>
          <div className="grid grid-cols-2 gap-3">
            <div><div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1">Device type</div>
              <Dropdown label="Any device type" options={facets.available_asset_types||[]} selected={devtype} onChange={setDevtype}/></div>
            <div><div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1">Tags</div>
              <Dropdown label="Any tag" options={facets.available_tags||[]} selected={tags} onChange={setTags}/></div>
          </div>
          <div className="flex gap-1.5">
            <button onClick={()=>setKev(v=>!v)} className={`h-7 px-2.5 text-[11.5px] rounded border ${kev?"border-red-500/40 bg-red-500/10 text-red-200":"border-[#30363D] text-slate-400"}`}>KEV only</button>
            <button onClick={()=>setInet(v=>!v)} className={`h-7 px-2.5 text-[11.5px] rounded border ${inet?"border-amber-500/40 bg-amber-500/10 text-amber-200":"border-[#30363D] text-slate-400"}`}>Internet-facing</button>
          </div>
        </div>
        {preview && preview.total>0 && (
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3 my-2">
            <div className="flex flex-wrap gap-1.5 mb-2">
              {Object.entries(preview.by_severity).map(([k,v])=>(<span key={k} className="text-[11px] px-1.5 py-0.5 rounded bg-slate-700/40 text-slate-200">{k}: {v}</span>))}
            </div>
            <div className="max-h-32 overflow-y-auto text-[11.5px] divide-y divide-[#30363D]/50">
              {preview.sample.map(f=>(<div key={f.id} className="py-1 flex items-center gap-2"><span className="text-slate-500 w-16 truncate">{f.severity}</span><span className="text-slate-200 truncate flex-1">{f.title}</span><span className="text-slate-500 font-mono">{f.asset_hostname||""}</span></div>))}
            </div>
            <div className="text-[10.5px] text-slate-500 mt-1">Showing {preview.sample.length} of {preview.total}. Only the {preview.to_patch} open one(s) count toward progress.</div>
          </div>
        )}
        <div className="border-t border-[#30363D] mt-3 pt-3 grid grid-cols-2 gap-3">
          <div><div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1">Maintenance window start</div>
            <input type="datetime-local" value={mwStart} onChange={e=>setMwStart(e.target.value)} className="w-full h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/></div>
          <div><div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1">Maintenance window end</div>
            <input type="datetime-local" value={mwEnd} onChange={e=>setMwEnd(e.target.value)} className="w-full h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/></div>
          <div><div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1">Change ticket</div>
            <input value={chg} onChange={e=>setChg(e.target.value)} placeholder="CHG-1001" className="w-full h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/></div>
          <label className="flex items-center gap-2 text-[12px] text-slate-300 mt-5"><input type="checkbox" checked={reqVerify} onChange={e=>setReqVerify(e.target.checked)}/> Require scanner verification to close</label>
        </div>
        <div className="text-[11px] text-slate-500 my-3">Members are snapshotted from these filters now; progress then tracks their live scanner status. With verification required, the campaign only closes once a scan confirms the fixes.</div>
        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="h-8 px-3 text-[12px] text-slate-400 rounded border border-[#30363D]">Cancel</button>
          <button onClick={create} disabled={busy} className="h-8 px-4 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">{busy?"Creating…":"Create"}</button>
        </div>
      </div>
    </div>
  );
}

function CampaignDetail({ id, onBack }) {
  const { user } = useAuth();
  const isAdmin = ["admin","manager"].includes(user?.role);
  const [c, setC] = useState(null);
  const [tab, setTab] = useState("overview");
  const [mineOnly, setMineOnly] = useState(!isAdmin);
  const [sel, setSel] = useState(new Set());
  const [drill, setDrill] = useState(null);   // {by, key} group drill-in
  const [subset, setSubset] = useState(null); // KPI / risk / SLA drill-down key
  const [showHistory, setShowHistory] = useState(false); // timeline: pre-creation events
  const [fq, setFq] = useState("");        // #65 advanced search (reuses item-58 operators)
  const [fSev, setFSev] = useState([]);    // severity facet
  const [fStat, setFStat] = useState([]);  // status facet
  const [burn, setBurn] = useState([]);
  const [report, setReport] = useState(null);
  const load = async () => { try { const r = await api.get(`/v1/remediation-campaigns/${id}`); setC(r.data); } catch { toast.error("Failed to load"); } };
  useEffect(() => { load(); api.get(`/v1/remediation-campaigns/${id}/burndown`).then(r=>setBurn(r.data.series||[])).catch(()=>{}); /* eslint-disable-next-line */ }, [id]);
  if (!c) return <Layout title="Campaign"><div className="text-[12px] text-slate-500">Loading…</div></Layout>;
  const mineIds = new Set(c.mine || []);
  const baseline = new Set(c.baseline_open_ids || (c.findings||[]).map(f=>f.id));
  // Everything (stats, groups, chart) is scoped to the active view so Admin and
  // My work are genuinely different, not the same numbers on different tabs.
  const scoped = (c.findings || []).filter(f => !mineOnly || mineIds.has(f.id));
  const p = progressOf(scoped, baseline);
  const groups = { device: groupBreak(scoped,"device",baseline),
                   vulnerability: groupBreak(scoped,"vulnerability",baseline),
                   team: groupBreak(scoped,"team",baseline) };
  // findings shown on the Findings tab: scope + optional group drill-in
  const drillMatch = (f) => !drill ? true
    : drill.by==="device" ? (f.asset_hostname||f.asset_id||"Unknown host")===drill.key
    : drill.by==="vulnerability" ? (f.cve||f.title||"Unknown vuln")===drill.key
    : (f.owner_team||"Unassigned")===drill.key;
  const openGroup = (by, key) => { setDrill({by, key}); setTab("findings"); };
  // KPI / risk / SLA drill-downs -> filter the Findings tab to the findings behind
  // a tile. Scoped to the baseline (like the tiles) so the count matches.
  const _nowMs = Date.now();
  const _dueWithin = (f, n) => {
    if (!REMAINING_OPEN.includes(f.status) || !f.due_at) return false;
    const d = (new Date(f.due_at).getTime() - _nowMs) / 86400000;
    return d > 0 && d <= n;
  };
  const SUBSETS = {
    topatch:     { label: "To patch",        fn: () => true },
    patched:     { label: "Patched",         fn: f => PATCHED.includes(f.status) },
    verified:    { label: "Verified",        fn: f => VERIFIED.includes(f.status) },
    open:        { label: "Open",            fn: f => REMAINING_OPEN.includes(f.status) },
    regressions: { label: "Regressions",     fn: f => f.status === "Reopened" },
    aging30:     { label: "Aging >30d",      fn: f => REMAINING_OPEN.includes(f.status) && (ageDays(f) || 0) > 30 },
    kev:         { label: "KEV (exploited)", fn: f => REMAINING_OPEN.includes(f.status) && f.kev_flag },
    epss:        { label: "EPSS ≥ 0.5",      fn: f => REMAINING_OPEN.includes(f.status) && (f.epss_score || 0) >= 0.5 },
    overdue:     { label: "Overdue",         fn: f => REMAINING_OPEN.includes(f.status) && f.due_at && new Date(f.due_at).getTime() < _nowMs },
    due7:        { label: "Due ≤ 7d",        fn: f => _dueWithin(f, 7) },
    due14:       { label: "Due ≤ 14d",       fn: f => _dueWithin(f, 14) },
    due30:       { label: "Due ≤ 30d",       fn: f => _dueWithin(f, 30) },
  };
  const openSubset = (key) => { setDrill(null); setSubset(key); setTab("findings"); };
  const subsetMatch = (f) => !subset ? true : (baseline.has(f.id) && (SUBSETS[subset] ? SUBSETS[subset].fn(f) : true));
  const _parsedSearch = parseSearch(fq);
  const findings = scoped.filter(drillMatch).filter(subsetMatch)
    .filter(f => matchFinding(f, _parsedSearch))
    .filter(f => facetMatch(f, { severities: fSev, statuses: fStat }));
  const toggle = (fid) => { const n = new Set(sel); n.has(fid)?n.delete(fid):n.add(fid); setSel(n); };

  const massNote = async () => {
    const text = window.prompt(`Note for ${sel.size} selected finding(s):`); if (!text) return;
    await api.post(`/v1/remediation-campaigns/${id}/mass-note`, { finding_ids:[...sel], text });
    toast.success(`Noted ${sel.size} finding(s)`); setSel(new Set()); load();
  };
  const bulkStatus = async (status) => {
    if (!sel.size) return;
    await api.post(`/v1/remediation-campaigns/${id}/bulk-status`, { finding_ids:[...sel], status });
    toast.success(`${sel.size} → ${status}`); setSel(new Set()); load();
  };
  const requestExc = async () => {
    if (!sel.size) return;
    const why = window.prompt(`Can't patch these ${sel.size}? Business justification for a risk exception:`);
    if (!why || !why.trim()) return;
    const days = parseInt(window.prompt("Acceptance duration (days):", "90") || "90", 10) || 90;
    const r = await api.post(`/v1/remediation-campaigns/${id}/request-exceptions`,
      { finding_ids:[...sel], business_justification:why.trim(), duration_days:days });
    toast.success(`Filed ${r.data.requested} risk exception(s)`); setSel(new Set()); load();
  };
  const removeSel = async () => {
    if (!sel.size || !window.confirm(`Remove ${sel.size} from this campaign? (findings not deleted)`)) return;
    await api.patch(`/v1/remediation-campaigns/${id}`, { remove_finding_ids:[...sel] });
    setSel(new Set()); load();
  };
  const exportCsv = () => { window.open(`/api/v1/remediation-campaigns/${id}/export.csv`, "_blank"); };
  const quickPatch = async (fid) => {
    await api.post(`/v1/remediation-campaigns/${id}/bulk-status`, { finding_ids:[fid], status:"Fixed pending validation" });
    toast.success("Marked patched (pending validation)"); load();
  };
  const quickNote = async (fid) => {
    const t = window.prompt("Note for this finding:"); if (!t || !t.trim()) return;
    await api.post(`/v1/remediation-campaigns/${id}/mass-note`, { finding_ids:[fid], text:t.trim() });
    toast.success("Noted"); load();
  };
  const notifyAssignees = async () => {
    if (!window.confirm("Message each assignee a summary of their open queue in this campaign?")) return;
    try { const r = await api.post(`/v1/remediation-campaigns/${id}/notify-assignees`);
      toast.success(`Notified ${r.data.notified} assignee(s)` + (r.data.unassigned_open?` · ${r.data.unassigned_open} open unassigned`:"")); }
    catch { toast.error("Notify failed"); }
  };
  const openReport = async () => { try { const r = await api.get(`/v1/remediation-campaigns/${id}/report`); setReport(r.data); } catch { toast.error("Report failed"); } };
  const reassignSel = async () => {
    if (!sel.size) return;
    const who = window.prompt(`Reassign ${sel.size} finding(s) to (email):`); if (!who || !who.trim()) return;
    await api.post(`/v1/remediation-campaigns/${id}/bulk-assign`, { finding_ids:[...sel], assignee:who.trim() });
    toast.success(`Reassigned ${sel.size}`); setSel(new Set()); load();
  };
  const close = async () => {
    try { await api.post(`/v1/remediation-campaigns/${id}/close`); toast.success("Closed"); load(); }
    catch (e) {
      const msg = e.response?.data?.detail || "Close failed";
      if (window.confirm(`${msg}\n\nForce-close anyway?`)) {
        await api.post(`/v1/remediation-campaigns/${id}/close`, null, { params: { force: true } });
        toast.success("Force-closed"); load();
      } else toast.error(msg);
    }
  };

  // due-by histogram
  const dueBuckets = [{k:"Overdue",v:0},{k:"≤7d",v:0},{k:"8–30d",v:0},{k:">30d",v:0},{k:"No date",v:0}];
  const now = Date.now();
  scoped.forEach(f => {
    if (f.status && ["Fixed validated","Mitigated","Accepted risk","Duplicate","False positive"].includes(f.status)) return;
    if (!f.due_at) { dueBuckets[4].v++; return; }
    const d = (new Date(f.due_at).getTime()-now)/86400000;
    if (d<0) dueBuckets[0].v++; else if (d<=7) dueBuckets[1].v++; else if (d<=30) dueBuckets[2].v++; else dueBuckets[3].v++;
  });
  const DUE_COLORS = ["#ef4444","#f97316","#eab308","#3b82f6","#475569"];
  const ov = c.overview || {}; const vel = ov.velocity || {}; const risk = ov.risk || {};
  const exc = ov.exceptions || {}; const tix = ov.tickets || {}; const my = c.my || {};
  const fc = ov.sla_forecast || {}; const stalled = ov.stalled || {};
  const SEV = [["Critical","#ef4444"],["High","#f97316"],["Medium","#eab308"],["Low","#3b82f6"],["Info","#475569"]];
  const sevTotal = SEV.reduce((a,[k])=>a+(risk.severity?.[k]||0),0) || 1;
  const fmtDate = (d)=> d ? new Date(d).toLocaleDateString(undefined,{month:"short",day:"numeric",year:"numeric"}) : "—";
  const _capNote = vel.eta_note ? vel.eta_note.charAt(0).toUpperCase()+vel.eta_note.slice(1) : "No deadline set";
  const trackBadge = vel.on_track===true ? ["On track","text-green-300 bg-green-500/10 border-green-500/30"]
                    : vel.on_track===false ? ["Behind schedule","text-red-300 bg-red-500/10 border-red-500/30"]
                    : [_capNote,"text-slate-400 bg-slate-500/10 border-slate-500/30"];

  return (
    <Layout title={c.name} subtitle={`${p.patched}/${p.total} patched · ${p.percent_complete}% · ${c.status==="closed"?"closed":c.owner_team||"no team"}`}
      actions={<>
        {isAdmin && (
          <div className="flex items-center border border-[#30363D] rounded overflow-hidden">
            <button onClick={()=>setMineOnly(false)} className={`px-3 h-8 text-[12px] ${!mineOnly?"bg-blue-500/15 text-blue-300":"text-slate-400"}`}>Admin view</button>
            <button onClick={()=>setMineOnly(true)} className={`px-3 h-8 text-[12px] ${mineOnly?"bg-blue-500/15 text-blue-300":"text-slate-400"}`}>My work</button>
          </div>
        )}
        <button onClick={exportCsv} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Export CSV</button>
        <button onClick={openReport} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Report</button>
        {isAdmin && c.status!=="closed" && <button onClick={notifyAssignees} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Notify assignees</button>}
        {isAdmin && c.status!=="closed" && <button onClick={close} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Close</button>}
        <button onClick={onBack} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300 inline-flex items-center gap-1"><CaretLeft size={13}/> Back</button>
      </>}>

      {report && <ReportModal report={report} onClose={()=>setReport(null)}/>}
      <div className="flex items-center gap-2 mb-3 max-w-7xl">
        <Bar2 pct={p.percent_complete}/><span className="text-[12px] text-slate-300 w-10 text-right">{p.percent_complete}%</span>
      </div>
      <div className="grid grid-cols-3 md:grid-cols-6 gap-2 mb-4 max-w-7xl">
        <Stat label="To patch" value={p.total} onClick={()=>openSubset("topatch")}/>
        <Stat label="Patched" value={p.patched} tone="green" onClick={()=>openSubset("patched")}/>
        <Stat label="Verified" value={p.verified} tone="green" onClick={()=>openSubset("verified")}/>
        <Stat label="Open" value={p.open} onClick={()=>openSubset("open")}/>
        <Stat label="Regressions" value={p.regressions} tone="orange" onClick={()=>openSubset("regressions")}/>
        <Stat label="Aging >30d" value={p.aging_over_30d} tone="amber" onClick={()=>openSubset("aging30")}/>
      </div>
      {(c.maintenance_window?.start || c.change_ticket) && (
        <div className="flex items-center gap-3 mb-4 text-[11.5px] text-slate-400 max-w-7xl">
          {c.maintenance_window?.start && <span>🛠 Maintenance window: {new Date(c.maintenance_window.start).toLocaleString()} → {new Date(c.maintenance_window.end).toLocaleString()}</span>}
          {c.change_ticket && <span>· Change: <span className="text-slate-300 font-mono">{c.change_ticket}</span></span>}
        </div>
      )}

      <div className="flex gap-1 mb-3 border-b border-[#30363D] max-w-7xl">
        {[["overview","Overview"],["findings","Findings"],["timeline","Timeline"],["notes","Notes"]].map(([t,l])=>(
          <button key={t} onClick={()=>setTab(t)} className={`px-3 py-1.5 text-[12px] border-b-2 -mb-px ${tab===t?"border-blue-500 text-blue-300":"border-transparent text-slate-400 hover:text-slate-200"}`}>{l}</button>
        ))}
      </div>

      {tab==="overview" && (
        <div className="space-y-4 max-w-7xl">
          {!mineOnly && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {/* Velocity + ETA */}
              <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="text-[12px] text-slate-300">Velocity &amp; projected close</div>
                  <span className={`text-[10.5px] px-2 py-0.5 rounded border ${trackBadge[1]}`}>{trackBadge[0]}</span>
                </div>
                <div className="grid grid-cols-3 gap-3">
                  <div><div className="text-[18px] font-semibold text-slate-100">{vel.patched_per_week ?? "—"}</div><div className="text-[10.5px] text-slate-500 uppercase tracking-wide">Patched / wk</div></div>
                  <div><div className="text-[18px] font-semibold text-slate-100">{vel.eta?fmtDate(vel.eta):"—"}</div><div className="text-[10.5px] text-slate-500 uppercase tracking-wide">Projected close</div></div>
                  <div><div className={`text-[18px] font-semibold ${vel.days_to_due!=null&&vel.days_to_due<0?"text-red-300":"text-slate-100"}`}>{vel.days_to_due!=null?`${vel.days_to_due}d`:"—"}</div><div className="text-[10.5px] text-slate-500 uppercase tracking-wide">To deadline</div></div>
                </div>
                {vel.target && <div className="text-[10.5px] text-slate-500 mt-3">Deadline: {fmtDate(vel.target)} · {vel.patched_total||0} patched so far</div>}
              </div>
              {/* Risk composition */}
              <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
                <div className="text-[12px] text-slate-300 mb-3">Risk composition · {risk.open_total||0} open</div>
                <div className="flex h-2.5 w-full rounded overflow-hidden mb-2 bg-[#161b22]">
                  {SEV.map(([k,col])=>{const w=100*(risk.severity?.[k]||0)/sevTotal; return w>0?<div key={k} style={{width:`${w}%`,background:col}} title={`${k}: ${risk.severity?.[k]||0}`}/>:null;})}
                </div>
                <div className="flex flex-wrap gap-x-3 gap-y-1 text-[10.5px] mb-3">
                  {SEV.map(([k,col])=><span key={k} className="inline-flex items-center gap-1 text-slate-400"><span className="w-2 h-2 rounded-full" style={{background:col}}/>{k} {risk.severity?.[k]||0}</span>)}
                </div>
                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <button onClick={()=>openSubset("kev")} className="flex justify-between border border-[#30363D] rounded px-2 py-1 hover:border-blue-500/40 text-left"><span className="text-slate-400">KEV (exploited)</span><span className="text-red-300 font-semibold">{risk.kev_open||0}</span></button>
                  <button onClick={()=>openSubset("epss")} className="flex justify-between border border-[#30363D] rounded px-2 py-1 hover:border-blue-500/40 text-left"><span className="text-slate-400">EPSS ≥ 0.5</span><span className="text-orange-300 font-semibold">{risk.high_epss_open||0}</span></button>
                  <button onClick={()=>openSubset("overdue")} className="flex justify-between border border-[#30363D] rounded px-2 py-1 hover:border-blue-500/40 text-left"><span className="text-slate-400">Overdue</span><span className="text-red-300 font-semibold">{risk.overdue_open||0}</span></button>
                  <button onClick={()=>openSubset("due7")} className="flex justify-between border border-[#30363D] rounded px-2 py-1 hover:border-blue-500/40 text-left"><span className="text-slate-400">Due ≤ 7d</span><span className="text-amber-300 font-semibold">{risk.due_7d_open||0}</span></button>
                </div>
              </div>
            </div>
          )}
          {!mineOnly && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {/* Exceptions + tickets */}
              <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
                <div className="text-[12px] text-slate-300 mb-3">Exceptions &amp; tickets</div>
                <div className="grid grid-cols-3 gap-2 text-center mb-3">
                  <div><div className="text-[17px] font-semibold text-amber-300">{exc.pending||0}</div><div className="text-[10px] text-slate-500 uppercase">Pending</div></div>
                  <div><div className="text-[17px] font-semibold text-blue-300">{exc.active||0}</div><div className="text-[10px] text-slate-500 uppercase">Accepted</div></div>
                  <div><div className="text-[17px] font-semibold text-slate-400">{exc.denied||0}</div><div className="text-[10px] text-slate-500 uppercase">Denied</div></div>
                </div>
                <div className="text-[11px] text-slate-400 flex items-center justify-between border-t border-[#30363D] pt-2">
                  <span>Ticket coverage (open)</span>
                  <span className="text-slate-200">{tix.with_ticket||0} linked · <span className="text-slate-500">{tix.without_ticket||0} none</span></span>
                </div>
              </div>
              {/* Recent activity */}
              <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
                <div className="text-[12px] text-slate-300 mb-2">Recent activity</div>
                {(c.activity||[]).length===0 && <div className="text-[11px] text-slate-500">No activity yet.</div>}
                <div className="space-y-1.5 max-h-[150px] overflow-auto">
                  {(c.activity||[]).slice(0,8).map((a,i)=>(
                    <div key={i} className="text-[11px] flex gap-2">
                      <span className="text-slate-500 shrink-0 w-14">{a.at?new Date(a.at).toLocaleDateString(undefined,{month:"short",day:"numeric"}):""}</span>
                      <span className="text-slate-300"><span className="text-slate-400">{a.actor||"system"}</span> · {(a.detail||a.action||"").slice(0,80)}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
          {!mineOnly && (
            <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
              <div className="text-[12px] text-slate-300 mb-3">SLA-breach forecast — open findings coming due</div>
              <div className="grid grid-cols-3 gap-3">
                {[["7","Next 7 days"],["14","Next 14 days"],["30","Next 30 days"]].map(([n,lbl])=>{
                  const w = fc[n]||{};
                  return (
                    <div key={n} onClick={()=>openSubset("due"+n)} title="Click to view these findings"
                         className="border border-[#30363D] rounded p-3 cursor-pointer hover:border-blue-500/40">
                      <div className="text-[10.5px] text-slate-500 uppercase tracking-wide mb-1">{lbl}</div>
                      <div className="text-[20px] font-semibold text-slate-100">{w.due ?? 0} <span className="text-[11px] text-slate-500">due</span></div>
                      {w.at_risk!=null && <div className={`text-[11px] mt-1 ${w.at_risk>0?"text-red-300":"text-green-300"}`}>{w.at_risk>0?`~${w.at_risk} at risk at current pace`:"on pace to clear"}</div>}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
          {!mineOnly && (ov.regressions||[]).length>0 && (
            <div className="border border-orange-500/30 bg-orange-500/5 rounded-md p-4">
              <div className="text-[12px] text-orange-300 mb-2">⚠ Regressions — patched then reopened ({ov.regressions.length})</div>
              <div className="flex flex-wrap gap-2">
                {ov.regressions.map(r=>(
                  <button key={r.id} onClick={()=>{setDrill(null);setTab("findings");}} className="text-[11px] px-2 py-1 rounded border border-orange-500/30 text-slate-300 hover:bg-orange-500/10">
                    <span className="font-mono text-slate-400">{r.asset_hostname||"host"}</span> · {r.cve||r.title}
                  </button>
                ))}
              </div>
            </div>
          )}
          {!mineOnly && stalled.count>0 && (
            <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
              <div className="text-[12px] text-slate-300 mb-2">Stalled — no progress in {stalled.days}+ days ({stalled.count})</div>
              <div className="space-y-1.5 max-h-[190px] overflow-auto">
                {(stalled.items||[]).map(sv=>(
                  <button key={sv.id} onClick={()=>{setDrill(null);setTab("findings");}} className="w-full text-left text-[11.5px] flex items-center gap-2 border border-[#30363D] rounded px-2 py-1 hover:bg-slate-500/10">
                    <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{background: sv.severity==="Critical"?"#ef4444":sv.severity==="High"?"#f97316":"#eab308"}}/>
                    <span className="text-slate-200 truncate flex-1">{sv.cve||sv.title}</span>
                    <span className="text-slate-500 font-mono truncate max-w-[140px] hidden md:inline">{sv.asset_hostname||""}</span>
                    <span className="text-slate-500 shrink-0 hidden md:inline">{sv.assigned_to?sv.assigned_to.split("@")[0]:"unassigned"}</span>
                    <span className="text-amber-300 shrink-0 w-20 text-right">{fmtDate(sv.since)}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
          {mineOnly && (
            <>
              <div className="grid grid-cols-3 md:grid-cols-6 gap-2">
                <Stat label="Assigned to me" value={my.total||0}/>
                <Stat label="Patched by me" value={my.patched||0} tone="green"/>
                <Stat label="Still open" value={my.open||0}/>
                <Stat label="Overdue" value={my.overdue||0} tone="orange"/>
                <Stat label="Due ≤ 7d" value={my.due_7d||0} tone="amber"/>
                <Stat label="Soonest due" value={my.soonest_due?fmtDate(my.soonest_due):"—"}/>
              </div>
              <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
                <div className="text-[12px] text-slate-300 mb-3">My priority queue — work these next</div>
                {(my.queue||[]).length===0 && <div className="text-[11px] text-slate-500">Nothing open assigned to you. 🎉</div>}
                <div className="space-y-1.5">
                  {(my.queue||[]).map(q=>{
                    const overdue = q.due_at && new Date(q.due_at).getTime()<Date.now();
                    return (
                    <div key={q.id} className="flex items-center gap-2 text-[11.5px] border border-[#30363D] rounded px-2 py-1.5">
                      <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{background: q.priority_score>=150?"#ef4444":q.priority_score>=80?"#f97316":"#eab308"}}/>
                      <span className="text-slate-500 w-8 text-right shrink-0">{q.priority_score}</span>
                      <span className="text-slate-200 truncate flex-1">{q.cve||q.title}{q.kev_flag&&<span className="ml-1 text-[9px] px-1 rounded bg-red-500/15 text-red-300 align-middle">KEV</span>}</span>
                      <span className="text-slate-500 font-mono truncate max-w-[140px] hidden md:inline">{q.asset_hostname||""}</span>
                      <span className={`w-16 text-right shrink-0 ${overdue?"text-red-300":"text-slate-500"}`}>{q.due_at?fmtDate(q.due_at):"no date"}</span>
                      <button onClick={()=>quickPatch(q.id)} className="shrink-0 text-[10.5px] px-2 py-0.5 rounded border border-green-500/30 text-green-300 hover:bg-green-500/10">Patched</button>
                      <button onClick={()=>quickNote(q.id)} className="shrink-0 text-[10.5px] px-2 py-0.5 rounded border border-[#30363D] text-slate-300 hover:bg-slate-500/10">Note</button>
                    </div>
                  );})}
                </div>
              </div>
              {(my.by_device||[]).length>0 && (
                <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
                  <div className="text-[12px] text-slate-300 mb-3">Batch by device — clear a host in one pass</div>
                  <div className="flex flex-wrap gap-2">
                    {my.by_device.map(d=>(
                      <button key={d.host} onClick={()=>openGroup("device",d.host)} className="text-[11px] px-2.5 py-1.5 rounded border border-[#30363D] text-slate-300 hover:bg-slate-500/10 inline-flex items-center gap-2">
                        <span className="font-mono truncate max-w-[180px]">{d.host}</span>
                        <span className="text-[10px] px-1.5 rounded bg-blue-500/15 text-blue-300">{d.open} open</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
          {burn.length > 1 && (
            <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
              <div className="text-[12px] text-slate-300 mb-2">Burndown ({p.percent_verified}% verified)</div>
              <ResponsiveContainer width="100%" height={180}>
                <LineChart data={burn} margin={{top:5,right:10,left:-15,bottom:0}}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2733"/>
                  <XAxis dataKey="day" tick={{fontSize:10,fill:"#64748b"}}/><YAxis tick={{fontSize:10,fill:"#64748b"}}/>
                  <Tooltip contentStyle={{background:"#0D1117",border:"1px solid #30363D",fontSize:12}}/>
                  <Legend wrapperStyle={{fontSize:11}}/>
                  <Line type="monotone" dataKey="open" name="Still open" stroke="#f59e0b" strokeWidth={2} dot={false}/>
                  <Line type="monotone" dataKey="verified" name="Verified" stroke="#22c55e" strokeWidth={2} dot={false}/>
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="text-[12px] text-slate-300 mb-2">Due window (open findings) · avg open age {p.avg_open_age_days}d, max {p.max_open_age_days}d</div>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={dueBuckets} margin={{top:5,right:10,left:-15,bottom:0}}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2733"/>
                <XAxis dataKey="k" tick={{fontSize:11,fill:"#64748b"}}/><YAxis tick={{fontSize:10,fill:"#64748b"}}/>
                <Tooltip contentStyle={{background:"#0D1117",border:"1px solid #30363D",fontSize:12}}/>
                <Bar dataKey="v">{dueBuckets.map((_,i)=><Cell key={i} fill={DUE_COLORS[i]}/>)}</Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {[["device","By device"],["vulnerability","By vulnerability"],["team","By team"]].map(([k,lbl])=>(
              <GroupCard key={k} title={lbl} rows={groups[k]||[]} onPick={(key)=>openGroup(k,key)}/>
            ))}
          </div>
        </div>
      )}

      {tab==="findings" && (
        <div className="max-w-5xl">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <input value={fq} onChange={e=>setFq(e.target.value)} placeholder={SEARCH_OPERATOR_HINT}
              className="h-8 flex-1 min-w-[260px] bg-[#161B22] border border-[#30363D] rounded px-3 text-[12px] text-slate-100"/>
            <MultiChips label="Severity" options={SEVS} selected={fSev} onChange={setFSev}/>
            <MultiChips label="Status" options={STATUSES} selected={fStat} onChange={setFStat}/>
          </div>
          {(fq || fSev.length || fStat.length) ? (
            <div className="flex items-center gap-1.5 mb-2 flex-wrap">
              {fq && <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-200">Search: {fq}<button onClick={()=>setFq("")} className="text-blue-300/70 hover:text-red-300"><X size={10}/></button></span>}
              {fSev.map(v=><span key={"s"+v} className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-200">Severity: {v}<button onClick={()=>setFSev(fSev.filter(x=>x!==v))} className="text-blue-300/70 hover:text-red-300"><X size={10}/></button></span>)}
              {fStat.map(v=><span key={"t"+v} className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-200">Status: {v}<button onClick={()=>setFStat(fStat.filter(x=>x!==v))} className="text-blue-300/70 hover:text-red-300"><X size={10}/></button></span>)}
              <button onClick={()=>{setFq("");setFSev([]);setFStat([]);}} className="text-[11px] text-slate-500 hover:text-slate-300 underline">Clear all</button>
            </div>
          ) : null}
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            {mineOnly ? <span className="text-[11px] text-slate-500">Showing your team / assigned findings</span> : null}
            <span className="text-[11px] text-slate-500">· sorted by priority (SLA × severity × KEV × EPSS × age)</span>
            {c.findings_total > (c.findings||[]).length && <span className="text-[11px] text-amber-300">· showing top {(c.findings||[]).length} of {c.findings_total} — narrow with a group or export CSV for all</span>}
            {drill && <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-200">{drill.by}: {drill.key}<button onClick={()=>setDrill(null)} className="text-blue-300/70 hover:text-red-300"><X size={10}/></button></span>}
            {subset && <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-200">{(SUBSETS[subset]&&SUBSETS[subset].label)||subset}<button onClick={()=>setSubset(null)} className="text-blue-300/70 hover:text-red-300"><X size={10}/></button></span>}
            {sel.size>0 && <>
              <span className="text-[12px] text-slate-300">{sel.size} selected</span>
              <button onClick={massNote} className="h-7 px-2.5 text-[11.5px] rounded border border-[#30363D] text-blue-300 inline-flex items-center gap-1"><NotePencil size={12}/> Mass note</button>
              <select onChange={e=>{if(e.target.value){bulkStatus(e.target.value);e.target.value="";}}} className="h-7 bg-[#161B22] border border-[#30363D] rounded px-2 text-[11.5px] text-slate-300">
                <option value="">Set status…</option>{STATUSES.map(s=><option key={s}>{s}</option>)}
              </select>
              <button onClick={requestExc} className="h-7 px-2.5 text-[11.5px] rounded border border-amber-500/40 text-amber-200">Can&apos;t patch → exception</button>
              {isAdmin && <button onClick={reassignSel} className="h-7 px-2.5 text-[11.5px] rounded border border-[#30363D] text-emerald-300">Reassign</button>}
              {isAdmin && <button onClick={removeSel} className="h-7 px-2.5 text-[11.5px] rounded border border-[#30363D] text-red-300">Remove</button>}
            </>}
          </div>
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
            <table className="w-full text-[12px]">
              <thead><tr className="border-b border-[#30363D] text-left text-slate-500 text-[10.5px] uppercase tracking-wider">
                <th className="pl-3 pr-1 py-2 w-6"></th><th className="px-2 py-2">Finding</th><th className="px-2 py-2">CVE/QID</th>
                <th className="px-2 py-2">Sev</th><th className="px-2 py-2">Asset</th><th className="px-2 py-2">Status</th><th className="px-2 py-2">Open</th><th className="px-2 py-2">Due in</th><th className="px-2 py-2">Ticket</th><th className="px-2 py-2"></th></tr></thead>
              <tbody>
                {findings.map(f=>(
                  <tr key={f.id} className="border-b border-[#30363D]/60 hover:bg-slate-800/20">
                    <td className="pl-3 pr-1 py-1.5"><input type="checkbox" checked={sel.has(f.id)} onChange={()=>toggle(f.id)}/></td>
                    <td className="px-2 py-1.5"><span className="inline-flex items-center gap-1.5"><span title={`priority ${f.priority_score}`} className={`w-1.5 h-1.5 rounded-full inline-block ${f.priority_score>=120?"bg-red-500":f.priority_score>=70?"bg-amber-500":f.priority_score<0?"bg-slate-700":"bg-slate-500"}`}/><Link to={`/findings/${f.id}`} className="text-slate-100 hover:text-blue-300 hover:underline">{f.title}</Link></span></td>
                    <td className="px-2 py-1.5 text-slate-400 font-mono">{f.cve||f.qid||"—"}</td>
                    <td className="px-2 py-1.5"><SevBadge severity={f.severity}/></td>
                    <td className="px-2 py-1.5 text-slate-400">{f.asset_hostname||"—"}</td>
                    <td className="px-2 py-1.5 text-slate-300">{f.status}</td>
                    <td className="px-2 py-1.5 text-slate-400">{ageDays(f)!=null?`${ageDays(f)}d`:"—"}</td>
                    <td className="px-2 py-1.5">{(() => { if(!f.due_at||RESOLVED.includes(f.status))return <span className="text-slate-500">—</span>; const dd=Math.round((new Date(f.due_at).getTime()-Date.now())/86400000); return <span className={dd<0?"text-red-300":dd<=7?"text-amber-300":"text-slate-400"}>{dd<0?`${-dd}d over`:`${dd}d`}</span>; })()}</td>
                    <td className="px-2 py-1.5">{f.ticket_ref?.url ? (f.ticket_ref.url.startsWith("http") ? <a href={f.ticket_ref.url} target="_blank" rel="noreferrer" className="text-blue-300 hover:underline">{f.ticket_ref.external_id}</a> : <Link to={f.ticket_ref.url} className="text-blue-300 hover:underline">{f.ticket_ref.external_id}</Link>) : (f.ticket ? <span className="text-slate-400">{typeof f.ticket==="string"?f.ticket:(f.ticket.key||f.ticket.id||"linked")}</span> : <span className="text-slate-500">—</span>)}</td>
                    <td className="px-2 py-1.5"><Link to={`/findings/${f.id}`} className="text-blue-300 hover:underline inline-flex items-center gap-0.5">Remediate <ArrowSquareOut size={11}/></Link></td>
                  </tr>
                ))}
                {findings.length===0 && <tr><td colSpan={10} className="px-3 py-6 text-center text-slate-500 text-[12px]">No findings in this view.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab==="timeline" && (() => {
        const evs = c.timeline || [];
        const preCount = evs.filter(e => e.pre_creation).length;
        const shown = showHistory ? evs : evs.filter(e => !e.pre_creation);
        return (
          <div className="max-w-3xl">
            {preCount > 0 && (
              <div className="mb-2 flex items-center justify-between">
                <span className="text-[11px] text-slate-500">Showing events since this campaign was created{showHistory ? " + earlier history" : ""}.</span>
                <button onClick={()=>setShowHistory(h=>!h)} className="text-[11.5px] px-2 py-1 rounded border border-[#30363D] text-slate-300 hover:bg-slate-500/10">
                  {showHistory ? `Hide ${preCount} pre-campaign event(s)` : `Show ${preCount} earlier event(s)`}
                </button>
              </div>
            )}
            <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
              <ol className="relative border-l border-[#30363D] ml-2">
                {shown.slice().reverse().map((e,i)=>(
                  <li key={i} className={`ml-4 mb-3 ${e.pre_creation?"opacity-60":""}`}>
                    <div className="absolute -left-1.5 w-3 h-3 rounded-full" style={{background:e.type==="patch"?"#22c55e":e.type==="exception_filed"?"#f59e0b":e.type==="closed"?"#3b82f6":"#64748b"}}/>
                    <div className="text-[12px] text-slate-200">{e.type==="patch"?"✅ Patch applied":e.type==="note"?"📝 Note":e.type==="status_change"?"🔁 Status change":e.type==="exception_filed"?"⚠️ Exception filed":e.type} — {e.detail}{e.pre_creation?<span className="ml-1 text-[9px] px-1 rounded bg-slate-500/20 text-slate-400 align-middle">pre-campaign</span>:null}</div>
                    <div className="text-[10.5px] text-slate-500">{e.at?new Date(e.at).toLocaleString():""}{e.actor?` · ${e.actor}`:""}</div>
                  </li>
                ))}
                {shown.length===0 && <li className="ml-4 text-[12px] text-slate-500">No events in the campaign window{preCount>0?" — toggle above to see earlier history.":"."}</li>}
              </ol>
            </div>
          </div>
        );
      })()}

      {tab==="notes" && <NotesTab id={id} activity={c.activity||[]} onChange={load} canWrite/>}
    </Layout>
  );
}

function Stat({ label, value, tone, onClick }) {
  const t = tone==="green"?"text-emerald-300":tone==="orange"?"text-orange-300":tone==="amber"?"text-amber-300":"text-slate-100";
  const clickable = typeof onClick === "function";
  return <div onClick={onClick} title={clickable?"Click to view these findings":undefined}
    className={`border border-[#30363D] bg-[#0D1117] rounded-md px-3 py-2 ${clickable?"cursor-pointer hover:border-blue-500/40":""}`}>
    <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500">{label}</div>
    <div className={`text-[18px] font-semibold mt-0.5 ${t}`}>{value}</div></div>;
}

function GroupCard({ title, rows, onPick }) {
  return <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3">
    <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-2">{title}</div>
    <div className="space-y-1.5 max-h-56 overflow-y-auto">
      {rows.slice(0,25).map((g,i)=>(
        <button key={i} onClick={()=>onPick && onPick(g.key)} className="w-full text-left group">
          <div className="flex justify-between text-[11.5px]"><span className="text-slate-300 group-hover:text-blue-300 truncate mr-2">{g.key}</span><span className="text-slate-500">{g.patched}/{g.total}</span></div>
          <Bar2 pct={g.percent_complete}/>
        </button>
      ))}
      {rows.length===0 && <div className="text-[11.5px] text-slate-500">None</div>}
    </div>
  </div>;
}

function NotesTab({ id, activity, onChange, canWrite }) {
  const [text,setText]=useState(""); const [links,setLinks]=useState(""); const [files,setFiles]=useState([]); const [busy,setBusy]=useState(false);
  const notes = activity.filter(a=>a.action==="note");
  const onFile = (e) => {
    const fs=[...e.target.files].slice(0,3);
    Promise.all(fs.map(f=>new Promise(res=>{const r=new FileReader();r.onload=()=>res({name:f.name,mime:f.type,data_url:r.result});r.readAsDataURL(f);}))).then(setFiles);
  };
  const post=async()=>{
    if(!text.trim()&&!links.trim()&&files.length===0){toast.error("Add a note, link, or screenshot");return;}
    setBusy(true);
    try{
      await api.post(`/v1/remediation-campaigns/${id}/notes`,{text,links:links.split(",").map(x=>x.trim()).filter(Boolean),attachments:files});
      setText("");setLinks("");setFiles([]);toast.success("Note added");onChange();
    }catch(e){toast.error(e.response?.data?.detail||"Failed");}finally{setBusy(false);}
  };
  return <div className="max-w-3xl space-y-3">
    {canWrite && <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3">
      <textarea value={text} onChange={e=>setText(e.target.value)} rows={2} placeholder="Add a note for this campaign…" className="w-full px-2 py-1.5 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100 mb-2"/>
      <div className="flex items-center gap-2 flex-wrap">
        <input value={links} onChange={e=>setLinks(e.target.value)} placeholder="Links (comma-sep)" className="h-8 flex-1 min-w-[160px] px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/>
        <label className="h-8 px-2.5 text-[11.5px] rounded border border-[#30363D] text-slate-300 inline-flex items-center gap-1 cursor-pointer"><Paperclip size={12}/> Screenshot<input type="file" accept="image/*,application/pdf" multiple className="hidden" onChange={onFile}/></label>
        {files.length>0 && <span className="text-[11px] text-slate-500">{files.length} file(s)</span>}
        <button onClick={post} disabled={busy} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded ml-auto">Post</button>
      </div>
    </div>}
    <div className="space-y-2">
      {notes.map((n,i)=>(
        <div key={i} className="border border-[#30363D] bg-[#0D1117] rounded-md p-3">
          <div className="text-[12.5px] text-slate-200 whitespace-pre-wrap">{n.detail}</div>
          {(n.links||[]).length>0 && <div className="mt-1.5 flex flex-wrap gap-2">{n.links.map((l,j)=><a key={j} href={l} target="_blank" rel="noreferrer" className="text-[11.5px] text-blue-300 hover:underline inline-flex items-center gap-1"><LinkSimple size={11}/>{l}</a>)}</div>}
          {(n.attachments||[]).length>0 && <div className="mt-2 flex flex-wrap gap-2">{n.attachments.map((a,j)=>a.mime?.startsWith("image/")?<img key={j} src={a.data_url} alt={a.name} className="h-20 rounded border border-[#30363D]"/>:<span key={j} className="text-[11.5px] text-slate-400">{a.name}</span>)}</div>}
          <div className="text-[10.5px] text-slate-500 mt-1.5">{n.actor} · {n.at?new Date(n.at).toLocaleString():""}</div>
        </div>
      ))}
      {notes.length===0 && <div className="text-[12px] text-slate-500">No notes yet.</div>}
    </div>
  </div>;
}
