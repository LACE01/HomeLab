import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Link } from "react-router-dom";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip, SevBadge } from "@/components/Badges";
import TeamCombobox from "@/components/TeamCombobox";
import { useAuth } from "@/lib/auth";
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, Cell,
} from "recharts";
import {
  Target, Warning, ArrowClockwise, CheckCircle, Plus, X, CaretDown, CaretLeft,
  ClockCounterClockwise, NotePencil, Paperclip, LinkSimple, ArrowSquareOut,
} from "@phosphor-icons/react";

const SEVS = ["Critical", "High", "Medium", "Low"];
const STATUSES = ["New","Needs triage","Valid","Fixed pending validation","Fixed validated","Mitigated","Accepted risk","Reopened"];
const EXPLOIT = [["kev","KEV"],["active_attacks","Active attacks"],["public_exploit","Public exploit"],["epss_high","EPSS ≥ 0.5"]];
const RESOLVED = ["Fixed validated","Mitigated","False positive","Duplicate","Accepted risk","Closed administratively"];

// Client-side progress over a BASELINE (findings open at add-time), so the Admin
// vs My-work toggle can rescope stats/groups without another round-trip.
function progressOf(findings, baseline) {
  const scope = baseline ? findings.filter(f => baseline.has(f.id)) : findings;
  const patched = scope.filter(f => RESOLVED.includes(f.status)).length;
  const open = scope.filter(f => !RESOLVED.includes(f.status)).length;
  const regressions = scope.filter(f => f.status === "Reopened").length;
  const total = scope.length;
  const now = Date.now();
  const ages = scope.filter(f => !RESOLVED.includes(f.status) && f.first_seen_at)
    .map(f => (now - new Date(f.first_seen_at).getTime()) / 86400000);
  return {
    total, patched, open, regressions,
    percent_complete: total ? Math.round(100 * patched / total) : 0,
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
        <button onClick={notify} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded text-slate-300">Send alerts</button>
        <button onClick={()=>setOpen(true)} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5"><Plus size={14}/> New campaign</button>
      </>}>
      {open && <CreateModal onClose={()=>setOpen(false)} onCreated={()=>{setOpen(false);load();}} />}
      {alerts && (alerts.overdue.length||alerts.regressions.length||alerts.newly_complete.length)>0 && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
          <AlertCard tone="red" icon={Warning} label="Overdue" items={alerts.overdue} render={x=>`${x.name} · ${x.open} open`} onOpen={onOpen}/>
          <AlertCard tone="amber" icon={ArrowClockwise} label="Regressions" items={alerts.regressions} render={x=>`${x.name} · ${x.regressions} reopened`} onOpen={onOpen}/>
          <AlertCard tone="green" icon={CheckCircle} label="Newly complete" items={alerts.newly_complete} render={x=>x.name} onOpen={onOpen}/>
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
  const [assignees,setAssignees]=useState(""); const [busy,setBusy]=useState(false);
  const [sev,setSev]=useState([]); const [status,setStatus]=useState([]); const [exp,setExp]=useState([]);
  const [tags,setTags]=useState([]); const [devtype,setDevtype]=useState([]); const [q,setQ]=useState("");
  const [kev,setKev]=useState(false); const [inet,setInet]=useState(false);
  const [facets,setFacets]=useState({available_tags:[],available_asset_types:[]});
  useEffect(()=>{api.get("/v1/findings/stats").then(r=>setFacets(r.data)).catch(()=>{});},[]);
  const create=async()=>{
    if(!name.trim()){toast.error("Name required");return;}
    const f={};
    if(sev.length)f.severity=sev; if(status.length)f.status=status; if(exp.length)f.exploitability=exp;
    if(tags.length)f.tags=tags;
    if(devtype.length)f.asset_type=devtype;
    if(q.trim())f.q=q.trim(); if(kev)f.kev=true; if(inet)f.internet_facing=true; if(team)f.owner_team=team;
    if(!Object.keys(f).length){toast.error("Pick at least one filter so the campaign has members");return;}
    setBusy(true);
    try{
      await api.post("/v1/remediation-campaigns",{name:name.trim(),owner_team:team||null,
        due_date:due?new Date(due).toISOString():null,
        assignees:assignees.split(",").map(x=>x.trim()).filter(Boolean),
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
          <div><label className="block text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1">Assignees (emails, comma-sep)</label>
            <input value={assignees} onChange={e=>setAssignees(e.target.value)} placeholder="tech@county.us" className="w-full h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/></div>
        </div>
        <div className="border-t border-[#30363D] pt-3 mb-1 text-[10.5px] uppercase tracking-wider font-mono text-slate-500">Scope — same filters as the Findings tab</div>
        <input value={q} onChange={e=>setQ(e.target.value)} placeholder='Search — supports qid: cve: owner: source: entity:' className="w-full h-8 px-2 my-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/>
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
        <div className="text-[11px] text-slate-500 my-3">Members are snapshotted from these filters now; progress then tracks their live scanner status.</div>
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
  const load = async () => { try { const r = await api.get(`/v1/remediation-campaigns/${id}`); setC(r.data); } catch { toast.error("Failed to load"); } };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [id]);
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
  const findings = scoped.filter(drillMatch);
  const openGroup = (by, key) => { setDrill({by, key}); setTab("findings"); };
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
  const removeSel = async () => {
    if (!sel.size || !window.confirm(`Remove ${sel.size} from this campaign? (findings not deleted)`)) return;
    await api.patch(`/v1/remediation-campaigns/${id}`, { remove_finding_ids:[...sel] });
    setSel(new Set()); load();
  };
  const close = async () => { await api.post(`/v1/remediation-campaigns/${id}/close`); toast.success("Closed"); load(); };

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

  return (
    <Layout title={c.name} subtitle={`${p.patched}/${p.total} patched · ${p.percent_complete}% · ${c.status==="closed"?"closed":c.owner_team||"no team"}`}
      actions={<>
        {isAdmin && (
          <div className="flex items-center border border-[#30363D] rounded overflow-hidden">
            <button onClick={()=>setMineOnly(false)} className={`px-3 h-8 text-[12px] ${!mineOnly?"bg-blue-500/15 text-blue-300":"text-slate-400"}`}>Admin view</button>
            <button onClick={()=>setMineOnly(true)} className={`px-3 h-8 text-[12px] ${mineOnly?"bg-blue-500/15 text-blue-300":"text-slate-400"}`}>My work</button>
          </div>
        )}
        {isAdmin && c.status!=="closed" && <button onClick={close} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Close</button>}
        <button onClick={onBack} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300 inline-flex items-center gap-1"><CaretLeft size={13}/> Back</button>
      </>}>

      <div className="flex items-center gap-2 mb-3 max-w-5xl">
        <Bar2 pct={p.percent_complete}/><span className="text-[12px] text-slate-300 w-10 text-right">{p.percent_complete}%</span>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mb-4 max-w-5xl">
        <Stat label="Total" value={p.total}/><Stat label="Patched" value={p.patched} tone="green"/>
        <Stat label="Open" value={p.open}/><Stat label="Regressions" value={p.regressions} tone="orange"/>
        <Stat label="Aging >30d" value={p.aging_over_30d} tone="amber"/>
      </div>

      <div className="flex gap-1 mb-3 border-b border-[#30363D] max-w-5xl">
        {[["overview","Overview"],["findings","Findings"],["timeline","Timeline"],["notes","Notes"]].map(([t,l])=>(
          <button key={t} onClick={()=>setTab(t)} className={`px-3 py-1.5 text-[12px] border-b-2 -mb-px ${tab===t?"border-blue-500 text-blue-300":"border-transparent text-slate-400 hover:text-slate-200"}`}>{l}</button>
        ))}
      </div>

      {tab==="overview" && (
        <div className="space-y-4 max-w-5xl">
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
            {mineOnly ? <span className="text-[11px] text-slate-500">Showing your team / assigned findings</span> : null}
            {drill && <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-200">{drill.by}: {drill.key}<button onClick={()=>setDrill(null)} className="text-blue-300/70 hover:text-red-300"><X size={10}/></button></span>}
            {sel.size>0 && <>
              <span className="text-[12px] text-slate-300">{sel.size} selected</span>
              <button onClick={massNote} className="h-7 px-2.5 text-[11.5px] rounded border border-[#30363D] text-blue-300 inline-flex items-center gap-1"><NotePencil size={12}/> Mass note</button>
              <select onChange={e=>{if(e.target.value){bulkStatus(e.target.value);e.target.value="";}}} className="h-7 bg-[#161B22] border border-[#30363D] rounded px-2 text-[11.5px] text-slate-300">
                <option value="">Set status…</option>{STATUSES.map(s=><option key={s}>{s}</option>)}
              </select>
              {isAdmin && <button onClick={removeSel} className="h-7 px-2.5 text-[11.5px] rounded border border-[#30363D] text-red-300">Remove</button>}
            </>}
          </div>
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
            <table className="w-full text-[12px]">
              <thead><tr className="border-b border-[#30363D] text-left text-slate-500 text-[10.5px] uppercase tracking-wider">
                <th className="pl-3 pr-1 py-2 w-6"></th><th className="px-2 py-2">Finding</th><th className="px-2 py-2">CVE/QID</th>
                <th className="px-2 py-2">Sev</th><th className="px-2 py-2">Asset</th><th className="px-2 py-2">Status</th><th className="px-2 py-2">Ticket</th><th className="px-2 py-2"></th></tr></thead>
              <tbody>
                {findings.map(f=>(
                  <tr key={f.id} className="border-b border-[#30363D]/60 hover:bg-slate-800/20">
                    <td className="pl-3 pr-1 py-1.5"><input type="checkbox" checked={sel.has(f.id)} onChange={()=>toggle(f.id)}/></td>
                    <td className="px-2 py-1.5"><Link to={`/findings/${f.id}`} className="text-slate-100 hover:text-blue-300 hover:underline">{f.title}</Link></td>
                    <td className="px-2 py-1.5 text-slate-400 font-mono">{f.cve||f.qid||"—"}</td>
                    <td className="px-2 py-1.5"><SevBadge severity={f.severity}/></td>
                    <td className="px-2 py-1.5 text-slate-400">{f.asset_hostname||"—"}</td>
                    <td className="px-2 py-1.5 text-slate-300">{f.status}</td>
                    <td className="px-2 py-1.5 text-slate-400">{f.ticket ? (typeof f.ticket==="string"?f.ticket:(f.ticket.key||f.ticket.id||"linked")) : "—"}</td>
                    <td className="px-2 py-1.5"><Link to={`/findings/${f.id}`} className="text-blue-300 hover:underline inline-flex items-center gap-0.5">Remediate <ArrowSquareOut size={11}/></Link></td>
                  </tr>
                ))}
                {findings.length===0 && <tr><td colSpan={8} className="px-3 py-6 text-center text-slate-500 text-[12px]">No findings in this view.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab==="timeline" && (
        <div className="max-w-3xl border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <ol className="relative border-l border-[#30363D] ml-2">
            {(c.timeline||[]).slice().reverse().map((e,i)=>(
              <li key={i} className="ml-4 mb-3">
                <div className="absolute -left-1.5 w-3 h-3 rounded-full" style={{background:e.type==="patch"?"#22c55e":e.type==="exception_filed"?"#f59e0b":e.type==="closed"?"#3b82f6":"#64748b"}}/>
                <div className="text-[12px] text-slate-200">{e.type==="patch"?"✅ Patch applied":e.type==="note"?"📝 Note":e.type==="status_change"?"🔁 Status change":e.type==="exception_filed"?"⚠️ Exception filed":e.type} — {e.detail}</div>
                <div className="text-[10.5px] text-slate-500">{e.at?new Date(e.at).toLocaleString():""}{e.actor?` · ${e.actor}`:""}</div>
              </li>
            ))}
            {(c.timeline||[]).length===0 && <li className="ml-4 text-[12px] text-slate-500">No events yet.</li>}
          </ol>
        </div>
      )}

      {tab==="notes" && <NotesTab id={id} activity={c.activity||[]} onChange={load} canWrite/>}
    </Layout>
  );
}

function Stat({ label, value, tone }) {
  const t = tone==="green"?"text-emerald-300":tone==="orange"?"text-orange-300":tone==="amber"?"text-amber-300":"text-slate-100";
  return <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-3 py-2">
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
