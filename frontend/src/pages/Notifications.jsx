import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Plus, Trash, Lightning, PaperPlaneTilt, EnvelopeSimple, DiscordLogo, SlackLogo, MicrosoftTeamsLogo, Globe } from "@phosphor-icons/react";
import { toast } from "sonner";

const CHANNEL_ICONS = {
  email: EnvelopeSimple, discord: DiscordLogo, slack: SlackLogo, teams: MicrosoftTeamsLogo, webhook: Globe,
};
const SEVERITIES = ["Critical","High","Medium","Low","Info"];

export default function Notifications() {
  const [channels, setChannels] = useState([]);
  const [rules, setRules] = useState([]);
  const [outbox, setOutbox] = useState([]);
  const [meta, setMeta] = useState({triggers:[], channels:[], templates:[]});
  const [tab, setTab] = useState("channels");

  const [chForm, setChForm] = useState({name:"", type:"discord", webhook_url:"", to:"", enabled:true});
  const [ruleForm, setRuleForm] = useState({name:"", trigger:"finding_created_critical", channel_ids:[], severity_in:[], owner_team:"", template_id:"new_assignment", frequency:"immediate", active:true});

  const load = async () => {
    const [c, r, o, m] = await Promise.all([
      api.get("/v1/admin/notification-channels"),
      api.get("/v1/admin/notification-rules"),
      api.get("/v1/admin/notifications-outbox"),
      api.get("/v1/admin/notification-meta"),
    ]);
    setChannels(c.data.items); setRules(r.data.items); setOutbox(o.data.items); setMeta(m.data);
  };
  useEffect(() => { load(); }, []);

  const addChannel = async () => {
    if (!chForm.name) { toast.error("Name required"); return; }
    if (chForm.type !== "email" && !chForm.webhook_url) { toast.error("Webhook URL required"); return; }
    if (chForm.type === "email" && !chForm.to) { toast.error("Recipient email required"); return; }
    try { await api.post("/v1/admin/notification-channels", chForm); toast.success("Channel added"); setChForm({name:"", type:"discord", webhook_url:"", to:"", enabled:true}); await load(); }
    catch (e) { toast.error(e.response?.data?.detail || "Failed"); }
  };
  const delChannel = async (id) => { if (window.confirm("Delete channel?")) { await api.delete(`/v1/admin/notification-channels/${id}`); await load(); } };
  const testChannel = async (c) => {
    try {
      const r = await api.post(`/v1/admin/notification-channels/${c.id}/test`);
      if (r.data.simulated) {
        toast(r.data.response, { icon: "⚠️", duration: 8000 });
      } else if (r.data.delivered) {
        toast.success(`Sent! (HTTP ${r.data.status_code})`);
      } else {
        toast.error(`Delivery failed: ${r.data.response}`);
      }
      await load();
    } catch (e) { toast.error("Test failed"); }
  };

  const addRule = async () => {
    if (!ruleForm.name) { toast.error("Name required"); return; }
    if (!ruleForm.channel_ids.length) { toast.error("Select at least one channel"); return; }
    try { await api.post("/v1/admin/notification-rules", ruleForm); toast.success("Rule added"); setRuleForm({name:"", trigger:"finding_created_critical", channel_ids:[], severity_in:[], owner_team:"", template_id:"new_assignment", frequency:"immediate", active:true}); await load(); }
    catch (e) { toast.error(e.response?.data?.detail || "Failed"); }
  };
  const delRule = async (id) => { if (window.confirm("Delete rule?")) { await api.delete(`/v1/admin/notification-rules/${id}`); await load(); } };
  const sendDigestNow = async (r) => {
    try {
      const res = await api.post(`/v1/admin/notification-rules/${r.id}/send-digest-now`);
      toast.success(`Digest sweep ran — ${res.data.digests_sent} sent.`);
      await load();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed"); }
  };

  const Tab = ({ id, label, testid }) => (
    <button data-testid={testid} onClick={()=>setTab(id)}
      className={`px-3 py-1.5 text-[12px] border-b-2 ${tab===id?"border-blue-400 text-blue-300":"border-transparent text-slate-400 hover:text-slate-200"}`}>
      {label}
    </button>
  );

  return (
    <Layout title="Notifications" subtitle="Channels, rules, message templates, and delivery log">
      <div className="border-b border-[#30363D] mb-4 flex gap-1">
        <Tab id="channels" label="Channels" testid="tab-channels"/>
        <Tab id="rules" label="Rules" testid="tab-rules"/>
        <Tab id="outbox" label="Outbox" testid="tab-outbox"/>
        <Tab id="templates" label="Templates" testid="tab-templates"/>
      </div>

      {tab === "channels" && (
        <div className="space-y-3">
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3 grid grid-cols-6 gap-2">
            <input placeholder="Name" data-testid="ch-name" value={chForm.name} onChange={(e)=>setChForm({...chForm, name:e.target.value})} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]"/>
            <select data-testid="ch-type" value={chForm.type} onChange={(e)=>setChForm({...chForm, type:e.target.value})} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]">{meta.channels.map(c=> <option key={c}>{c}</option>)}</select>
            {chForm.type !== "email" ? (
              <input placeholder="Webhook URL" data-testid="ch-url" value={chForm.webhook_url} onChange={(e)=>setChForm({...chForm, webhook_url:e.target.value})} className="col-span-2 h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] font-mono"/>
            ) : (
              <input placeholder="recipient@example.com" data-testid="ch-to" value={chForm.to} onChange={(e)=>setChForm({...chForm, to:e.target.value})} className="col-span-2 h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]"/>
            )}
            <button data-testid="ch-add" onClick={addChannel} className="h-8 col-span-2 bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded inline-flex items-center justify-center gap-1 text-[12px]"><Plus size={14}/> Add channel</button>
          </div>
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
            <table className="dense w-full">
              <thead><tr><th></th><th className="text-left">Name</th><th>Type</th><th className="text-left">Endpoint</th><th>Enabled</th><th></th></tr></thead>
              <tbody>
                {channels.map(c => {
                  const Icon = CHANNEL_ICONS[c.type] || Webhook;
                  return (
                    <tr key={c.id} className="border-t border-[#30363D]">
                      <td><Icon size={16} className="text-slate-400"/></td>
                      <td className="text-slate-200">{c.name}</td>
                      <td><Chip>{c.type}</Chip></td>
                      <td className="font-mono text-[10.5px] text-slate-400">{c.webhook_url_masked || c.to || "—"}</td>
                      <td><Chip color={c.enabled!==false?"green":"slate"}>{c.enabled!==false?"on":"off"}</Chip></td>
                      <td className="flex gap-1 justify-end pr-2 py-1">
                        <button data-testid={`test-ch-${c.id}`} onClick={()=>testChannel(c)} className="h-7 px-2 text-[11px] border border-[#30363D] hover:border-emerald-500/50 rounded inline-flex items-center gap-1 text-emerald-300"><PaperPlaneTilt size={12}/> Test</button>
                        <button data-testid={`del-ch-${c.id}`} onClick={()=>delChannel(c.id)} className="text-red-400 hover:text-red-300 px-2"><Trash size={14}/></button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === "rules" && (
        <div className="space-y-3">
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3 space-y-2">
            <div className="grid grid-cols-3 gap-2">
              <input placeholder="Rule name" data-testid="r-name" value={ruleForm.name} onChange={(e)=>setRuleForm({...ruleForm, name:e.target.value})} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]"/>
              <select data-testid="r-trigger" value={ruleForm.trigger} onChange={(e)=>setRuleForm({...ruleForm, trigger:e.target.value})} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]">
                {meta.triggers.map(t=> <option key={t}>{t}</option>)}
              </select>
              <select data-testid="r-template" value={ruleForm.template_id} onChange={(e)=>setRuleForm({...ruleForm, template_id:e.target.value})} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]">
                {meta.templates.map(t=> <option key={t}>{t}</option>)}
              </select>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <select data-testid="r-channels" multiple value={ruleForm.channel_ids} onChange={(e)=>setRuleForm({...ruleForm, channel_ids: Array.from(e.target.selectedOptions, o=>o.value)})} className="bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] py-1 h-[80px]">
                {channels.map(c=> <option key={c.id} value={c.id}>{c.name} ({c.type})</option>)}
              </select>
              <div className="flex flex-wrap gap-1 content-start">
                {SEVERITIES.map(s => (
                  <button key={s} type="button" onClick={()=>setRuleForm({...ruleForm, severity_in: ruleForm.severity_in.includes(s) ? ruleForm.severity_in.filter(x=>x!==s) : [...ruleForm.severity_in, s]})}
                    className={`px-2 py-1 text-[11px] rounded border ${ruleForm.severity_in.includes(s)?"border-blue-500/50 bg-blue-500/10 text-blue-300":"border-[#30363D] text-slate-400"}`}>{s}</button>
                ))}
              </div>
              <div className="space-y-2">
                <input placeholder="Owner team (optional)" data-testid="r-team" value={ruleForm.owner_team} onChange={(e)=>setRuleForm({...ruleForm, owner_team:e.target.value})} className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]"/>
                <select data-testid="r-freq" value={ruleForm.frequency} onChange={(e)=>setRuleForm({...ruleForm, frequency:e.target.value})} className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]">
                  <option>immediate</option><option>hourly</option><option>daily</option><option>weekly</option>
                </select>
              </div>
            </div>
            <button data-testid="r-add" onClick={addRule} className="h-8 px-4 bg-blue-500/20 border border-blue-500/40 text-blue-300 rounded inline-flex items-center gap-1 text-[12px]"><Plus size={14}/> Add rule</button>
          </div>
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
            <table className="dense w-full">
              <thead><tr><th className="text-left">Name</th><th>Trigger</th><th>Template</th><th>Channels</th><th>Severity</th><th>Cadence</th><th>Active</th><th></th></tr></thead>
              <tbody>
                {rules.map(r => (
                  <tr key={r.id} className="border-t border-[#30363D]">
                    <td className="text-slate-200">{r.name}</td>
                    <td><Chip>{r.trigger}</Chip></td>
                    <td className="text-slate-400 text-[11px]">{r.template_id}</td>
                    <td className="font-mono text-[10.5px]">{r.channel_ids?.length}</td>
                    <td className="text-[10.5px]">{(r.severity_in||[]).join(", ") || "any"}</td>
                    <td className="text-[11px]">
                      {r.frequency === "immediate" ? <Chip color="slate">immediate</Chip> : (
                        <div className="flex items-center gap-1.5">
                          <Chip color="blue">{r.frequency} · {r.queued_count ?? 0} queued</Chip>
                          <button onClick={()=>sendDigestNow(r)} title="Send digest now" className="text-blue-300 hover:text-blue-200"><PaperPlaneTilt size={12}/></button>
                        </div>
                      )}
                    </td>
                    <td><Chip color={r.active?"green":"slate"}>{r.active?"on":"off"}</Chip></td>
                    <td><button onClick={()=>delRule(r.id)} className="text-red-400 hover:text-red-300"><Trash size={14}/></button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === "outbox" && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
          <table className="dense w-full">
            <thead><tr><th className="text-left">Time</th><th>Channel</th><th>Template</th><th className="text-left">Subject</th><th>Status</th></tr></thead>
            <tbody>
              {outbox.map(o => (
                <tr key={o.id} className="border-t border-[#30363D]">
                  <td className="font-mono text-[10.5px]">{(o.created_at||"").slice(0,19).replace("T"," ")}</td>
                  <td className="text-[11px]">{o.channel_type} · {o.channel_name}</td>
                  <td className="text-[11px] text-slate-400">{o.template_id}</td>
                  <td className="text-[11.5px] max-w-[420px] truncate">{o.subject}</td>
                  <td><Chip color={o.delivered?"green":"red"}>{o.delivered?`✓ ${o.status_code}`:"failed"}</Chip></td>
                </tr>
              ))}
              {!outbox.length && <tr><td colSpan="5" className="text-center text-slate-500 py-6">No notifications sent yet. Try testing a channel above.</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {tab === "templates" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {meta.templates.map(t => (
            <div key={t} className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
              <div className="text-[13px] font-medium text-slate-100 mb-1">{t}</div>
              <div className="text-[11px] font-mono text-slate-500">Available variables:</div>
              <div className="mt-1 flex flex-wrap gap-1">
                {["severity","title","cve","asset","owner_team","risk_score","due_at","url","days_left","days_overdue","approver","expires_at"].map(v => <Chip key={v}>{`{${v}}`}</Chip>)}
              </div>
            </div>
          ))}
        </div>
      )}
    </Layout>
  );
}
