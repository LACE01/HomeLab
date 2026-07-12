import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Plus, X, Trash, PencilSimple, CheckCircle, XCircle, WebhooksLogo } from "@phosphor-icons/react";

const EMPTY_WEBHOOK = { name: "", url: "", secret: "", enabled: true };

export default function TicketingSoar() {
  const [jira, setJira] = useState(null);
  const [jiraForm, setJiraForm] = useState(null);
  const [savingJira, setSavingJira] = useState(false);
  const [webhooks, setWebhooks] = useState([]);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    try {
      const [j, w] = await Promise.all([
        api.get("/v1/admin/ticketing/jira-config"),
        api.get("/v1/admin/ticketing/webhooks"),
      ]);
      setJira(j.data);
      setJiraForm({ ...j.data, api_token: "" });
      setWebhooks(w.data.items || []);
    } catch (e) {
      toast.error("Failed to load ticketing config");
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const saveJira = async () => {
    if (!jiraForm.base_url.trim() || !jiraForm.email.trim() || !jiraForm.project_key.trim()) {
      toast.error("Base URL, email, and project key are required"); return;
    }
    setSavingJira(true);
    try {
      await api.put("/v1/admin/ticketing/jira-config", jiraForm);
      toast.success("Jira connection saved");
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to save Jira config");
    } finally { setSavingJira(false); }
  };

  const removeWebhook = async (wh) => {
    if (!window.confirm(`Remove webhook "${wh.name}"?`)) return;
    await api.delete(`/v1/admin/ticketing/webhooks/${wh.id}`);
    toast.success("Removed");
    load();
  };

  const toggleWebhook = async (wh) => {
    await api.put(`/v1/admin/ticketing/webhooks/${wh.id}`, { name: wh.name, url: wh.url, enabled: !wh.enabled });
    load();
  };

  if (loading || !jiraForm) {
    return <Layout title="Ticketing / SOAR"><div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div></Layout>;
  }

  return (
    <Layout title="Ticketing / SOAR" subtitle="Push a Security Alert out to Jira as an issue, or to any webhook a SOAR/automation platform is listening on">
      <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3 py-2.5 mb-5 text-[12px] text-blue-200 leading-relaxed max-w-3xl">
        Export is manual, per-alert -- open a Security Alert and choose "Send to Jira" or "Send to &lt;webhook&gt;". Nothing here auto-forwards
        every alert, so Jira/your SOAR queue doesn't get flooded with Low-severity noise.
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-5 mb-5 max-w-xl">
        <div className="flex items-center justify-between mb-3">
          <div className="text-[13.5px] text-slate-100 font-medium">Jira connection</div>
          {jira?.configured ? <Chip color="blue">Configured</Chip> : <Chip color="slate">Not configured</Chip>}
        </div>
        <div className="space-y-3">
          <div>
            <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Base URL</label>
            <input value={jiraForm.base_url} onChange={e=>setJiraForm({...jiraForm, base_url: e.target.value})}
              placeholder="https://yourcompany.atlassian.net"
              className="w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100 font-mono"/>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Account email</label>
              <input value={jiraForm.email} onChange={e=>setJiraForm({...jiraForm, email: e.target.value})}
                className="w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100"/>
            </div>
            <div>
              <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">API token</label>
              <input type="password" value={jiraForm.api_token} onChange={e=>setJiraForm({...jiraForm, api_token: e.target.value})}
                placeholder={jira?.configured ? "Leave blank to keep existing" : "Atlassian API token"}
                className="w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100 font-mono"/>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Project key</label>
              <input value={jiraForm.project_key} onChange={e=>setJiraForm({...jiraForm, project_key: e.target.value.toUpperCase()})}
                placeholder="SEC" className="w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100 font-mono"/>
            </div>
            <div>
              <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Issue type</label>
              <input value={jiraForm.issue_type} onChange={e=>setJiraForm({...jiraForm, issue_type: e.target.value})}
                placeholder="Task" className="w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100"/>
            </div>
          </div>
          <label className="flex items-center gap-2 text-[12px] text-slate-300">
            <input type="checkbox" checked={jiraForm.enabled} onChange={e=>setJiraForm({...jiraForm, enabled: e.target.checked})}/>
            Enabled
          </label>
          <button onClick={saveJira} disabled={savingJira}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">
            {savingJira ? "Saving…" : "Save Jira connection"}
          </button>
        </div>
      </div>

      <div className="flex items-center justify-between mb-3">
        <div className="text-[13.5px] text-slate-100 font-medium">Webhook destinations</div>
        <button onClick={() => { setEditing(null); setModalOpen(true); }}
          className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
          <Plus size={14}/> Add webhook
        </button>
      </div>

      {webhooks.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-8 text-center text-[12.5px] text-slate-500">
          No webhook destinations yet.
        </div>
      ) : (
        <div className="space-y-2">
          {webhooks.map(wh => (
            <div key={wh.id} className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3 flex items-center justify-between gap-3">
              <div className="min-w-0 flex items-center gap-2">
                <WebhooksLogo size={14} className="text-slate-500 shrink-0"/>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[13px] text-slate-100">{wh.name}</span>
                    {!wh.enabled && <Chip color="slate">Disabled</Chip>}
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono truncate">{wh.url}</div>
                </div>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <button onClick={() => toggleWebhook(wh)} title={wh.enabled ? "Disable" : "Enable"}
                  className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-slate-200 rounded border border-[#30363D]">
                  {wh.enabled ? <CheckCircle size={14}/> : <XCircle size={14}/>}
                </button>
                <button onClick={() => { setEditing(wh); setModalOpen(true); }}
                  className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-slate-200 rounded border border-[#30363D]">
                  <PencilSimple size={14}/>
                </button>
                <button onClick={() => removeWebhook(wh)}
                  className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-red-400 rounded border border-[#30363D]">
                  <Trash size={14}/>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {modalOpen && (
        <WebhookModal initial={editing || EMPTY_WEBHOOK} isEdit={!!editing}
          onClose={() => setModalOpen(false)} onSaved={() => { setModalOpen(false); load(); }}/>
      )}
    </Layout>
  );
}

function WebhookModal({ initial, isEdit, onClose, onSaved }) {
  const [form, setForm] = useState({ ...EMPTY_WEBHOOK, ...initial, secret: "" });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!form.name.trim() || !form.url.trim()) { toast.error("Name and URL are required"); return; }
    setSaving(true);
    try {
      if (isEdit) await api.put(`/v1/admin/ticketing/webhooks/${initial.id}`, form);
      else await api.post("/v1/admin/ticketing/webhooks", form);
      toast.success(isEdit ? "Webhook updated" : "Webhook added");
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to save webhook");
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="text-[14px] text-slate-100 font-medium">{isEdit ? "Edit" : "Add"} webhook</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5 space-y-3.5">
          <div>
            <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Name</label>
            <input value={form.name} onChange={e=>setForm({...form, name: e.target.value})}
              placeholder="SOAR Prod" className="w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100"/>
          </div>
          <div>
            <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">URL</label>
            <input value={form.url} onChange={e=>setForm({...form, url: e.target.value})}
              placeholder="https://soar.example.com/hooks/vulnops"
              className="w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100 font-mono"/>
          </div>
          <div>
            <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Shared secret (optional)</label>
            <input type="password" value={form.secret} onChange={e=>setForm({...form, secret: e.target.value})}
              placeholder={isEdit ? "Leave blank to keep existing" : "Used to HMAC-sign the payload"}
              className="w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100 font-mono"/>
            <div className="text-[10.5px] text-slate-600 mt-1">If set, requests include an X-VulnOps-Signature: sha256=... header so the receiver can verify authenticity.</div>
          </div>
          <label className="flex items-center gap-2 text-[12px] text-slate-300">
            <input type="checkbox" checked={form.enabled} onChange={e=>setForm({...form, enabled: e.target.checked})}/>
            Enabled
          </label>
        </div>
        <div className="flex justify-end gap-2 px-5 py-3.5 border-t border-[#30363D]">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={save} disabled={saving}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}
