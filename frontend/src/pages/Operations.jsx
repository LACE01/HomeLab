import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { fmtDate, fmtRel } from "@/lib/utils-fmt";
import { Link, useNavigate } from "react-router-dom";
import { Plus, X } from "@phosphor-icons/react";
import { toast } from "sonner";

const CRITICALITY_OPTIONS = ["crown_jewel", "critical", "medium", "low"];

export function ProductFormModal({ initial, onClose, onSaved }) {
  const [form, setForm] = useState(initial || {
    name: "", description: "", business_owner: "", criticality: "medium",
    sla_profile: "standard", environments: [],
  });
  const [saving, setSaving] = useState(false);
  const isEdit = !!initial?.id;

  const save = async () => {
    if (!form.name.trim()) { toast.error("Name is required"); return; }
    setSaving(true);
    try {
      const body = {
        name: form.name, description: form.description, business_owner: form.business_owner,
        criticality: form.criticality, sla_profile: form.sla_profile, environments: form.environments,
      };
      if (isEdit) await api.put(`/v1/products/${initial.id}`, body);
      else await api.post("/v1/products", body);
      toast.success(isEdit ? "Product updated." : "Product created.");
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to save product");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-md" onClick={e=>e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between">
          <h3 className="text-[13px] font-medium text-slate-100">{isEdit ? "Edit product" : "New product"}</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16}/></button>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Name</label>
            <input data-testid="product-form-name" value={form.name} onChange={e=>setForm({...form, name:e.target.value})}
              className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200"/>
          </div>
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Description</label>
            <textarea data-testid="product-form-description" value={form.description} onChange={e=>setForm({...form, description:e.target.value})}
              rows={2} className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200"/>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] uppercase font-mono text-slate-500">Business owner</label>
              <input data-testid="product-form-owner" value={form.business_owner} onChange={e=>setForm({...form, business_owner:e.target.value})}
                className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200"/>
            </div>
            <div>
              <label className="text-[11px] uppercase font-mono text-slate-500">Criticality</label>
              <select data-testid="product-form-criticality" value={form.criticality} onChange={e=>setForm({...form, criticality:e.target.value})}
                className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200">
                {CRITICALITY_OPTIONS.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">SLA profile</label>
            <select data-testid="product-form-sla" value={form.sla_profile} onChange={e=>setForm({...form, sla_profile:e.target.value})}
              className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200">
              {["expedited","standard","relaxed"].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
        </div>
        <div className="px-4 py-3 border-t border-[#30363D] flex justify-end gap-2">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button data-testid="product-form-save" onClick={save} disabled={saving}
            className="h-8 px-3 text-[12px] bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/40 text-blue-200 rounded disabled:opacity-50">
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

export function Products() {
  const [items, setItems] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const load = () => api.get("/v1/products").then(r => setItems(r.data.items));
  useEffect(() => { load(); }, []);
  return (
    <Layout title="Products / Business Services" subtitle="Vulnerability exposure grouped by application portfolio"
      actions={<button data-testid="new-product-btn" onClick={()=>setShowForm(true)}
        className="h-8 px-3 text-[12px] bg-blue-500/15 border border-blue-500/40 hover:bg-blue-500/25 text-blue-300 rounded inline-flex items-center gap-1.5">
        <Plus size={14}/> New product
      </button>}>
      {items.length === 0 && (
        <div className="text-[12.5px] text-slate-500 border border-[#30363D] bg-[#0D1117] rounded-md p-6 text-center">
          No products yet. Create one, then assign assets to it from the Assets page.
        </div>
      )}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {items.map(p => (
          <Link key={p.id} to={`/products/${p.id}`} className="block border border-[#30363D] bg-[#0D1117] rounded-md p-4 hover:border-[#484F58]" data-testid={`product-${p.id}`}>
            <div className="flex items-start justify-between"><div className="text-[14px] font-medium text-slate-100">{p.name}</div><Chip color={p.criticality === "crown_jewel" ? "red" : "orange"}>{p.criticality}</Chip></div>
            <div className="text-[12px] text-slate-500 mt-1">{p.description}</div>
            <div className="text-[11px] text-slate-500 mt-2">Owner: <span className="text-slate-300">{p.business_owner}</span></div>
            <div className="grid grid-cols-3 gap-2 mt-3 pt-3 border-t border-[#30363D]">
              <div><div className="text-[10px] uppercase font-mono text-slate-500">Assets</div><div className="text-[18px] font-mono">{p.asset_count}</div></div>
              <div><div className="text-[10px] uppercase font-mono text-slate-500">Open</div><div className="text-[18px] font-mono">{p.open_findings}</div></div>
              <div><div className="text-[10px] uppercase font-mono text-slate-500">Critical</div><div className="text-[18px] font-mono text-red-300">{p.critical_findings}</div></div>
            </div>
          </Link>
        ))}
      </div>
      {showForm && <ProductFormModal onClose={()=>setShowForm(false)} onSaved={()=>{setShowForm(false); load();}} />}
    </Layout>
  );
}

export function Engagements() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => { api.get("/v1/engagements").then(r => setItems(r.data.items)).finally(() => setLoading(false)); }, []);
  return (
    <Layout title="Engagements / Scan Runs" subtitle="Every actual scan/import run — Qualys polls, Nmap scans, SBOM/EASM sweeps, manual uploads, API pushes">
      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No scan runs yet — this fills in as Qualys polls, Nmap scans, SBOM uploads, EASM sweeps,
          or API ingests actually run.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
          <table className="dense w-full">
            <thead><tr><th className="text-left">Name</th><th>Scanner</th><th>Scan Type</th><th>Method</th><th>Status</th><th>Assets Scanned</th><th>Findings Created</th><th>Findings Updated</th><th>Started</th></tr></thead>
            <tbody>
              {items.map(e => (
                <tr key={e.id} className="border-t border-[#30363D] hover:bg-slate-800/30">
                  <td className="text-slate-200">{e.name}</td>
                  <td className="text-slate-400">{e.scanner}</td>
                  <td><Chip>{e.scan_type}</Chip></td>
                  <td><Chip>{e.scan_method}</Chip></td>
                  <td><Chip color={e.status === "completed" ? "green" : e.status === "failed" ? "red" : "slate"}>{e.status}</Chip></td>
                  <td className="font-mono">{e.assets_scanned}</td>
                  <td className="font-mono">{e.findings_created}</td>
                  <td className="font-mono">{e.findings_updated}</td>
                  <td className="font-mono text-[11px]">{fmtDate(e.started_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Layout>
  );
}

export function Tickets() {
  const [items, setItems] = useState([]);
  useEffect(() => { api.get("/v1/tickets").then(r => setItems(r.data.items)); }, []);
  return (
    <Layout title="Remediation Tickets" subtitle="External tickets synced from Jira, ServiceNow, GitHub">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table className="dense w-full">
          <thead><tr><th className="text-left">Ticket</th><th>System</th><th className="text-left">Title</th><th>Assignee</th><th>Status</th><th>Updated</th></tr></thead>
          <tbody>
            {items.map(t => (
              <tr key={t.id} className="border-t border-[#30363D] hover:bg-slate-800/30">
                <td><a href={t.url} target="_blank" rel="noopener noreferrer" className="font-mono text-blue-300 hover:underline" data-testid={`ticket-${t.id}`}>{t.external_id}</a></td>
                <td>{t.system}</td>
                <td className="max-w-[420px]"><Link to={`/findings/${t.finding_id}`} className="text-slate-200 hover:text-blue-300">{t.title}</Link></td>
                <td className="text-slate-400">{t.assignee}</td>
                <td><Chip color={t.status === "done" ? "green" : "amber"}>{t.status}</Chip></td>
                <td className="font-mono text-[11px] text-slate-400">{fmtRel(t.updated_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}

const EXC_STATUS_TABS = [
  { id: "", label: "All" },
  { id: "pending_approval", label: "Pending Approval" },
  { id: "active", label: "Active" },
  { id: "expired", label: "Expired" },
  { id: "rejected", label: "Rejected" },
  { id: "revoked", label: "Revoked" },
];

const EXC_STATUS_COLOR = { pending_approval: "amber", active: "green", expired: "slate", rejected: "red", revoked: "red" };

function RenewModal({ exc, onClose, onDone }) {
  const [newDate, setNewDate] = useState("");
  const [justification, setJustification] = useState("");
  const [saving, setSaving] = useState(false);
  const submit = async () => {
    if (!newDate || !justification.trim()) { toast.error("New expiry date and justification are required"); return; }
    setSaving(true);
    try {
      await api.post(`/v1/exceptions/${exc.id}/renew`, { new_expires_at: new Date(newDate).toISOString(), justification });
      toast.success("Renewal requested -- pending approval.");
      onDone();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to request renewal");
    } finally { setSaving(false); }
  };
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-sm" onClick={e=>e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between">
          <h3 className="text-[13px] font-medium text-slate-100">Renew exception</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16}/></button>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">New expiry date</label>
            <input type="date" value={newDate} onChange={e=>setNewDate(e.target.value)}
              className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200"/>
          </div>
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Why does this still need an exception?</label>
            <textarea value={justification} onChange={e=>setJustification(e.target.value)} rows={3}
              className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200"/>
          </div>
        </div>
        <div className="px-4 py-3 border-t border-[#30363D] flex justify-end gap-2">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={submit} disabled={saving} className="h-8 px-3 text-[12px] bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/40 text-blue-200 rounded disabled:opacity-50">
            {saving ? "Submitting…" : "Request renewal"}
          </button>
        </div>
      </div>
    </div>
  );
}

function RejectModal({ exc, onClose, onDone }) {
  const [reason, setReason] = useState("");
  const [saving, setSaving] = useState(false);
  const submit = async () => {
    if (!reason.trim()) { toast.error("A rejection reason is required"); return; }
    setSaving(true);
    try {
      await api.post(`/v1/exceptions/${exc.id}/reject`, { reason });
      toast.success("Exception rejected.");
      onDone();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to reject");
    } finally { setSaving(false); }
  };
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-sm" onClick={e=>e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between">
          <h3 className="text-[13px] font-medium text-slate-100">Reject exception request</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16}/></button>
        </div>
        <div className="p-4">
          <label className="text-[11px] uppercase font-mono text-slate-500">Reason</label>
          <textarea value={reason} onChange={e=>setReason(e.target.value)} rows={3}
            className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200"/>
        </div>
        <div className="px-4 py-3 border-t border-[#30363D] flex justify-end gap-2">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={submit} disabled={saving} className="h-8 px-3 text-[12px] bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-200 rounded disabled:opacity-50">
            {saving ? "Submitting…" : "Reject"}
          </button>
        </div>
      </div>
    </div>
  );
}

export function Exceptions() {
  const navigate = useNavigate();
  const [items, setItems] = useState([]);
  const [statusFilter, setStatusFilter] = useState("");
  const [renewing, setRenewing] = useState(null);
  const [rejecting, setRejecting] = useState(null);

  const load = () => api.get("/v1/exceptions", { params: statusFilter ? {status: statusFilter} : {} }).then(r => setItems(r.data.items));
  useEffect(() => { load(); }, [statusFilter]); // eslint-disable-line

  const approve = async (e) => {
    try {
      await api.post(`/v1/exceptions/${e.id}/approve`);
      toast.success("Exception approved.");
      load();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Failed to approve");
    }
  };

  return (
    <Layout title="Risk Acceptances / Exceptions" subtitle="Time-bound exceptions with approval, compensating controls, and renewal"
      actions={<button onClick={()=>navigate("/exceptions/new")} data-testid="new-risk-acceptance-btn"
        className="h-8 px-3 text-[12px] bg-blue-500/15 border border-blue-500/40 hover:bg-blue-500/25 text-blue-300 rounded inline-flex items-center gap-1.5">
        <Plus size={14}/> New request
      </button>}>
      <div className="flex items-center gap-1 mb-3">
        {EXC_STATUS_TABS.map(t => (
          <button key={t.id} onClick={()=>setStatusFilter(t.id)}
            className={`px-3 py-1 text-[12px] rounded-sm border transition-colors ${statusFilter===t.id ? "bg-blue-500/15 text-blue-300 border-blue-500/30" : "text-slate-400 hover:text-slate-200 border-transparent"}`}>
            {t.label}
          </button>
        ))}
      </div>
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table className="dense w-full">
          <thead><tr><th className="text-left">Target</th><th>Severity</th><th>Asset</th><th className="text-left">Justification</th><th>Status</th><th>Requested by</th><th>Expires</th><th></th></tr></thead>
          <tbody>
            {items.map(e => (
              <tr key={e.id} className="border-t border-[#30363D] hover:bg-slate-800/20 cursor-pointer" onClick={()=>navigate(`/exceptions/${e.id}`)} data-testid={`exception-row-${e.id}`}>
                <td>
                  {e.finding_count > 1 ? (
                    <span className="text-slate-200">{e.finding_count} findings <span className="text-slate-500 font-mono text-[10.5px]">({e.target_type}: {e.target_value})</span></span>
                  ) : (
                    <Link to={`/findings/${e.finding_id}`} onClick={ev=>ev.stopPropagation()} className="text-blue-300 hover:underline">{e.finding_title?.slice(0,50)}</Link>
                  )}
                  <div className="text-[10.5px] text-slate-500 font-mono">{e.cve}</div>
                </td>
                <td><Chip color={e.severity === "Critical" ? "red" : "orange"}>{e.severity}</Chip></td>
                <td className="font-mono text-[11px]">{e.asset_hostname}</td>
                <td className="max-w-[300px] text-slate-300">{e.business_justification || e.rationale}<div className="mt-1 flex gap-1 flex-wrap">{(e.compensating_controls||[]).map(c=> <Chip key={c} color="blue">{c}</Chip>)}</div></td>
                <td>
                  <Chip color={EXC_STATUS_COLOR[e.status] || "slate"}>{e.status?.replace("_"," ")}</Chip>
                  {e.status === "active" && e.days_until_expiry <= 7 && <div className="text-[10px] text-amber-400 mt-0.5">{e.days_until_expiry}d left</div>}
                  {e.status === "pending_approval" && e.awaiting_step_label && <div className="text-[10px] text-slate-500 mt-0.5">awaiting {e.awaiting_step_label}</div>}
                </td>
                <td className="text-slate-400 text-[11px]">{e.requested_by || e.approver}</td>
                <td className="font-mono text-[11px]">{fmtDate(e.expires_at)}</td>
                <td className="whitespace-nowrap" onClick={ev=>ev.stopPropagation()}>
                  {e.status === "pending_approval" && e.can_current_user_approve && (
                    <div className="flex gap-1">
                      <button onClick={()=>approve(e)} data-testid={`approve-exc-${e.id}`} className="h-6 px-2 text-[10.5px] bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 rounded">Approve</button>
                      <button onClick={()=>setRejecting(e)} data-testid={`reject-exc-${e.id}`} className="h-6 px-2 text-[10.5px] bg-red-500/20 border border-red-500/40 text-red-300 rounded">Reject</button>
                    </div>
                  )}
                  {(e.status === "active" || e.status === "expired") && (
                    <button onClick={()=>setRenewing(e)} data-testid={`renew-exc-${e.id}`} className="h-6 px-2 text-[10.5px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 text-slate-400 rounded">Renew</button>
                  )}
                </td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr><td colSpan={8} className="text-center text-slate-500 py-6 text-[12px]">No exceptions in this view.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      {renewing && <RenewModal exc={renewing} onClose={()=>setRenewing(null)} onDone={()=>{setRenewing(null); load();}} />}
      {rejecting && <RejectModal exc={rejecting} onClose={()=>setRejecting(null)} onDone={()=>{setRejecting(null); load();}} />}
    </Layout>
  );
}
