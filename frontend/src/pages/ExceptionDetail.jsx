import { useEffect, useState, useCallback } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import Layout from "@/components/Layout";
import { Chip, SevBadge } from "@/components/Badges";
import { fmtDate, fmtRel } from "@/lib/utils-fmt";
import {
  ArrowLeft, CheckCircle, XCircle, ArrowClockwise, Clock, Ticket as TicketIcon,
  User, EnvelopeSimple, ShieldCheck, X,
} from "@phosphor-icons/react";

const STATUS_COLOR = { pending_approval: "amber", active: "green", expired: "slate", rejected: "red", revoked: "red" };

const ACTION_META = {
  exception_requested: { label: "Requested", color: "blue" },
  exception_approved: { label: "Approved", color: "green" },
  exception_rejected: { label: "Rejected", color: "red" },
  exception_renewal_requested: { label: "Renewal requested", color: "amber" },
  exception_expired: { label: "Expired", color: "slate" },
  exception_reminder_sent: { label: "Reminder sent", color: "purple" },
};

function ApproveModal({ exc, onClose, onDone }) {
  const [justification, setJustification] = useState("");
  const [saving, setSaving] = useState(false);
  const submit = async () => {
    setSaving(true);
    try {
      const r = await api.post(`/v1/exceptions/${exc.id}/approve`, { justification });
      toast.success(`Approved — ticket ${r.data.ticket_external_id} created.`);
      onDone();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to approve");
    } finally { setSaving(false); }
  };
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-sm" onClick={e => e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between">
          <h3 className="text-[13px] font-medium text-slate-100">Approve risk acceptance</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16}/></button>
        </div>
        <div className="p-4">
          <label className="text-[11px] uppercase font-mono text-slate-500">Justification (optional)</label>
          <textarea value={justification} onChange={e => setJustification(e.target.value)} rows={3} data-testid="approve-justification"
            className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200"/>
        </div>
        <div className="px-4 py-3 border-t border-[#30363D] flex justify-end gap-2">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={submit} disabled={saving} data-testid="approve-submit"
            className="h-8 px-3 text-[12px] bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300 rounded disabled:opacity-50">
            {saving ? "Approving…" : "Approve"}
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
      toast.success("Rejected.");
      onDone();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to reject");
    } finally { setSaving(false); }
  };
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-sm" onClick={e => e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between">
          <h3 className="text-[13px] font-medium text-slate-100">Reject risk acceptance</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16}/></button>
        </div>
        <div className="p-4">
          <label className="text-[11px] uppercase font-mono text-slate-500">Reason</label>
          <textarea value={reason} onChange={e => setReason(e.target.value)} rows={3} data-testid="reject-reason"
            className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200"/>
        </div>
        <div className="px-4 py-3 border-t border-[#30363D] flex justify-end gap-2">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={submit} disabled={saving} data-testid="reject-submit"
            className="h-8 px-3 text-[12px] bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-300 rounded disabled:opacity-50">
            {saving ? "Rejecting…" : "Reject"}
          </button>
        </div>
      </div>
    </div>
  );
}

function RenewModal({ exc, onClose, onDone }) {
  const [newDate, setNewDate] = useState("");
  const [justification, setJustification] = useState("");
  const [saving, setSaving] = useState(false);
  const submit = async () => {
    if (!newDate || !justification.trim()) { toast.error("New expiry date and justification are required"); return; }
    setSaving(true);
    try {
      await api.post(`/v1/exceptions/${exc.id}/renew`, { new_expires_at: new Date(newDate).toISOString(), justification });
      toast.success("Renewal requested — pending approval.");
      onDone();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to request renewal");
    } finally { setSaving(false); }
  };
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-sm" onClick={e => e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between">
          <h3 className="text-[13px] font-medium text-slate-100">Renew risk acceptance</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16}/></button>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">New expiry date</label>
            <input type="date" value={newDate} onChange={e => setNewDate(e.target.value)}
              className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200"/>
          </div>
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Why does this still need an exception?</label>
            <textarea value={justification} onChange={e => setJustification(e.target.value)} rows={3}
              className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200"/>
          </div>
        </div>
        <div className="px-4 py-3 border-t border-[#30363D] flex justify-end gap-2">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={submit} disabled={saving}
            className="h-8 px-3 text-[12px] bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/40 text-blue-200 rounded disabled:opacity-50">
            {saving ? "Submitting…" : "Request renewal"}
          </button>
        </div>
      </div>
    </div>
  );
}

function RevokeModal({ exc, onClose, onDone }) {
  const [reason, setReason] = useState("");
  const [saving, setSaving] = useState(false);
  const submit = async () => {
    if (!reason.trim()) { toast.error("A reason is required"); return; }
    setSaving(true);
    try {
      const r = await api.post(`/v1/exceptions/${exc.id}/revoke`, { reason });
      toast.success(`Revoked — ${r.data.findings_reopened} finding(s) reopened.`);
      onDone();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to revoke");
    } finally { setSaving(false); }
  };
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-sm" onClick={e => e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between">
          <h3 className="text-[13px] font-medium text-slate-100">Revoke risk acceptance</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16}/></button>
        </div>
        <div className="p-4">
          <div className="text-[11.5px] text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded p-2 mb-3">
            This denies an already-approved risk acceptance before its normal expiry. Every attached finding reopens
            immediately and the team is notified.
          </div>
          <label className="text-[11px] uppercase font-mono text-slate-500">Reason</label>
          <textarea value={reason} onChange={e => setReason(e.target.value)} rows={3} data-testid="revoke-reason"
            placeholder="e.g. exploitation activity has escalated since approval"
            className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200"/>
        </div>
        <div className="px-4 py-3 border-t border-[#30363D] flex justify-end gap-2">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={submit} disabled={saving} data-testid="revoke-submit"
            className="h-8 px-3 text-[12px] bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-300 rounded disabled:opacity-50">
            {saving ? "Revoking…" : "Revoke"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ExceptionDetail() {
  const { id } = useParams();
  const { user } = useAuth();
  const navigate = useNavigate();
  const [exc, setExc] = useState(null);
  const [modal, setModal] = useState(null); // "approve" | "reject" | "renew" | "revoke"
  const canApprove = !!exc?.can_current_user_approve;
  const canRevoke = user?.role === "admin" || user?.role === "manager";

  const load = useCallback(() => {
    api.get(`/v1/exceptions/${id}`).then(r => setExc(r.data)).catch(() => setExc(false));
  }, [id]);
  useEffect(() => { load(); }, [load]);

  if (exc === false) return <Layout title="Risk Acceptance"><div className="text-slate-500 text-center py-10">Not found.</div></Layout>;
  if (!exc) return <Layout title="Risk Acceptance"><div className="text-slate-500 text-center py-10">Loading…</div></Layout>;

  const targetSummary = exc.finding_count > 1
    ? `${exc.finding_count} findings — ${exc.target_type}: ${exc.target_value}`
    : (exc.finding_title || exc.finding_id);

  return (
    <Layout title="Risk Acceptance Detail" subtitle={targetSummary}
      actions={<button onClick={() => navigate("/exceptions")} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300"><ArrowLeft size={14}/> Back</button>}>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-4">

          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="flex items-center justify-between flex-wrap gap-2 mb-3">
              <div className="flex items-center gap-2">
                <Chip color={STATUS_COLOR[exc.status] || "slate"}>{exc.status?.replace("_", " ")}</Chip>
                <Chip color="slate">{exc.target_type}</Chip>
                {exc.status === "active" && exc.days_until_expiry <= 7 && (
                  <span className="text-[11px] text-amber-400 flex items-center gap-1"><Clock size={12}/> {exc.days_until_expiry}d left</span>
                )}
              </div>
              <div className="flex gap-2">
                {exc.status === "pending_approval" && canApprove && (
                  <>
                    <button onClick={() => setModal("approve")} data-testid="detail-approve-btn"
                      className="h-8 px-3 text-[12px] bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 rounded inline-flex items-center gap-1.5"><CheckCircle size={14}/> Approve</button>
                    <button onClick={() => setModal("reject")} data-testid="detail-reject-btn"
                      className="h-8 px-3 text-[12px] bg-red-500/20 border border-red-500/40 text-red-300 rounded inline-flex items-center gap-1.5"><XCircle size={14}/> Reject</button>
                  </>
                )}
                {(exc.status === "active" || exc.status === "expired") && (
                  <button onClick={() => setModal("renew")} data-testid="detail-renew-btn"
                    className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 text-slate-400 rounded inline-flex items-center gap-1.5"><ArrowClockwise size={14}/> Renew</button>
                )}
                {exc.status === "active" && canRevoke && (
                  <button onClick={() => setModal("revoke")} data-testid="detail-revoke-btn"
                    className="h-8 px-3 text-[12px] border border-red-500/30 hover:bg-red-500/10 text-red-400 rounded inline-flex items-center gap-1.5"><XCircle size={14}/> Revoke</button>
                )}
              </div>
            </div>

            {exc.status === "pending_approval" && exc.approval_chain?.length > 0 && (
              <div className="flex items-center gap-1.5 flex-wrap mb-3" data-testid="approval-chain-stepper">
                {exc.approval_chain.map((s, i) => (
                  <div key={i} className="flex items-center gap-1.5">
                    <div className={`px-2 py-1 rounded border text-[11px] flex items-center gap-1.5 ${
                      s.status === "approved" ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                      : s.status === "pending" && i === exc.approval_chain.findIndex(x => x.status === "pending")
                        ? "border-amber-500/40 bg-amber-500/10 text-amber-300" : "border-[#30363D] text-slate-500"
                    }`}>
                      {s.status === "approved" ? <CheckCircle size={12}/> : <Clock size={12}/>}
                      Step {s.step}: {s.role === "specific" ? s.approver_email : s.role}
                      {s.status === "approved" && <span className="text-slate-500">· {s.by}</span>}
                    </div>
                    {i < exc.approval_chain.length - 1 && <span className="text-slate-600">→</span>}
                  </div>
                ))}
              </div>
            )}
            {exc.status === "pending_approval" && !canApprove && exc.awaiting_step_label && (
              <div className="text-[11.5px] text-slate-500 mb-3">Awaiting approval from <span className="text-slate-300">{exc.awaiting_step_label}</span> — you aren't able to act on this step.</div>
            )}
            {exc.status === "revoked" && (
              <div className="text-[12px] text-red-300 bg-red-500/10 border border-red-500/30 rounded p-2 mb-3">
                Revoked by {exc.revoked_by} on {fmtDate(exc.revoked_at)}: {exc.revocation_reason}
              </div>
            )}

            <div className="text-[12.5px] text-slate-300 whitespace-pre-wrap">{exc.business_justification || exc.rationale}</div>
            {exc.approval_justification && (
              <div className="mt-2 text-[12px] text-emerald-300 border-l-2 border-emerald-500/40 pl-2">Approver's note: {exc.approval_justification}</div>
            )}
            {exc.rejection_reason && (
              <div className="mt-2 text-[12px] text-red-300 border-l-2 border-red-500/40 pl-2">Rejection reason: {exc.rejection_reason}</div>
            )}
            {(exc.compensating_controls || []).length > 0 && (
              <div className="mt-2 flex gap-1 flex-wrap">{exc.compensating_controls.map(c => <Chip key={c} color="blue">{c}</Chip>)}</div>
            )}

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 pt-3 border-t border-[#30363D] text-[11.5px]">
              <div><div className="text-slate-500 uppercase font-mono text-[10px]">Requested by</div><div className="text-slate-300 mt-0.5">{exc.requested_by}</div></div>
              <div><div className="text-slate-500 uppercase font-mono text-[10px]">Requested</div><div className="text-slate-300 mt-0.5">{fmtDate(exc.requested_at)}</div></div>
              <div><div className="text-slate-500 uppercase font-mono text-[10px]">Approver</div><div className="text-slate-300 mt-0.5">{exc.approver || "—"}</div></div>
              <div><div className="text-slate-500 uppercase font-mono text-[10px]">Expires</div><div className="text-slate-300 mt-0.5">{fmtDate(exc.expires_at)}</div></div>
            </div>

            {(exc.contact_name || exc.contact_email) && (
              <div className="mt-3 pt-3 border-t border-[#30363D] flex gap-4 text-[11.5px] text-slate-400">
                {exc.contact_name && <span className="flex items-center gap-1.5"><User size={13}/> {exc.contact_name}</span>}
                {exc.contact_email && <span className="flex items-center gap-1.5"><EnvelopeSimple size={13}/> {exc.contact_email}</span>}
              </div>
            )}
          </div>

          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="text-[13px] font-medium text-slate-100 mb-2">Attached findings ({exc.findings?.length || 0})</div>
            <div className="space-y-1.5">
              {(exc.findings || []).map(f => (
                <Link key={f.id} to={`/findings/${f.id}`} className="flex items-center gap-2 border border-[#30363D] rounded px-2.5 py-1.5 hover:border-[#484F58]">
                  <SevBadge severity={f.severity} />
                  <span className="text-[12px] text-slate-200 truncate flex-1">{f.title}</span>
                  <span className="text-[10.5px] font-mono text-slate-500">{f.asset_hostname}</span>
                </Link>
              ))}
              {(!exc.findings || exc.findings.length === 0) && <div className="text-[12px] text-slate-500">No findings attached.</div>}
            </div>
          </div>

          {(exc.evidence_files || []).length > 0 && (
            <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
              <div className="text-[13px] font-medium text-slate-100 mb-2">Evidence</div>
              <div className="flex flex-wrap gap-2">
                {exc.evidence_files.map((a, i) => a.mime?.startsWith("image/") ? (
                  <a key={i} href={a.data_url} target="_blank" rel="noopener noreferrer" title={a.name}>
                    <img src={a.data_url} alt={a.name} className="max-h-28 rounded border border-[#30363D] hover:border-blue-500/50"/>
                  </a>
                ) : (
                  <a key={i} href={a.data_url} download={a.name} className="text-[11.5px] text-blue-300 hover:underline">📎 {a.name}</a>
                ))}
              </div>
            </div>
          )}

          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="text-[13px] font-medium text-slate-100 mb-3">Timeline</div>
            <div className="space-y-3">
              {(exc.timeline || []).map(t => {
                const meta = ACTION_META[t.action] || { label: t.action, color: "slate" };
                return (
                  <div key={t.id} className="flex gap-2.5">
                    <div className="w-1.5 h-1.5 rounded-full bg-slate-600 mt-1.5 shrink-0"/>
                    <div>
                      <div className="flex items-center gap-2">
                        <Chip color={meta.color}>{meta.label}</Chip>
                        <span className="text-[10.5px] font-mono text-slate-500">{t.actor} · {fmtDate(t.timestamp)}</span>
                      </div>
                      <div className="text-[12px] text-slate-300 mt-0.5">{t.details}</div>
                    </div>
                  </div>
                );
              })}
              {(!exc.timeline || exc.timeline.length === 0) && <div className="text-[12px] text-slate-500">No activity yet.</div>}
            </div>
          </div>
        </div>

        <div className="space-y-4">
          {exc.ticket && (
            <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
              <div className="text-[13px] font-medium text-slate-100 mb-2 flex items-center gap-1.5"><TicketIcon size={15}/> Ticket</div>
              <div className="text-[12.5px] font-mono text-blue-300">{exc.ticket.external_id}</div>
              <div className="text-[12px] text-slate-300 mt-1">{exc.ticket.title}</div>
              <Chip color={exc.ticket.status === "open" ? "amber" : exc.ticket.status === "reopened" ? "red" : "slate"}>{exc.ticket.status}</Chip>
            </div>
          )}
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="text-[13px] font-medium text-slate-100 mb-2 flex items-center gap-1.5"><ShieldCheck size={15}/> Reminder</div>
            <div className="text-[12px] text-slate-400">
              {exc.reminder_sent ? "Expiry reminder already sent." : `Will remind ${exc.reminder_days_before || 7} day(s) before expiry.`}
            </div>
          </div>
          {(exc.renewal_history || []).length > 0 && (
            <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
              <div className="text-[13px] font-medium text-slate-100 mb-2">Renewal history</div>
              <div className="space-y-2">
                {exc.renewal_history.map((r, i) => (
                  <div key={i} className="text-[11.5px] text-slate-400 border-l-2 border-[#30363D] pl-2">
                    <div>{fmtDate(r.previous_expires_at)} → {fmtDate(r.requested_new_expires_at)}</div>
                    <div className="text-slate-500">{r.justification}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {modal === "approve" && <ApproveModal exc={exc} onClose={() => setModal(null)} onDone={() => { setModal(null); load(); }} />}
      {modal === "reject" && <RejectModal exc={exc} onClose={() => setModal(null)} onDone={() => { setModal(null); load(); }} />}
      {modal === "renew" && <RenewModal exc={exc} onClose={() => setModal(null)} onDone={() => { setModal(null); load(); }} />}
      {modal === "revoke" && <RevokeModal exc={exc} onClose={() => setModal(null)} onDone={() => { setModal(null); load(); }} />}
    </Layout>
  );
}
