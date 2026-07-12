import { useEffect, useState, useCallback } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { SevBadge, Chip } from "@/components/Badges";
import {
  Siren, CaretLeft, CaretRight, X, Check, ArrowsClockwise, LinkSimple, MagnifyingGlass,
  PaperPlaneTilt, ArrowSquareOut,
} from "@phosphor-icons/react";

const PAGE_SIZE = 50;
const STATUS_OPTIONS = ["open", "acknowledged", "closed"];
const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low", "Info"];

// Security Alerts -- the triage queue over backend/security_events.py's event bus.
// Every module that calls emit_event() (login lockouts, new critical/high
// findings, YARA hits, and whatever else gets wired up next) shows up here as one
// normalized row; a "correlated_alert" row is what the bus's own correlation
// logic raises when 2+ different sources fire on the same asset/user/IP within
// 24h, so those already represent the bus's best guess at "this matters more
// than any one of its parts."

function EventDetail({ event, onClose, onChanged }) {
  const [busy, setBusy] = useState(false);
  const [reason, setReason] = useState("");
  const [webhooks, setWebhooks] = useState([]);
  const [tickets, setTickets] = useState(event.tickets || []);
  const [exporting, setExporting] = useState(null);

  useEffect(() => {
    api.get("/v1/admin/ticketing/webhooks").then(r => setWebhooks(r.data.items || [])).catch(() => {});
  }, []);

  const exportTo = async (target, webhookId) => {
    const key = target === "jira" ? "jira" : `webhook:${webhookId}`;
    setExporting(key);
    try {
      const r = await api.post(`/v1/security-events/${event.id}/export`, { target, webhook_id: webhookId });
      setTickets(prev => [...prev, r.data.ticket]);
      toast.success(target === "jira" ? `Jira issue ${r.data.ticket.ref} created` : `Sent to ${r.data.ticket.ref}`);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Export failed");
    } finally { setExporting(null); }
  };

  const act = async (action) => {
    setBusy(true);
    try {
      const body = action === "close" ? { reason: reason || undefined } : undefined;
      await api.post(`/v1/security-events/${event.id}/${action}`, body);
      toast.success(`Event ${action === "acknowledge" ? "acknowledged" : action === "close" ? "closed" : "reopened"}`);
      onChanged();
      onClose();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Action failed");
    } finally { setBusy(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-lg max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="flex items-center gap-2">
            <SevBadge severity={event.severity}/>
            <div className="text-[14px] text-slate-100 font-medium">{event.title}</div>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5 space-y-3">
          <div className="text-[12.5px] text-slate-300">{event.description}</div>
          <div className="grid grid-cols-2 gap-2 text-[11.5px]">
            <div><span className="text-slate-500">Source:</span> <span className="font-mono">{event.source}</span></div>
            <div><span className="text-slate-500">Type:</span> <span className="font-mono">{event.event_type}</span></div>
            <div><span className="text-slate-500">Entity:</span> {event.entity_label || event.entity_id || "—"}</div>
            <div><span className="text-slate-500">Occurrences:</span> {event.occurrence_count || 1}</div>
            <div><span className="text-slate-500">First seen:</span> {event.created_at ? new Date(event.created_at).toLocaleString() : "—"}</div>
            <div><span className="text-slate-500">Last seen:</span> {event.last_seen_at ? new Date(event.last_seen_at).toLocaleString() : "—"}</div>
          </div>
          {event.related_events?.length > 0 && (
            <div className="border-t border-[#30363D] pt-3">
              <div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-2 flex items-center gap-1.5">
                <LinkSimple size={12}/> Related events ({event.related_events.length})
              </div>
              <div className="space-y-1.5">
                {event.related_events.map(r => (
                  <div key={r.id} className="flex items-center gap-2 text-[11.5px]">
                    <SevBadge severity={r.severity}/>
                    <span className="text-slate-400 font-mono">{r.source}</span>
                    <span className="text-slate-300 truncate">{r.title}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          <div className="border-t border-[#30363D] pt-3">
            <div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-2 flex items-center gap-1.5">
              <PaperPlaneTilt size={12}/> Export to ticketing / SOAR
            </div>
            {tickets.length > 0 && (
              <div className="space-y-1 mb-2">
                {tickets.map((t, i) => (
                  <div key={i} className="flex items-center gap-1.5 text-[11.5px] text-slate-400">
                    <Check size={11} className="text-emerald-400"/> Sent to {t.system === "jira" ? "Jira" : t.ref} as
                    {t.url ? (
                      <a href={t.url} target="_blank" rel="noreferrer" className="text-blue-300 hover:underline inline-flex items-center gap-0.5">
                        {t.ref} <ArrowSquareOut size={10}/>
                      </a>
                    ) : <span className="font-mono">{t.ref}</span>}
                  </div>
                ))}
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              <button onClick={()=>exportTo("jira")} disabled={exporting === "jira"}
                className="h-8 px-2.5 text-[11.5px] border border-[#30363D] hover:border-blue-500/50 text-slate-300 rounded disabled:opacity-50">
                {exporting === "jira" ? "Sending…" : "Send to Jira"}
              </button>
              {webhooks.filter(w => w.enabled !== false).map(w => (
                <button key={w.id} onClick={()=>exportTo("webhook", w.id)} disabled={exporting === `webhook:${w.id}`}
                  className="h-8 px-2.5 text-[11.5px] border border-[#30363D] hover:border-blue-500/50 text-slate-300 rounded disabled:opacity-50">
                  {exporting === `webhook:${w.id}` ? "Sending…" : `Send to ${w.name}`}
                </button>
              ))}
            </div>
          </div>
          {event.status !== "closed" && (
            <div className="border-t border-[#30363D] pt-3">
              <input value={reason} onChange={e=>setReason(e.target.value)} placeholder="Close reason (optional)"
                className="w-full h-8 px-2.5 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100 mb-2"/>
              <div className="flex gap-2">
                {event.status === "open" && (
                  <button onClick={()=>act("acknowledge")} disabled={busy}
                    className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-blue-500/50 text-slate-300 rounded disabled:opacity-50">
                    Acknowledge
                  </button>
                )}
                <button onClick={()=>act("close")} disabled={busy}
                  className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded disabled:opacity-50 inline-flex items-center gap-1.5">
                  <Check size={13}/> Close
                </button>
              </div>
            </div>
          )}
          {event.status === "closed" && (
            <div className="border-t border-[#30363D] pt-3 flex items-center justify-between">
              <div className="text-[11px] text-slate-500">
                Closed by {event.closed_by} {event.closed_at ? new Date(event.closed_at).toLocaleString() : ""}
                {event.close_reason && ` — ${event.close_reason}`}
              </div>
              <button onClick={()=>act("reopen")} disabled={busy}
                className="h-7 px-2.5 text-[11px] border border-[#30363D] rounded text-slate-300 inline-flex items-center gap-1">
                <ArrowsClockwise size={11}/> Reopen
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function SecurityAlerts() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    const params = { limit: PAGE_SIZE, offset: page * PAGE_SIZE };
    if (status) params.status = status;
    if (severity) params.severity = severity;
    if (q) params.q = q;
    Promise.all([
      api.get("/v1/security-events", { params }),
      api.get("/v1/security-events/stats"),
    ]).then(([r, s]) => { setItems(r.data.items || []); setTotal(r.data.total || 0); setStats(s.data); })
      .catch(() => toast.error("Failed to load security alerts"))
      .finally(() => setLoading(false));
  }, [status, severity, q, page]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(0); }, [status, severity, q]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <Layout title="Security Alerts" subtitle="Correlated events across every module -- logins, findings, YARA, and more">
      {stats && (
        <div className="grid grid-cols-5 gap-2.5 mb-4">
          {["Critical", "High", "Medium", "Low", "Info"].map(sev => (
            <div key={sev} className="border border-[#30363D] bg-[#0D1117] rounded-md px-3 py-2.5">
              <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500">{sev}</div>
              <div className="text-[20px] font-semibold text-slate-100 mt-0.5">{stats.open_by_severity?.[sev] || 0}</div>
            </div>
          ))}
        </div>
      )}
      {stats?.correlated_open > 0 && (
        <div className="border border-orange-500/30 bg-orange-500/5 rounded-md px-3 py-2 mb-4 text-[12px] text-orange-200 flex items-center gap-2">
          <LinkSimple size={14}/> {stats.correlated_open} correlated alert(s) span multiple sources on the same asset/user/IP -- these usually deserve first look.
        </div>
      )}

      <div className="flex gap-2 mb-4 flex-wrap items-center">
        <div className="relative">
          <MagnifyingGlass size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500"/>
          <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search title/entity…"
            className="h-9 w-56 pl-8 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100"/>
        </div>
        <select value={status} onChange={e=>setStatus(e.target.value)} className="h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-200">
          <option value="">All statuses</option>
          {STATUS_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={severity} onChange={e=>setSeverity(e.target.value)} className="h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-200">
          <option value="">All severities</option>
          {SEVERITY_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          <Siren size={28} className="mx-auto mb-2 text-slate-600"/>
          No matching alerts.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
          {items.map(it => (
            <div key={it.id} onClick={()=>setSelected(it)}
              className="px-4 py-3 flex items-center justify-between gap-3 cursor-pointer hover:bg-slate-800/30">
              <div className="min-w-0 flex items-center gap-3">
                <SevBadge severity={it.severity}/>
                {it.event_type === "correlated_alert" && <Chip color="orange">Correlated</Chip>}
                <div className="min-w-0">
                  <div className="text-[12.5px] text-slate-200 truncate">{it.title}</div>
                  <div className="text-[11px] text-slate-500 mt-0.5">
                    {it.source} · {it.entity_label || it.entity_id || "—"}
                    {it.occurrence_count > 1 && ` · ${it.occurrence_count}x`}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <Chip color={it.status === "open" ? "red" : it.status === "acknowledged" ? "amber" : "slate"}>{it.status}</Chip>
                <div className="text-[11px] text-slate-500 font-mono">
                  {it.last_seen_at ? new Date(it.last_seen_at).toLocaleString() : "—"}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="flex items-center justify-between mt-4">
        <div className="text-[11.5px] text-slate-500">{total} alert(s)</div>
        <div className="flex items-center gap-2">
          <button onClick={()=>setPage(p=>Math.max(0,p-1))} disabled={page===0}
            className="h-8 w-8 flex items-center justify-center text-slate-400 hover:text-slate-200 disabled:opacity-30 rounded border border-[#30363D]">
            <CaretLeft size={14}/>
          </button>
          <span className="text-[11.5px] text-slate-500">Page {page+1} of {totalPages}</span>
          <button onClick={()=>setPage(p=>Math.min(totalPages-1,p+1))} disabled={page>=totalPages-1}
            className="h-8 w-8 flex items-center justify-center text-slate-400 hover:text-slate-200 disabled:opacity-30 rounded border border-[#30363D]">
            <CaretRight size={14}/>
          </button>
        </div>
      </div>

      {selected && <EventDetail event={selected} onClose={()=>setSelected(null)} onChanged={load}/>}
    </Layout>
  );
}
