import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Link } from "react-router-dom";
import { Notepad, CaretLeft, CaretRight, SignIn, CheckCircle, XCircle, X, Globe, Monitor, Translate, User, Funnel } from "@phosphor-icons/react";

const PAGE_SIZE = 50;

const ACTION_COLOR = (action) => {
  if (!action) return "slate";
  if (action.includes("chatops")) return "purple";
  if (action.includes("automation")) return "blue";
  if (action.includes("exception")) return "amber";
  if (action.includes("status")) return "green";
  return "slate";
};

function LoginAttemptDetail({ item, onClose, onFilterIp, onFilterEmail }) {
  if (!item) return null;
  const row = (label, value, icon) => (
    <div className="flex items-start gap-2.5 py-2 border-b border-[#30363D]/60 last:border-0">
      <div className="text-slate-500 mt-0.5 shrink-0">{icon}</div>
      <div className="min-w-0">
        <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500">{label}</div>
        <div className="text-[12.5px] text-slate-200 break-all">{value ?? "—"}</div>
      </div>
    </div>
  );
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-md max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="flex items-center gap-2">
            {item.success ? <CheckCircle size={16} className="text-emerald-400"/> : <XCircle size={16} className="text-red-400"/>}
            <div className="text-[14px] text-slate-100 font-medium">{item.success ? "Successful login" : "Failed login"}</div>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5">
          {!item.success && item.reason && (
            <div className="border border-red-500/30 bg-red-500/5 rounded-md px-3 py-2 mb-3 text-[12px] text-red-300">
              Reason: {item.reason}
            </div>
          )}
          {row("Email", item.email, <User size={14}/>)}
          {row("User ID", item.user_id, <User size={14}/>)}
          {row("IP address", item.ip, <Globe size={14}/>)}
          {row("User agent", item.user_agent, <Monitor size={14}/>)}
          {row("Accept-language", item.accept_language, <Translate size={14}/>)}
          {row("Timestamp", item.timestamp ? new Date(item.timestamp).toLocaleString() : "—", <SignIn size={14}/>)}

          <div className="mt-4 flex flex-wrap gap-2">
            {item.ip && (
              <button onClick={() => onFilterIp(item.ip)}
                className="h-8 px-3 text-[11.5px] border border-[#30363D] hover:border-[#484F58] text-slate-300 rounded inline-flex items-center gap-1.5">
                <Funnel size={12}/> Other attempts from this IP
              </button>
            )}
            {item.email && (
              <button onClick={() => onFilterEmail(item.email)}
                className="h-8 px-3 text-[11.5px] border border-[#30363D] hover:border-[#484F58] text-slate-300 rounded inline-flex items-center gap-1.5">
                <Funnel size={12}/> Other attempts by this email
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function LoginAuditTab() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [email, setEmail] = useState("");
  const [outcome, setOutcome] = useState(""); // "" | "success" | "failed"
  const [ipFilter, setIpFilter] = useState("");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState(null); // login_audit row shown in detail modal

  const load = async () => {
    setLoading(true);
    try {
      const params = { limit: PAGE_SIZE, offset: page * PAGE_SIZE };
      if (email) params.email = email;
      if (outcome) params.success = outcome === "success";
      if (ipFilter) params.ip = ipFilter;
      const r = await api.get("/v1/admin/login-audit", { params });
      setItems(r.data.items || []);
      setTotal(r.data.total || 0);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to load login attempts");
    } finally { setLoading(false); }
  };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { load(); }, [page, email, outcome, ipFilter]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const filterByIp = (ip) => { setSelected(null); setEmail(""); setIpFilter(ip); setPage(0); };
  const filterByEmail = (em) => { setSelected(null); setIpFilter(""); setEmail(em); setPage(0); };

  return (
    <div>
      <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3 py-2.5 mb-4 text-[12px] text-blue-200 leading-relaxed">
        Every login attempt, successful or not, with IP, user-agent, and browser language — the full set of metadata a
        standard web login actually exposes. A MAC address can't be captured here: it's link-layer information that
        never survives a router hop, and no browser API exposes it, so it's intentionally not tracked.
      </div>
      <div className="flex gap-2 mb-4 flex-wrap items-center">
        <input value={email} onChange={e => { setEmail(e.target.value); setPage(0); }}
          placeholder="Filter by email…"
          className="h-9 w-56 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100"/>
        <select value={outcome} onChange={e => { setOutcome(e.target.value); setPage(0); }}
          className="h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-200">
          <option value="">All outcomes</option>
          <option value="success">Successful</option>
          <option value="failed">Failed</option>
        </select>
        {ipFilter && (
          <div className="h-9 px-3 flex items-center gap-2 bg-blue-500/10 border border-blue-500/30 rounded text-[12px] text-blue-200 font-mono">
            IP: {ipFilter}
            <button onClick={() => { setIpFilter(""); setPage(0); }} className="text-blue-300 hover:text-blue-100"><X size={12}/></button>
          </div>
        )}
      </div>
      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          <SignIn size={28} className="mx-auto mb-2 text-slate-600"/>
          No matching login attempts.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
          {items.map(it => (
            <div key={it.id} onClick={() => setSelected(it)}
              className="px-4 py-3 flex items-start justify-between gap-3 cursor-pointer hover:bg-slate-800/30">
              <div className="min-w-0 flex items-start gap-2">
                {it.success ? <CheckCircle size={15} className="text-emerald-400 shrink-0 mt-0.5"/> : <XCircle size={15} className="text-red-400 shrink-0 mt-0.5"/>}
                <div>
                  <div className="text-[12.5px] text-slate-200 font-mono">{it.email || "—"}</div>
                  <div className="text-[11px] text-slate-500 mt-0.5">
                    {it.ip || "unknown ip"} · {it.user_agent || "unknown client"}
                    {!it.success && it.reason && <span className="text-red-400"> · {it.reason}</span>}
                  </div>
                </div>
              </div>
              <div className="text-[11px] text-slate-500 shrink-0 font-mono">
                {it.timestamp ? new Date(it.timestamp).toLocaleString() : "—"}
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="flex items-center justify-between mt-4">
        <div className="text-[11.5px] text-slate-500">{total} total attempt(s)</div>
        <div className="flex items-center gap-2">
          <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
            className="h-8 w-8 flex items-center justify-center text-slate-400 hover:text-slate-200 disabled:opacity-30 rounded border border-[#30363D]">
            <CaretLeft size={14}/>
          </button>
          <span className="text-[11.5px] text-slate-500">Page {page + 1} of {totalPages}</span>
          <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}
            className="h-8 w-8 flex items-center justify-center text-slate-400 hover:text-slate-200 disabled:opacity-30 rounded border border-[#30363D]">
            <CaretRight size={14}/>
          </button>
        </div>
      </div>
      <LoginAttemptDetail item={selected} onClose={() => setSelected(null)} onFilterIp={filterByIp} onFilterEmail={filterByEmail}/>
    </div>
  );
}

export default function AuditLog() {
  const [tab, setTab] = useState("activity"); // "activity" | "logins"
  const [items, setItems] = useState([]);
  const [actions, setActions] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ actor: "", action: "", entity_type: "" });
  const [page, setPage] = useState(0);

  const load = async () => {
    setLoading(true);
    try {
      const params = { limit: PAGE_SIZE, offset: page * PAGE_SIZE };
      if (filters.actor) params.actor = filters.actor;
      if (filters.action) params.action = filters.action;
      if (filters.entity_type) params.entity_type = filters.entity_type;
      const r = await api.get("/v1/admin/audit-log", { params });
      setItems(r.data.items || []);
      setActions(r.data.actions || []);
      setTotal(r.data.total || 0);
    } catch (e) {
      toast.error("Failed to load audit log");
    } finally { setLoading(false); }
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { if (tab === "activity") load(); }, [tab, page, filters.actor, filters.action, filters.entity_type]);

  const updateFilter = (patch) => { setFilters(f => ({ ...f, ...patch })); setPage(0); };

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <Layout title="Audit Log" subtitle="Everything that's happened across the system — status changes, assignments, exceptions, automation, ChatOps actions, and login attempts">
      <div className="flex gap-1 border-b border-[#30363D] mb-5">
        {[{ key: "activity", label: "System Activity" }, { key: "logins", label: "Login Attempts" }].map(t => (
          <button key={t.key} onClick={() => setTab(t.key)}
            className={`px-4 py-2 text-[13px] border-b-2 -mb-px transition-colors ${
              tab === t.key ? "border-blue-500 text-blue-300" : "border-transparent text-slate-500 hover:text-slate-300"
            }`}>
            {t.label}
          </button>
        ))}
      </div>
      {tab === "logins" ? <LoginAuditTab/> : <>
      <div className="flex gap-2 mb-4 flex-wrap">
        <input value={filters.actor} onChange={e => updateFilter({ actor: e.target.value })}
          placeholder="Filter by actor…"
          className="h-9 w-52 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100"/>
        <select value={filters.action} onChange={e => updateFilter({ action: e.target.value })}
          className="h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-200">
          <option value="">All actions</option>
          {actions.map(a => <option key={a} value={a}>{a}</option>)}
        </select>
        <select value={filters.entity_type} onChange={e => updateFilter({ entity_type: e.target.value })}
          className="h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-200">
          <option value="">All entity types</option>
          <option value="finding">Finding</option>
          <option value="asset">Asset</option>
          <option value="risk">Risk</option>
          <option value="albert_allowlist">Albert Allowlist</option>
          <option value="albert_alert">Albert Alert</option>
        </select>
      </div>

      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          <Notepad size={28} className="mx-auto mb-2 text-slate-600"/>
          No matching activity.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
          {items.map(it => (
            <div key={it.id} className="px-4 py-3 flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <Chip color={ACTION_COLOR(it.action)}>{it.action}</Chip>
                  <span className="text-[11.5px] text-slate-400 font-mono">{it.actor}</span>
                  {it.entity_type === "finding" && it.entity_id && (
                    <Link to={`/findings/${it.entity_id}`} className="text-[11px] text-blue-300 hover:underline font-mono">
                      {it.entity_id.slice(0, 8)}
                    </Link>
                  )}
                </div>
                <div className="text-[12.5px] text-slate-300">{it.details || "—"}</div>
              </div>
              <div className="text-[11px] text-slate-500 shrink-0 font-mono">
                {it.timestamp ? new Date(it.timestamp).toLocaleString() : "—"}
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="flex items-center justify-between mt-4">
        <div className="text-[11.5px] text-slate-500">{total} total event(s)</div>
        <div className="flex items-center gap-2">
          <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
            className="h-8 w-8 flex items-center justify-center text-slate-400 hover:text-slate-200 disabled:opacity-30 rounded border border-[#30363D]">
            <CaretLeft size={14}/>
          </button>
          <span className="text-[11.5px] text-slate-500">Page {page + 1} of {totalPages}</span>
          <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}
            className="h-8 w-8 flex items-center justify-center text-slate-400 hover:text-slate-200 disabled:opacity-30 rounded border border-[#30363D]">
            <CaretRight size={14}/>
          </button>
        </div>
      </div>
      </>}
    </Layout>
  );
}
