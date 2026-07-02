import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Link } from "react-router-dom";
import { Notepad, CaretLeft, CaretRight } from "@phosphor-icons/react";

const PAGE_SIZE = 50;

const ACTION_COLOR = (action) => {
  if (!action) return "slate";
  if (action.includes("chatops")) return "purple";
  if (action.includes("automation")) return "blue";
  if (action.includes("exception")) return "amber";
  if (action.includes("status")) return "green";
  return "slate";
};

export default function AuditLog() {
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
  useEffect(() => { load(); }, [page, filters.actor, filters.action, filters.entity_type]);

  const updateFilter = (patch) => { setFilters(f => ({ ...f, ...patch })); setPage(0); };

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <Layout title="Audit Log" subtitle="Everything that's happened across the system — status changes, assignments, exceptions, automation, ChatOps actions">
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
    </Layout>
  );
}
