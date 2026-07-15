import { useEffect, useState, useCallback } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { fmtDate, fmtRel } from "@/lib/utils-fmt";
import { MagnifyingGlass, UsersThree, UsersFour, Warning, Prohibit } from "@phosphor-icons/react";

export default function Directory() {
  const [tab, setTab] = useState("users");
  const [stats, setStats] = useState(null);
  const [users, setUsers] = useState({ items: [], total: 0 });
  const [groups, setGroups] = useState({ items: [], total: 0 });
  const [q, setQ] = useState("");
  const [staleOnly, setStaleOnly] = useState(false);
  const [disabledOnly, setDisabledOnly] = useState(false);
  const [page, setPage] = useState(1);
  const pageSize = 50;

  const loadStats = useCallback(() => {
    api.get("/v1/directory/stats").then(r => setStats(r.data)).catch(() => {});
  }, []);

  const loadUsers = useCallback(() => {
    api.get("/v1/directory/users", {
      params: { q: q || undefined, stale_only: staleOnly || undefined, disabled_only: disabledOnly || undefined, page, page_size: pageSize },
    }).then(r => setUsers(r.data)).catch(() => {});
  }, [q, staleOnly, disabledOnly, page]);

  const loadGroups = useCallback(() => {
    api.get("/v1/directory/groups", { params: { q: q || undefined } }).then(r => setGroups(r.data)).catch(() => {});
  }, [q]);

  useEffect(() => { loadStats(); }, [loadStats]);
  useEffect(() => { if (tab === "users") loadUsers(); }, [tab, loadUsers]);
  useEffect(() => { if (tab === "groups") loadGroups(); }, [tab, loadGroups]);
  useEffect(() => { setPage(1); }, [q, staleOnly, disabledOnly]);

  const noData = stats && stats.total_users === 0;

  return (
    <Layout title="Directory" subtitle="Users and groups synced from Microsoft Entra ID, with stale-account detection">
      {noData && (
        <div className="mb-4 rounded-md border border-[#30363D] bg-[#0D1117] px-4 py-3 text-[12.5px] text-slate-400">
          No directory data yet. Configure tenant ID / client ID / client secret under{" "}
          <a href="/integrations" className="text-blue-300 hover:text-blue-200">Integrations → Microsoft Entra ID</a>{" "}
          and run "Sync now" to pull users and groups.
        </div>
      )}

      {stats && !noData && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-4">
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3">
            <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Total Users</div>
            <div className="text-[20px] font-medium text-slate-100 mt-1">{stats.total_users}</div>
          </div>
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3">
            <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider flex items-center gap-1"><Warning size={11} className="text-amber-400" /> Stale Accounts</div>
            <div className="text-[20px] font-medium text-amber-300 mt-1">{stats.stale_users}</div>
          </div>
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3">
            <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider flex items-center gap-1"><Prohibit size={11} /> Disabled Accounts</div>
            <div className="text-[20px] font-medium text-slate-300 mt-1">{stats.disabled_users}</div>
          </div>
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3">
            <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Groups</div>
            <div className="text-[20px] font-medium text-slate-100 mt-1">{stats.total_groups}</div>
            <div className="text-[10px] text-slate-500 mt-1">Last synced {fmtRel(stats.last_synced_at)}</div>
          </div>
        </div>
      )}

      <div className="flex items-center gap-2 mb-3">
        <button onClick={() => setTab("users")}
          className={`h-8 px-3 text-[12px] rounded border ${tab === "users" ? "bg-blue-500/15 border-blue-500/40 text-blue-300" : "border-[#30363D] text-slate-400"}`}>
          <UsersThree size={13} className="inline mr-1" /> Users
        </button>
        <button onClick={() => setTab("groups")}
          className={`h-8 px-3 text-[12px] rounded border ${tab === "groups" ? "bg-blue-500/15 border-blue-500/40 text-blue-300" : "border-[#30363D] text-slate-400"}`}>
          <UsersFour size={13} className="inline mr-1" /> Groups
        </button>
        <div className="flex-1" />
        <div className="relative">
          <MagnifyingGlass size={13} className="absolute left-2 top-2.5 text-slate-500" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search…"
            className="h-8 pl-7 pr-2 text-[12px] bg-[#161B22] border border-[#30363D] rounded text-slate-200 w-56" />
        </div>
        {tab === "users" && (
          <>
            <label className="flex items-center gap-1.5 text-[11.5px] text-slate-400">
              <input type="checkbox" checked={staleOnly} onChange={e => setStaleOnly(e.target.checked)} /> Stale only
            </label>
            <label className="flex items-center gap-1.5 text-[11.5px] text-slate-400">
              <input type="checkbox" checked={disabledOnly} onChange={e => setDisabledOnly(e.target.checked)} /> Disabled only
            </label>
          </>
        )}
      </div>

      {tab === "users" && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
          <table className="dense w-full">
            <thead><tr><th className="text-left">Name</th><th className="text-left">UPN / Email</th><th>Status</th><th>Stale</th><th>Last Sign-in</th><th>Created</th></tr></thead>
            <tbody>
              {users.items.map(u => (
                <tr key={u.id} className="border-t border-[#30363D]">
                  <td className="text-slate-200">{u.display_name}</td>
                  <td className="font-mono text-[11.5px] text-slate-400">{u.upn || u.email || "—"}</td>
                  <td><Chip color={u.enabled ? "green" : "slate"}>{u.enabled ? "enabled" : "disabled"}</Chip></td>
                  <td>{u.is_stale ? <Chip color="amber">stale</Chip> : <span className="text-slate-600">—</span>}</td>
                  <td className="text-[11px] text-slate-400">{u.last_sign_in_at ? fmtRel(u.last_sign_in_at) : "never / unknown"}</td>
                  <td className="font-mono text-[11px] text-slate-500">{fmtDate(u.created_at)}</td>
                </tr>
              ))}
              {users.items.length === 0 && (
                <tr><td colSpan={6} className="text-center text-slate-500 py-6 text-[12px]">No users found.</td></tr>
              )}
            </tbody>
          </table>
          {users.total > pageSize && (
            <div className="px-4 py-2 flex items-center justify-between border-t border-[#30363D] text-[11px] text-slate-400">
              <span>Page {page} of {Math.ceil(users.total / pageSize)} · {users.total} total</span>
              <div className="flex gap-1.5">
                <button disabled={page <= 1} onClick={() => setPage(p => p - 1)} className="h-7 px-2 border border-[#30363D] rounded disabled:opacity-40">Prev</button>
                <button disabled={page >= Math.ceil(users.total / pageSize)} onClick={() => setPage(p => p + 1)} className="h-7 px-2 border border-[#30363D] rounded disabled:opacity-40">Next</button>
              </div>
            </div>
          )}
        </div>
      )}

      {tab === "groups" && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
          <table className="dense w-full">
            <thead><tr><th className="text-left">Name</th><th>Security-enabled</th><th>Mail-enabled</th><th className="text-left">Types</th></tr></thead>
            <tbody>
              {groups.items.map(g => (
                <tr key={g.id} className="border-t border-[#30363D]">
                  <td className="text-slate-200">{g.display_name}</td>
                  <td><Chip color={g.security_enabled ? "blue" : "slate"}>{g.security_enabled ? "yes" : "no"}</Chip></td>
                  <td><Chip color={g.mail_enabled ? "blue" : "slate"}>{g.mail_enabled ? "yes" : "no"}</Chip></td>
                  <td className="text-[11px] text-slate-400">{(g.group_types || []).join(", ") || "—"}</td>
                </tr>
              ))}
              {groups.items.length === 0 && (
                <tr><td colSpan={4} className="text-center text-slate-500 py-6 text-[12px]">No groups found.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </Layout>
  );
}
