import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  Plus, X, Trash, CircleNotch, Binoculars, UploadSimple, Siren, MagnifyingGlass,
} from "@phosphor-icons/react";

const IOC_TYPES = ["ip", "domain", "hash", "url"];
const SEVERITIES = ["Info", "Low", "Medium", "High", "Critical"];

const SEVERITY_COLOR = { Info: "slate", Low: "blue", Medium: "amber", High: "orange", Critical: "red" };

export default function ThreatIntelWatchlist() {
  const [items, setItems] = useState([]);
  const [stats, setStats] = useState(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState("");
  const [q, setQ] = useState("");
  const [addOpen, setAddOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [syncing, setSyncing] = useState(false);

  const load = async () => {
    try {
      const params = {};
      if (typeFilter) params.ioc_type = typeFilter;
      if (q.trim()) params.q = q.trim();
      const [r, s] = await Promise.all([
        api.get("/v1/admin/threat-intel/watchlist", { params }),
        api.get("/v1/admin/threat-intel/stats"),
      ]);
      setItems(r.data.items || []);
      setTotal(r.data.total || 0);
      setStats(s.data);
    } catch (e) {
      toast.error("Failed to load watchlist");
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, [typeFilter]);

  const search = (e) => { e.preventDefault(); load(); };

  const removeIoc = async (item) => {
    if (!window.confirm(`Remove "${item.value}" from the watchlist?`)) return;
    await api.delete(`/v1/admin/threat-intel/watchlist/${item.id}`);
    toast.success("Removed");
    load();
  };

  const syncNow = async () => {
    setSyncing(true);
    try {
      const r = await api.post("/v1/admin/threat-intel/sync-now");
      toast.success(`ThreatFox sync: ${r.data.added} new IOC(s) added (${r.data.seen ?? 0} seen)`);
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Sync failed");
    } finally { setSyncing(false); }
  };

  return (
    <Layout title="Threat Intel Watchlist"
      subtitle="A living list of known-bad IPs, domains, hashes, and URLs -- checked automatically against new assets and file scans, not just on-demand lookups"
      actions={
        <div className="flex items-center gap-2">
          <button onClick={syncNow} disabled={syncing}
            className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-slate-500 disabled:opacity-50 text-slate-300 rounded inline-flex items-center gap-1.5">
            {syncing ? <CircleNotch size={14} className="animate-spin"/> : <Binoculars size={14}/>}
            Sync ThreatFox feed
          </button>
          <button onClick={() => setImportOpen(true)}
            className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-slate-500 text-slate-300 rounded inline-flex items-center gap-1.5">
            <UploadSimple size={14}/> Bulk import
          </button>
          <button onClick={() => setAddOpen(true)}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
            <Plus size={14}/> Add IOC
          </button>
        </div>
      }>
      <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3 py-2.5 mb-4 text-[12px] text-blue-200 leading-relaxed max-w-3xl">
        This list grows two ways: manually added/pasted IOCs, and a scheduled pull of abuse.ch's ThreatFox feed
        (reuses the same Auth-Key already configured under Integrations &rarr; abuse.ch (ThreatFox) for the
        on-demand recon-ng lookup). New Qualys assets are checked against watchlisted IPs, and every YARA file scan
        checks the file's hash -- both raise a Security Alert automatically on a match.
      </div>

      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5 mb-4">
          <StatCard label="Total IOCs" value={stats.total}/>
          <StatCard label="IPs" value={stats.by_type.ip}/>
          <StatCard label="Domains" value={stats.by_type.domain}/>
          <StatCard label="Hashes" value={stats.by_type.hash}/>
          <StatCard label="Have matched" value={stats.with_hits}/>
        </div>
      )}

      <form onSubmit={search} className="flex items-center gap-2 mb-3">
        <div className="relative flex-1 max-w-sm">
          <MagnifyingGlass size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500"/>
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search value..."
            className="w-full h-8 pl-8 pr-3 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100"/>
        </div>
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)}
          className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-300">
          <option value="">All types</option>
          {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <button type="submit" className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Search</button>
      </form>

      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No IOCs on the watchlist yet. Add one manually, bulk import a list, or sync the ThreatFox feed.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr className="border-b border-[#30363D] text-left text-slate-500 text-[11px] uppercase tracking-wider">
                <th className="px-4 py-2.5 font-medium">Value</th>
                <th className="px-4 py-2.5 font-medium">Type</th>
                <th className="px-4 py-2.5 font-medium">Severity</th>
                <th className="px-4 py-2.5 font-medium">Source</th>
                <th className="px-4 py-2.5 font-medium">Hits</th>
                <th className="px-4 py-2.5 font-medium">Added</th>
                <th className="px-4 py-2.5 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {items.map(it => (
                <tr key={it.id} className="border-b border-[#30363D] last:border-0 hover:bg-slate-800/20">
                  <td className="px-4 py-2.5 font-mono text-slate-200">{it.value}</td>
                  <td className="px-4 py-2.5 text-slate-400">{it.ioc_type}</td>
                  <td className="px-4 py-2.5"><Chip color={SEVERITY_COLOR[it.severity] || "slate"}>{it.severity}</Chip></td>
                  <td className="px-4 py-2.5 text-slate-500 truncate max-w-[220px]" title={it.notes || ""}>
                    {it.source === "abuse.ch_threatfox_feed" ? "ThreatFox feed" : "Manual"}
                    {it.notes && <span className="text-slate-600"> &middot; {it.notes}</span>}
                  </td>
                  <td className="px-4 py-2.5">
                    {it.hits > 0 ? (
                      <Link to="/alerts" className="inline-flex items-center gap-1 text-amber-400 hover:underline">
                        <Siren size={12}/> {it.hits}
                      </Link>
                    ) : <span className="text-slate-600">0</span>}
                  </td>
                  <td className="px-4 py-2.5 text-slate-500">{new Date(it.added_at).toLocaleDateString()}</td>
                  <td className="px-4 py-2.5 text-right">
                    <button onClick={() => removeIoc(it)} className="text-slate-500 hover:text-red-400">
                      <Trash size={14}/>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="px-4 py-2 text-[11px] text-slate-600 border-t border-[#30363D]">{total} total</div>
        </div>
      )}

      {addOpen && <AddIocModal onClose={() => setAddOpen(false)} onSaved={() => { setAddOpen(false); load(); }}/>}
      {importOpen && <BulkImportModal onClose={() => setImportOpen(false)} onSaved={() => { setImportOpen(false); load(); }}/>}
    </Layout>
  );
}

function StatCard({ label, value }) {
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-3.5 py-3">
      <div className="text-[11px] text-slate-500 uppercase tracking-wider">{label}</div>
      <div className="text-[20px] text-slate-100 font-semibold mt-0.5">{value ?? 0}</div>
    </div>
  );
}

function AddIocModal({ onClose, onSaved }) {
  const [form, setForm] = useState({ ioc_type: "ip", value: "", severity: "High", notes: "" });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!form.value.trim()) { toast.error("Value is required"); return; }
    setSaving(true);
    try {
      await api.post("/v1/admin/threat-intel/watchlist", form);
      toast.success("IOC added");
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to add IOC");
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="text-[14px] text-slate-100 font-medium">Add IOC</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5 space-y-3.5">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Type</label>
              <select value={form.ioc_type} onChange={e => setForm({ ...form, ioc_type: e.target.value })}
                className="w-full mt-1 h-9 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200">
                {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Severity</label>
              <select value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })}
                className="w-full mt-1 h-9 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200">
                {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Value</label>
            <input value={form.value} onChange={e => setForm({ ...form, value: e.target.value })}
              placeholder="1.2.3.4, evil.example.com, or a sha256 hash"
              className="w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100 font-mono"/>
          </div>
          <div>
            <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Notes (optional)</label>
            <input value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })}
              className="w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100"/>
          </div>
        </div>
        <div className="flex justify-end gap-2 px-5 py-3.5 border-t border-[#30363D]">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={save} disabled={saving}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">
            {saving ? "Saving…" : "Add"}
          </button>
        </div>
      </div>
    </div>
  );
}

function BulkImportModal({ onClose, onSaved }) {
  const [form, setForm] = useState({ ioc_type: "ip", severity: "High", notes: "", raw: "" });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    const values = form.raw.split(/[\n,]+/).map(v => v.trim()).filter(Boolean);
    if (values.length === 0) { toast.error("Paste at least one value"); return; }
    setSaving(true);
    try {
      const r = await api.post("/v1/admin/threat-intel/watchlist/bulk-import", { ...form, values });
      toast.success(`${r.data.added} added, ${r.data.skipped} already on the list`);
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Bulk import failed");
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="text-[14px] text-slate-100 font-medium">Bulk import IOCs</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5 space-y-3.5">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Type (applies to all)</label>
              <select value={form.ioc_type} onChange={e => setForm({ ...form, ioc_type: e.target.value })}
                className="w-full mt-1 h-9 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200">
                {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Severity</label>
              <select value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })}
                className="w-full mt-1 h-9 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200">
                {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Values (one per line, or comma-separated)</label>
            <textarea value={form.raw} onChange={e => setForm({ ...form, raw: e.target.value })} rows={6}
              placeholder={"1.2.3.4\nevil.example.com\n..."}
              className="w-full mt-1 px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100 font-mono"/>
          </div>
          <div>
            <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Notes (optional, applies to all)</label>
            <input value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })}
              className="w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100"/>
          </div>
        </div>
        <div className="flex justify-end gap-2 px-5 py-3.5 border-t border-[#30363D]">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={save} disabled={saving}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">
            {saving ? "Importing…" : "Import"}
          </button>
        </div>
      </div>
    </div>
  );
}
