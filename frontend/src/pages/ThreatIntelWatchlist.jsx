import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  Plus, X, Trash, CircleNotch, Binoculars, UploadSimple, Siren, MagnifyingGlass, Package,
  Database, Broadcast, CaretRight, ArrowSquareOut, Clock,
} from "@phosphor-icons/react";

const IOC_TYPES = ["ip", "domain", "hash", "url", "package"];
const SEVERITIES = ["Info", "Low", "Medium", "High", "Critical"];

const SEVERITY_COLOR = { Info: "slate", Low: "blue", Medium: "amber", High: "orange", Critical: "red" };

const SOURCE_LABELS = {
  "abuse.ch_threatfox_feed": "ThreatFox feed",
  "opensourcemalware_feed": "OpenSourceMalware feed",
  "opencti_feed": "OpenCTI feed",
  "otx_feed": "AlienVault OTX feed",
  "manual": "Manual",
};

// Field-key -> human label overrides for the detail drill-down. Any detail key
// not listed here just gets its snake_case turned into Title Case.
const DETAIL_LABELS = {
  malware: "Malware family", malware_alias: "Malware alias", threat_type: "Threat type",
  confidence_level: "Confidence level", first_seen: "First seen", last_seen: "Last seen",
  reference: "Reference", reporter: "Reporter", threatfox_ioc_id: "ThreatFox IOC ID",
  ecosystem: "Ecosystem", package_name: "Package name", severity_level: "Severity level",
  threat_description: "Description", discovered_date: "Discovered", advisory_url: "Advisory",
  indicator_name: "Indicator name", description: "Description", pattern: "STIX pattern",
  valid_until: "Valid until", score: "OpenCTI score", labels: "Labels",
  opencti_indicator_id: "OpenCTI indicator ID", pulse_name: "OTX pulse", pulse_id: "Pulse ID",
  pulse_description: "Pulse description", author: "Pulse author", tags: "Tags",
  references: "References", indicator_type: "OTX indicator type",
  indicator_description: "Indicator description", indicator_created: "Indicator created",
};

function fieldLabel(key) {
  return DETAIL_LABELS[key] || key.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

function fieldValue(v) {
  if (v === null || v === undefined || v === "") return null;
  if (Array.isArray(v)) return v.length ? v.join(", ") : null;
  return String(v);
}

export default function ThreatIntelWatchlist() {
  const [items, setItems] = useState([]);
  const [stats, setStats] = useState(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState("");
  const [q, setQ] = useState("");
  const [addOpen, setAddOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [selected, setSelected] = useState(null); // IOC row currently open in the detail modal
  const [syncing, setSyncing] = useState(null); // "threatfox" | "opensourcemalware" | "opencti" | "otx" | null

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

  const removeIoc = async (e, item) => {
    e.stopPropagation();
    if (!window.confirm(`Remove "${item.value}" from the watchlist?`)) return;
    await api.delete(`/v1/admin/threat-intel/watchlist/${item.id}`);
    toast.success("Removed");
    load();
  };

  const runSync = async (key, label, path) => {
    setSyncing(key);
    try {
      const r = await api.post(path);
      const errNote = r.data.errors?.length ? ` (${r.data.errors.length} error(s), see server logs)` : "";
      toast.success(`${label} sync: ${r.data.added} new IOC(s) added (${r.data.seen ?? 0} seen)${errNote}`);
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || `${label} sync failed`);
    } finally { setSyncing(null); }
  };

  return (
    <Layout title="Threat Intel Watchlist"
      subtitle="A living list of known-bad IPs, domains, hashes, and URLs -- checked automatically against new assets and file scans, not just on-demand lookups"
      actions={
        <div className="flex items-center gap-2 flex-wrap justify-end">
          <button onClick={() => runSync("threatfox", "ThreatFox", "/v1/admin/threat-intel/sync-now")} disabled={!!syncing}
            className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-slate-500 disabled:opacity-50 text-slate-300 rounded inline-flex items-center gap-1.5">
            {syncing === "threatfox" ? <CircleNotch size={14} className="animate-spin"/> : <Binoculars size={14}/>}
            Sync ThreatFox
          </button>
          <button onClick={() => runSync("opensourcemalware", "OpenSourceMalware", "/v1/admin/threat-intel/sync-now/opensourcemalware")} disabled={!!syncing}
            className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-slate-500 disabled:opacity-50 text-slate-300 rounded inline-flex items-center gap-1.5">
            {syncing === "opensourcemalware" ? <CircleNotch size={14} className="animate-spin"/> : <Package size={14}/>}
            Sync OpenSourceMalware
          </button>
          <button onClick={() => runSync("opencti", "OpenCTI", "/v1/admin/threat-intel/sync-now/opencti")} disabled={!!syncing}
            className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-slate-500 disabled:opacity-50 text-slate-300 rounded inline-flex items-center gap-1.5">
            {syncing === "opencti" ? <CircleNotch size={14} className="animate-spin"/> : <Database size={14}/>}
            Sync OpenCTI
          </button>
          <button onClick={() => runSync("otx", "AlienVault OTX", "/v1/admin/threat-intel/sync-now/otx")} disabled={!!syncing}
            className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-slate-500 disabled:opacity-50 text-slate-300 rounded inline-flex items-center gap-1.5">
            {syncing === "otx" ? <CircleNotch size={14} className="animate-spin"/> : <Broadcast size={14}/>}
            Sync OTX
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
        This list grows five ways: manually added/pasted IOCs, a scheduled pull of abuse.ch's ThreatFox feed, a
        scheduled pull of OpenSourceMalware.com's verified malicious open-source package feed, a scheduled pull of
        our own OpenCTI instance's recent Indicators, and a scheduled pull of AlienVault OTX's subscribed pulses
        (each reuses the same connection already configured under Integrations for that source's on-demand recon-ng
        lookup). New Qualys assets are checked against watchlisted IPs, every YARA file scan checks the file's hash,
        and every SBOM upload checks each dependency's package name -- all three raise a Security Alert automatically
        on a match. Click any row below to see exactly why a value is considered malicious and where it's matched.
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
          No IOCs on the watchlist yet. Add one manually, bulk import a list, or sync a feed above.
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
                <tr key={it.id} onClick={() => setSelected(it)}
                  className="border-b border-[#30363D] last:border-0 hover:bg-slate-800/20 cursor-pointer">
                  <td className="px-4 py-2.5 font-mono text-slate-200">{it.value}</td>
                  <td className="px-4 py-2.5 text-slate-400">{it.ioc_type}</td>
                  <td className="px-4 py-2.5"><Chip color={SEVERITY_COLOR[it.severity] || "slate"}>{it.severity}</Chip></td>
                  <td className="px-4 py-2.5 text-slate-500 truncate max-w-[220px]" title={it.notes || ""}>
                    {SOURCE_LABELS[it.source] || it.source || "Manual"}
                    {it.notes && <span className="text-slate-600"> &middot; {it.notes}</span>}
                  </td>
                  <td className="px-4 py-2.5">
                    {it.hits > 0 ? (
                      <span className="inline-flex items-center gap-1 text-amber-400">
                        <Siren size={12}/> {it.hits}
                      </span>
                    ) : <span className="text-slate-600">0</span>}
                  </td>
                  <td className="px-4 py-2.5 text-slate-500">{new Date(it.added_at).toLocaleDateString()}</td>
                  <td className="px-4 py-2.5 text-right">
                    <div className="flex items-center justify-end gap-2.5">
                      <button onClick={(e) => removeIoc(e, it)} className="text-slate-500 hover:text-red-400">
                        <Trash size={14}/>
                      </button>
                      <CaretRight size={13} className="text-slate-600"/>
                    </div>
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
      {selected && <IocDetailModal item={selected} onClose={() => setSelected(null)}/>}
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

function IocDetailModal({ item, onClose }) {
  const [matches, setMatches] = useState(null);
  const [matchesLoading, setMatchesLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setMatchesLoading(true);
    api.get(`/v1/admin/threat-intel/watchlist/${item.id}/matches`)
      .then(r => { if (!cancelled) setMatches(r.data.items || []); })
      .catch(() => { if (!cancelled) setMatches([]); })
      .finally(() => { if (!cancelled) setMatchesLoading(false); });
    return () => { cancelled = true; };
  }, [item.id]);

  const detail = item.detail || null;
  const detailEntries = detail
    ? Object.entries(detail).map(([k, v]) => [k, fieldValue(v)]).filter(([, v]) => v !== null)
    : [];

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-lg max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D] sticky top-0 bg-[#0D1117]">
          <div>
            <div className="text-[14px] text-slate-100 font-medium font-mono">{item.value}</div>
            <div className="text-[11px] text-slate-500 mt-0.5">{item.ioc_type} &middot; {SOURCE_LABELS[item.source] || item.source || "Manual"}</div>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>

        <div className="p-5 space-y-5">
          <div className="flex items-center gap-4 text-[12.5px]">
            <div>
              <div className="text-[11px] text-slate-500 uppercase tracking-wider">Severity</div>
              <div className="mt-1"><Chip color={SEVERITY_COLOR[item.severity] || "slate"}>{item.severity}</Chip></div>
            </div>
            <div>
              <div className="text-[11px] text-slate-500 uppercase tracking-wider">Hits</div>
              <div className="mt-1 text-slate-200">{item.hits ?? 0}</div>
            </div>
            <div>
              <div className="text-[11px] text-slate-500 uppercase tracking-wider">Added</div>
              <div className="mt-1 text-slate-200">{new Date(item.added_at).toLocaleDateString()}</div>
            </div>
          </div>

          <div>
            <div className="text-[11px] text-slate-500 uppercase tracking-wider mb-2">Why this is flagged</div>
            {item.notes && (
              <div className="text-[12.5px] text-slate-300 mb-2">{item.notes}</div>
            )}
            {detailEntries.length > 0 ? (
              <div className="border border-[#30363D] rounded-md divide-y divide-[#30363D]">
                {detailEntries.map(([k, v]) => (
                  <div key={k} className="px-3 py-2 flex items-start gap-3 text-[12px]">
                    <div className="w-36 shrink-0 text-slate-500">{fieldLabel(k)}</div>
                    <div className="text-slate-200 break-all">
                      {/^https?:\/\//.test(v) ? (
                        <a href={v} target="_blank" rel="noreferrer" className="text-blue-400 hover:underline inline-flex items-center gap-1">
                          {v} <ArrowSquareOut size={11}/>
                        </a>
                      ) : v}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-[12px] text-slate-500 border border-[#30363D] rounded-md px-3 py-3">
                {item.source === "manual"
                  ? "This IOC was added manually -- no feed detail beyond the note above."
                  : "No additional source detail was captured for this entry."}
              </div>
            )}
          </div>

          <div>
            <div className="text-[11px] text-slate-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Clock size={12}/> Recent matches in this environment
            </div>
            {matchesLoading ? (
              <div className="text-[12px] text-slate-500 py-3 text-center">Loading…</div>
            ) : matches && matches.length > 0 ? (
              <div className="border border-[#30363D] rounded-md divide-y divide-[#30363D]">
                {matches.map(ev => (
                  <div key={ev.id} className="px-3 py-2.5 text-[12px]">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-200">{ev.entity_label || ev.entity_id || "Unknown entity"}</span>
                      <span className="text-slate-500">{ev.last_seen_at ? new Date(ev.last_seen_at).toLocaleString() : ""}</span>
                    </div>
                    {ev.description && <div className="text-slate-500 mt-0.5">{ev.description}</div>}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-[12px] text-slate-500 border border-[#30363D] rounded-md px-3 py-3">
                Hasn't matched anything in this environment yet.
              </div>
            )}
          </div>
        </div>
      </div>
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
