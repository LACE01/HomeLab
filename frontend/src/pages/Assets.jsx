import { useEffect, useState, useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { SevBadge, Chip, RiskBar } from "@/components/Badges";
import { fmtDate, fmtRel, isOverdue } from "@/lib/utils-fmt";
import { MagnifyingGlass, ArrowLeft, Stack, CaretLeft, CaretRight, LockKey, LockKeyOpen, Info, WindowsLogo, LinuxLogo, AppleLogo, Desktop, User } from "@phosphor-icons/react";
import TrendChart from "@/components/TrendChart";
import { toast } from "sonner";

const PAGE_SIZE = 50;

// Small platform badge next to the OS text -- Windows/Linux/macOS get their own logo,
// anything else (or "unknown") falls back to a generic desktop icon rather than
// guessing.
function PlatformIcon({ platform, size = 15 }) {
  const p = (platform || "").toLowerCase();
  if (p.includes("windows")) return <WindowsLogo size={size} className="text-blue-400 shrink-0"/>;
  if (p.includes("linux")) return <LinuxLogo size={size} className="text-amber-400 shrink-0"/>;
  if (p.includes("mac") || p.includes("darwin") || p.includes("osx")) return <AppleLogo size={size} className="text-slate-300 shrink-0"/>;
  return <Desktop size={size} className="text-slate-500 shrink-0"/>;
}

export function Assets() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [q, setQ] = useState("");
  const [criticality, setCriticality] = useState("");
  const [products, setProducts] = useState([]);
  const [selected, setSelected] = useState(new Set());
  const [bulkProduct, setBulkProduct] = useState("");
  const [assigning, setAssigning] = useState(false);

  const load = useCallback(() => {
    const params = { limit: PAGE_SIZE, offset: page * PAGE_SIZE };
    if (q) params.q = q; if (criticality) params.criticality = criticality;
    api.get("/v1/assets", { params }).then(r => { setItems(r.data.items); setTotal(r.data.total || 0); });
  }, [q, criticality, page]);

  useEffect(() => { load(); }, [criticality, page]); // eslint-disable-line
  useEffect(() => { setPage(0); }, [q, criticality]);
  useEffect(() => { api.get("/v1/products").then(r => setProducts(r.data.items)); }, []);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const toggle = (id) => setSelected(s => {
    const next = new Set(s);
    next.has(id) ? next.delete(id) : next.add(id);
    return next;
  });
  const toggleAll = () => setSelected(s => s.size === items.length ? new Set() : new Set(items.map(a => a.id)));

  const assignSelected = async () => {
    if (!selected.size) return;
    setAssigning(true);
    try {
      await api.post("/v1/assets/bulk-assign-product", {
        asset_ids: Array.from(selected), product_id: bulkProduct || null,
      });
      toast.success(`Assigned ${selected.size} asset(s) to product.`);
      setSelected(new Set());
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to assign product");
    } finally {
      setAssigning(false);
    }
  };

  return (
    <Layout title="Assets" subtitle="Hosts, cloud resources, repositories, and devices under management">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md mb-3 px-3 py-2 flex gap-2 items-center flex-wrap">
        <div className="flex items-center gap-1.5 bg-[#161B22] border border-[#30363D] rounded px-2 h-8 flex-1 min-w-[200px]">
          <MagnifyingGlass size={14} className="text-slate-500" />
          <input data-testid="assets-search" value={q} onChange={(e)=>setQ(e.target.value)} onKeyDown={(e)=>e.key==='Enter'&&load()}
            placeholder="hostname, IP, or FQDN…" className="bg-transparent flex-1 outline-none text-[12.5px] text-slate-200"/>
        </div>
        <select data-testid="assets-criticality" value={criticality} onChange={(e)=>setCriticality(e.target.value)} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]">
          <option value="">All criticalities</option>
          {["crown_jewel","critical","high","medium","low"].map(s => <option key={s}>{s}</option>)}
        </select>
      </div>

      {selected.size > 0 && (
        <div data-testid="bulk-assign-bar" className="border border-blue-500/30 bg-blue-500/5 rounded-md mb-3 px-3 py-2 flex items-center gap-2">
          <Stack size={14} className="text-blue-300"/>
          <span className="text-[12px] text-blue-200">{selected.size} selected</span>
          <select data-testid="bulk-assign-product-select" value={bulkProduct} onChange={(e)=>setBulkProduct(e.target.value)}
            className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] ml-auto">
            <option value="">Unassign product</option>
            {products.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <button data-testid="bulk-assign-apply" onClick={assignSelected} disabled={assigning}
            className="h-8 px-3 text-[12px] bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/40 text-blue-200 rounded disabled:opacity-50">
            {assigning ? "Applying…" : "Assign to product"}
          </button>
        </div>
      )}

      <div className="flex items-center justify-between mb-2 px-1">
        <div className="text-[11.5px] text-slate-500">{total} asset{total===1?"":"s"} total</div>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table data-testid="assets-table" className="dense w-full">
          <thead><tr>
            <th className="w-8"><input type="checkbox" checked={items.length>0 && selected.size===items.length} onChange={toggleAll} data-testid="select-all-assets"/></th>
            <th className="text-left">Hostname</th><th className="text-left">IP</th>
            <th className="text-left">Type</th><th className="text-left">Env</th>
            <th className="text-left">Criticality</th><th className="text-left">Exposure</th>
            <th className="text-left">Owner Team</th><th className="text-left">Product</th>
            <th className="text-right">Open Findings</th>
            <th className="text-right">Critical</th><th className="text-left">Ownership</th>
          </tr></thead>
          <tbody>
            {items.map(a => (
              <tr key={a.id} className="border-t border-[#30363D] hover:bg-slate-800/30">
                <td><input type="checkbox" checked={selected.has(a.id)} onChange={()=>toggle(a.id)} data-testid={`select-asset-${a.id}`}/></td>
                <td>
                  <Link to={`/assets/${a.id}`} data-testid={`asset-${a.id}`} className="text-blue-300 hover:underline font-mono text-[12px] inline-flex items-center gap-1.5">
                    <PlatformIcon platform={a.platform} size={13}/> {a.hostname}
                  </Link>
                </td>
                <td className="font-mono text-[11.5px] text-slate-400">{a.ip || "—"}</td>
                <td className="text-slate-400 text-[11.5px]">{a.asset_type}</td>
                <td className="text-slate-400 capitalize">{a.environment}</td>
                <td><Chip color={a.criticality === "crown_jewel" ? "red" : a.criticality === "critical" ? "orange" : "slate"}>{a.criticality}</Chip></td>
                <td><Chip color={a.exposure === "internet" ? "orange" : "slate"}>{a.exposure}</Chip></td>
                <td className="text-slate-400">{a.owner_team}</td>
                <td className="text-slate-400 text-[11.5px]">{a.product_name || "—"}</td>
                <td className="text-right font-mono">{a.open_findings}</td>
                <td className="text-right font-mono text-red-300">{a.critical_findings}</td>
                <td><div className="flex items-center gap-1.5">
                  <div className="h-1 w-12 bg-slate-800 rounded overflow-hidden">
                    <div className={`h-full ${a.ownership_confidence >= 0.8 ? "bg-emerald-500" : a.ownership_confidence >= 0.6 ? "bg-amber-500" : "bg-red-500"}`} style={{width: `${(a.ownership_confidence||0)*100}%`}}/>
                  </div>
                  <span className="font-mono text-[10.5px] text-slate-400">{((a.ownership_confidence||0)*100).toFixed(0)}%</span>
                </div></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between mt-3 px-1">
        <div className="text-[11px] text-slate-500">
          Showing {items.length === 0 ? 0 : page * PAGE_SIZE + 1}–{page * PAGE_SIZE + items.length} of {total}
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
            className="h-8 w-8 flex items-center justify-center text-slate-400 hover:text-slate-200 disabled:opacity-30 rounded border border-[#30363D]" data-testid="assets-prev-page">
            <CaretLeft size={14}/>
          </button>
          <span className="text-[11.5px] text-slate-500">Page {page + 1} of {totalPages}</span>
          <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}
            className="h-8 w-8 flex items-center justify-center text-slate-400 hover:text-slate-200 disabled:opacity-30 rounded border border-[#30363D]" data-testid="assets-next-page">
            <CaretRight size={14}/>
          </button>
        </div>
      </div>
    </Layout>
  );
}

export function AssetDetail() {
  const { id } = useParams();
  const [a, setA] = useState(null);
  const [findings, setFindings] = useState([]);
  const [history, setHistory] = useState({activity: [], observations: []});
  const [products, setProducts] = useState([]);
  const [savingProduct, setSavingProduct] = useState(false);
  const [patchGroups, setPatchGroups] = useState([]);
  const [editingCrit, setEditingCrit] = useState(false);
  const [critChoice, setCritChoice] = useState("medium");
  const [savingCrit, setSavingCrit] = useState(false);

  useEffect(() => {
    api.get(`/v1/assets/${id}`).then(r => setA(r.data));
    api.get(`/v1/assets/${id}/findings`).then(r => setFindings(r.data.items));
    api.get(`/v1/assets/${id}/history`).then(r => setHistory(r.data));
    api.get("/v1/products").then(r => setProducts(r.data.items));
    api.get(`/v1/assets/${id}/patch-groups`).then(r => setPatchGroups(r.data.groups.filter(g => g.count > 1)));
  }, [id]);

  const setManualCriticality = async () => {
    setSavingCrit(true);
    try {
      await api.patch(`/v1/assets/${id}/criticality`, { criticality: critChoice });
      const r = await api.get(`/v1/assets/${id}`);
      setA(r.data);
      setEditingCrit(false);
      toast.success("Criticality set and locked — auto-scoring won't override it until you unlock.");
    } catch (err) {
      toast.error(err.response?.data?.detail || "Failed to update criticality");
    } finally { setSavingCrit(false); }
  };

  const unlockCriticality = async () => {
    setSavingCrit(true);
    try {
      await api.patch(`/v1/assets/${id}/criticality`, { locked: false });
      const r = await api.get(`/v1/assets/${id}`);
      setA(r.data);
      toast.success("Unlocked — resumed auto-scoring from detected ports/services/exposure.");
    } catch (err) {
      toast.error(err.response?.data?.detail || "Failed to unlock");
    } finally { setSavingCrit(false); }
  };

  const changeProduct = async (e) => {
    const product_id = e.target.value || null;
    setSavingProduct(true);
    try {
      await api.post(`/v1/assets/${id}/product`, { product_id });
      const r = await api.get(`/v1/assets/${id}`);
      setA(r.data);
      toast.success("Product assignment updated.");
    } catch (err) {
      toast.error(err.response?.data?.detail || "Failed to update product");
    } finally {
      setSavingProduct(false);
    }
  };

  if (!a) return <Layout title="Asset…"><div className="text-slate-500">Loading…</div></Layout>;

  return (
    <Layout title={
        <span className="inline-flex items-center gap-2">
          <PlatformIcon platform={a.platform}/> {a.hostname}
        </span>
      } subtitle={`${a.platform} · ${a.operating_system} · ${a.environment}`}
      actions={<Link to="/assets" className="h-8 px-3 text-[12px] border border-[#30363D] rounded inline-flex items-center gap-1.5 text-slate-300"><ArrowLeft size={14}/> Back</Link>}>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-3 mb-4">
        <div className="lg:col-span-2 border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500">Asset Profile</div>
          <div className="mt-2 grid grid-cols-2 gap-2 text-[12.5px] items-center">
            <div><span className="text-slate-500">IP:</span> <span className="font-mono">{a.ip || "—"}</span></div>
            <div><span className="text-slate-500">FQDN:</span> <span className="font-mono text-[11px]">{a.fqdn || "—"}</span></div>
            <div><span className="text-slate-500">Type:</span> {a.asset_type}</div>
            <div><span className="text-slate-500">Status:</span> {a.status}</div>
            <div><span className="text-slate-500">Owner Team:</span> {a.owner_team}</div>
            {a.hardware_info && <div><span className="text-slate-500">Hardware:</span> {a.hardware_info}</div>}
            {a.last_logged_on_user && (
              <div className="flex items-center gap-1">
                <User size={12} className="text-slate-500"/><span className="text-slate-500">Last logged in:</span> {a.last_logged_on_user}
              </div>
            )}
            <div className="flex items-center gap-1.5">
              <span className="text-slate-500">Product:</span>
              <select data-testid="asset-product-select" value={a.product_id || ""} onChange={changeProduct} disabled={savingProduct}
                className="h-6 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11.5px] text-slate-200 disabled:opacity-50">
                <option value="">Unassigned</option>
                {products.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>
          </div>
          <div className="mt-3 flex flex-wrap gap-1">{(a.tags||[]).map(t => <Chip key={t}>{t}</Chip>)}</div>
        </div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <div className="flex items-center justify-between">
            <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500">Criticality</div>
            {a.criticality_locked
              ? <button onClick={unlockCriticality} disabled={savingCrit} title="Unlock to resume auto-scoring"
                  className="text-slate-500 hover:text-emerald-300 disabled:opacity-50"><LockKey size={13}/></button>
              : <button onClick={()=>{ setCritChoice(a.criticality || "medium"); setEditingCrit(true); }} title="Manually override"
                  className="text-slate-500 hover:text-blue-300"><LockKeyOpen size={13}/></button>}
          </div>
          <div className="mt-2 flex items-center gap-2">
            <Chip color={a.criticality === "crown_jewel" ? "red" : a.criticality === "critical" ? "orange" : a.criticality === "high" ? "amber" : "slate"}>{a.criticality}</Chip>
            {a.criticality_score != null && !a.criticality_locked && <span className="text-[10.5px] font-mono text-slate-500">score: {a.criticality_score}</span>}
            {a.criticality_locked && <span className="text-[10.5px] text-slate-500">manually locked</span>}
          </div>
          {editingCrit && (
            <div className="mt-2 flex items-center gap-1.5">
              <select value={critChoice} onChange={e=>setCritChoice(e.target.value)}
                className="h-7 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11.5px] text-slate-200">
                {["crown_jewel","critical","high","medium","low"].map(t => <option key={t} value={t}>{t}</option>)}
              </select>
              <button onClick={setManualCriticality} disabled={savingCrit} className="h-7 px-2 text-[11px] bg-blue-500 hover:bg-blue-400 text-white rounded disabled:opacity-50">Set</button>
              <button onClick={()=>setEditingCrit(false)} className="h-7 px-2 text-[11px] border border-[#30363D] rounded text-slate-300">Cancel</button>
            </div>
          )}
          {!a.criticality_locked && a.criticality_rationale?.length > 0 && (
            <div className="mt-2 text-[10.5px] text-slate-500 leading-relaxed flex items-start gap-1">
              <Info size={11} className="shrink-0 mt-0.5"/>
              <span>{a.criticality_rationale.map(r => r.name).join("; ")}</span>
            </div>
          )}
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mt-3">Exposure</div>
          <div className="mt-2"><Chip color={a.exposure === "internet" ? "orange" : "slate"}>{a.exposure}</Chip></div>
        </div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500">Ownership Confidence</div>
          <div className="text-[28px] font-mono font-semibold text-blue-300 mt-1">{((a.ownership_confidence||0)*100).toFixed(0)}<span className="text-slate-500 text-[14px]">%</span></div>
          <div className="text-[11px] text-slate-500 mt-1">{a.ownership_rationale}</div>
        </div>
      </div>

      {a.open_ports?.length > 0 && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden mb-4">
          <div className="px-4 py-2 border-b border-[#30363D] flex items-center justify-between">
            <h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">
              Open Ports ({a.open_ports.length}) — via Nmap
            </h3>
            <div className="text-[10.5px] text-slate-500 font-mono flex items-center gap-2">
              {a.detected_os && <span>OS guess: {a.detected_os}</span>}
              {a.nmap_last_scan_at && <span>Last scanned {a.nmap_last_scan_at.slice(0,10)}</span>}
            </div>
          </div>
          {a.exposure_mismatch && (
            <div className="px-4 py-2 bg-amber-500/5 border-b border-amber-500/20 text-[11.5px] text-amber-200">
              {a.exposure_mismatch_note}
            </div>
          )}
          <table className="dense w-full">
            <thead><tr><th>Port</th><th>Protocol</th><th className="text-left">Service</th><th className="text-left">Product / Version</th></tr></thead>
            <tbody>
              {a.open_ports.map((p, i) => (
                <tr key={i} className="border-t border-[#30363D]">
                  <td className="text-center font-mono">{p.port}</td>
                  <td className="text-center text-slate-400">{p.protocol}</td>
                  <td className="text-slate-200">{p.service || "—"}</td>
                  <td className="text-slate-400 text-[11.5px]">{[p.product, p.version].filter(Boolean).join(" ") || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {patchGroups.length > 0 && (
        <div className="border border-emerald-500/30 bg-emerald-500/5 rounded-md overflow-hidden mb-4">
          <div className="px-4 py-2 border-b border-emerald-500/20 text-[11px] uppercase tracking-wider font-mono text-emerald-300">
            Patch Once, Fix Many — {patchGroups.length} group{patchGroups.length===1?"":"s"}
          </div>
          <div className="divide-y divide-emerald-500/10">
            {patchGroups.map((g, i) => (
              <div key={i} className="px-4 py-2.5 flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-[12.5px] text-slate-200 truncate">{g.title}</div>
                  <div className="text-[10.5px] text-slate-500 mt-0.5 font-mono">{g.cves.slice(0,4).join(", ")}{g.cves.length>4?` +${g.cves.length-4} more`:""}</div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <SevBadge severity={g.top_severity}/>
                  <Chip color="green">{g.count} findings, 1 patch</Chip>
                  {!g.patch_available && <Chip color="amber">no patch yet</Chip>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="mb-4">
        <TrendChart title="Vulnerabilities on this Host — Over Time" filters={{ asset_id: id }} defaultDays={90}/>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden mb-4">
        <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">Vulnerabilities on this Host ({findings.length})</h3></div>
        <table className="dense w-full">
          <thead><tr><th className="text-left">Risk</th><th>Severity</th><th className="text-left">Title</th><th>CVE</th><th>Status</th><th>First Seen</th><th>Last Seen</th><th>Due</th></tr></thead>
          <tbody>
            {findings.map(f => (
              <tr key={f.id} className="border-t border-[#30363D] hover:bg-slate-800/30">
                <td><RiskBar score={f.risk_score} /></td>
                <td><SevBadge severity={f.severity} /></td>
                <td><Link to={`/findings/${f.id}`} className="text-blue-300 hover:underline">{f.title?.slice(0,70)}</Link></td>
                <td className="font-mono text-[11px]">{f.cve || "—"}</td>
                <td><Chip color={f.status==="Reopened" ? "orange" : f.status?.includes("Fixed") ? "green" : "slate"}>{f.status}</Chip></td>
                <td className="font-mono text-[11px]">{fmtDate(f.first_seen_at)}</td>
                <td className="font-mono text-[11px]">{fmtDate(f.last_seen_at)}</td>
                <td className={isOverdue(f.due_at) ? "text-red-300 text-[11px]" : "text-slate-400 text-[11px]"}>{fmtRel(f.due_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">Detection History</h3></div>
        <table className="dense w-full">
          <thead><tr><th className="text-left">Source</th><th>Method</th><th>Severity</th><th>Observed</th></tr></thead>
          <tbody>
            {history.observations.slice(0,30).map(o => (
              <tr key={o.id} className="border-t border-[#30363D]">
                <td>{o.source_tool}</td><td>{o.agent_or_network}</td>
                <td><SevBadge severity={o.normalized_severity} /></td>
                <td className="font-mono text-[11px]">{fmtDate(o.observed_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}
