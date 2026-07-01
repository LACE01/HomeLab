import { useEffect, useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip, SevBadge, RiskBar } from "@/components/Badges";
import { ArrowLeft, PencilSimple, Trash } from "@phosphor-icons/react";
import { ProductFormModal } from "@/pages/Operations";
import { toast } from "sonner";

export default function ProductDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [p, setP] = useState(null);
  const [editing, setEditing] = useState(false);

  const load = () => api.get(`/v1/products/${id}`).then(r => setP(r.data));
  useEffect(() => { load(); }, [id]); // eslint-disable-line

  const remove = async () => {
    if (!window.confirm(`Delete "${p.name}"? Assets and findings will be unlinked, not deleted.`)) return;
    try {
      await api.delete(`/v1/products/${id}`);
      toast.success("Product deleted.");
      navigate("/products");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to delete product");
    }
  };

  if (!p) return <Layout title="Product…"><div className="text-slate-500">Loading…</div></Layout>;
  return (
    <Layout title={p.name} subtitle={p.description}
      actions={<>
        <button data-testid="edit-product-btn" onClick={()=>setEditing(true)}
          className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300"><PencilSimple size={14}/> Edit</button>
        <button data-testid="delete-product-btn" onClick={remove}
          className="h-8 px-3 text-[12px] border border-red-500/30 hover:bg-red-500/10 rounded inline-flex items-center gap-1.5 text-red-300"><Trash size={14}/> Delete</button>
        <Link to="/products" className="h-8 px-3 text-[12px] border border-[#30363D] rounded inline-flex items-center gap-1.5 text-slate-300"><ArrowLeft size={14}/> Back</Link>
      </>}>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3"><div className="text-[10px] uppercase font-mono text-slate-500">Criticality</div><div className="mt-1"><Chip color="orange">{p.criticality}</Chip></div></div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3"><div className="text-[10px] uppercase font-mono text-slate-500">Business Owner</div><div className="text-[13px] mt-1">{p.business_owner}</div></div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3"><div className="text-[10px] uppercase font-mono text-slate-500">SLA Profile</div><div className="text-[13px] mt-1">{p.sla_profile}</div></div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3"><div className="text-[10px] uppercase font-mono text-slate-500">Environments</div><div className="flex gap-1 mt-1">{p.environments?.map(e=> <Chip key={e}>{e}</Chip>)}</div></div>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden mb-4">
        <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">Assets ({p.assets?.length})</h3></div>
        {(p.assets||[]).length === 0 ? (
          <div className="text-[12px] text-slate-500 p-4">No assets assigned yet. Go to Assets, select some, and assign them to this product.</div>
        ) : (
        <table className="dense w-full">
          <thead><tr><th className="text-left">Hostname</th><th>IP</th><th>Env</th><th>Criticality</th><th>Exposure</th></tr></thead>
          <tbody>{(p.assets||[]).map(a => (
            <tr key={a.id} className="border-t border-[#30363D]"><td><Link to={`/assets/${a.id}`} className="text-blue-300 hover:underline font-mono text-[12px]">{a.hostname}</Link></td><td className="font-mono text-[11px]">{a.ip||"—"}</td><td>{a.environment}</td><td><Chip>{a.criticality}</Chip></td><td><Chip>{a.exposure}</Chip></td></tr>
          ))}</tbody>
        </table>
        )}
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">Top Findings</h3></div>
        <table className="dense w-full">
          <thead><tr><th className="text-left">Risk</th><th>Severity</th><th className="text-left">Title</th><th>Asset</th><th>Status</th></tr></thead>
          <tbody>{(p.findings||[]).slice(0,30).map(f => (
            <tr key={f.id} className="border-t border-[#30363D]"><td><RiskBar score={f.risk_score}/></td><td><SevBadge severity={f.severity}/></td><td><Link to={`/findings/${f.id}`} className="text-blue-300 hover:underline">{f.title?.slice(0,70)}</Link></td><td className="font-mono text-[11px]">{f.asset_hostname}</td><td><Chip>{f.status}</Chip></td></tr>
          ))}</tbody>
        </table>
      </div>

      {editing && (
        <ProductFormModal initial={p} onClose={()=>setEditing(false)} onSaved={()=>{setEditing(false); load();}} />
      )}
    </Layout>
  );
}
