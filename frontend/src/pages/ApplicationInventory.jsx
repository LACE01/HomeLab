import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Cube, ArrowsClockwise, Warning, ShieldCheck, MagnifyingGlass } from "@phosphor-icons/react";

const CAT_LABEL = {
  installed_software: "Installed",
  saas: "SaaS",
  dependency: "Dependency",
  reviewed: "Reviewed",
};
const SOURCE_LABEL = {
  edr: "EDR", qualys: "Qualys", endpoint: "Endpoint", sbom: "SBOM",
  security_review: "Security Review", google_workspace: "Google Workspace",
};

export default function ApplicationInventory() {
  const [items, setItems] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [rebuilding, setRebuilding] = useState(false);
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState(null); // null | "shadow_it" | "reviewed" | category

  const load = async () => {
    setLoading(true);
    try {
      const params = {};
      if (q) params.q = q;
      if (filter === "shadow_it") params.shadow_it = true;
      else if (filter === "reviewed") params.reviewed = true;
      else if (filter) params.category = filter;
      const [r, s] = await Promise.all([
        api.get("/v1/app-inventory", { params }),
        api.get("/v1/app-inventory/stats"),
      ]);
      setItems(r.data.items || []);
      setStats(s.data);
    } catch (e) {
      toast.error("Failed to load application inventory");
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [filter]);

  const rebuild = async () => {
    setRebuilding(true);
    try {
      const r = await api.post("/v1/app-inventory/rebuild");
      toast.success(`Rebuilt: ${r.data.applications} apps · ${r.data.shadow_it} shadow IT · ${r.data.reviewed} reviewed`);
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Rebuild failed");
    } finally { setRebuilding(false); }
  };

  return (
    <Layout title="Application Inventory"
            subtitle="Application-level inventory for IR and shadow-IT discovery — auto-populated from EDR, SBOM, and completed Security Reviews"
            actions={
              <button onClick={rebuild} disabled={rebuilding}
                className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded inline-flex items-center gap-1.5">
                <ArrowsClockwise size={14} className={rebuilding ? "animate-spin" : ""} /> {rebuilding ? "Rebuilding…" : "Rebuild"}
              </button>
            }>
      {stats && (
        <div className="grid grid-cols-4 gap-3 mb-4 max-w-4xl">
          <Stat label="Applications" value={stats.total} onClick={() => setFilter(null)} active={filter === null} />
          <Stat label="Shadow IT" value={stats.shadow_it} tone="red" onClick={() => setFilter("shadow_it")} active={filter === "shadow_it"} />
          <Stat label="Reviewed" value={stats.reviewed} tone="green" onClick={() => setFilter("reviewed")} active={filter === "reviewed"} />
          <Stat label="Google Workspace" value={stats.google_workspace_configured ? "Connected" : "Not configured"} />
        </div>
      )}

      <div className="flex items-center gap-2 mb-3 max-w-4xl">
        <div className="relative flex-1">
          <MagnifyingGlass size={14} className="absolute left-2.5 top-2.5 text-slate-500" />
          <input value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === "Enter" && load()}
            placeholder="Search application or vendor…"
            className="w-full h-8 pl-8 pr-3 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100" />
        </div>
        {["installed_software", "saas", "dependency"].map((c) => (
          <button key={c} onClick={() => setFilter(filter === c ? null : c)}
            className={`h-8 px-2.5 text-[11.5px] rounded border ${filter === c ? "border-blue-500/40 bg-blue-500/15 text-blue-300" : "border-[#30363D] text-slate-400"}`}>
            {CAT_LABEL[c]}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="text-[12px] text-slate-500">Loading…</div>
      ) : items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-8 text-center text-[12.5px] text-slate-500">
          No applications. Click Rebuild to populate from EDR, SBOM, and Security Reviews.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden max-w-5xl">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr className="border-b border-[#30363D] text-left text-slate-500 text-[11px] uppercase tracking-wider">
                <th className="px-4 py-2 font-medium">Application</th>
                <th className="px-4 py-2 font-medium">Category</th>
                <th className="px-4 py-2 font-medium">Sources</th>
                <th className="px-4 py-2 font-medium">Installs</th>
                <th className="px-4 py-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {items.map((a) => (
                <tr key={a.id} className={`border-b border-[#30363D] last:border-0 ${a.shadow_it ? "bg-red-500/[0.03]" : ""}`}>
                  <td className="px-4 py-2">
                    <span className="text-slate-100">{a.name}</span>
                    {a.vendor && <span className="text-slate-500 ml-2 text-[11px]">{a.vendor}</span>}
                  </td>
                  <td className="px-4 py-2 text-slate-400">{CAT_LABEL[a.category] || a.category}</td>
                  <td className="px-4 py-2">
                    <div className="flex gap-1 flex-wrap">
                      {a.sources.map((s) => <Chip key={s} color="slate">{SOURCE_LABEL[s] || s}</Chip>)}
                    </div>
                  </td>
                  <td className="px-4 py-2 text-slate-300">{a.install_count || "—"}</td>
                  <td className="px-4 py-2">
                    {a.shadow_it ? (
                      <span className="inline-flex items-center gap-1 text-red-300 text-[11.5px]"><Warning size={13} /> Shadow IT</span>
                    ) : a.reviewed ? (
                      <span className="inline-flex items-center gap-1 text-emerald-300 text-[11.5px]">
                        <ShieldCheck size={13} /> Reviewed{a.review_rating ? ` · ${a.review_rating}` : ""}
                      </span>
                    ) : (
                      <span className="text-slate-500 text-[11.5px]">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Layout>
  );
}

function Stat({ label, value, tone, onClick, active }) {
  const toneCls = tone === "red" ? "text-red-300" : tone === "green" ? "text-emerald-300" : "text-slate-100";
  return (
    <button onClick={onClick} disabled={!onClick}
      className={`text-left border rounded-md px-3 py-2.5 ${active ? "border-blue-500/40 bg-blue-500/[0.04]" : "border-[#30363D] bg-[#0D1117]"} ${onClick ? "hover:border-slate-500 cursor-pointer" : "cursor-default"}`}>
      <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500">{label}</div>
      <div className={`text-[19px] font-semibold mt-0.5 ${toneCls}`}>{value}</div>
    </button>
  );
}
