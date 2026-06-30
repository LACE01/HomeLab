import { useEffect, useState, useCallback } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import ReactFlow, { Background, Controls, MiniMap, MarkerType } from "reactflow";
import "reactflow/dist/style.css";
import { Shield, Globe, Desktop, HardDrives as HardDrivesIcon, Crown, Lightning } from "@phosphor-icons/react";

const NODE_STYLES = {
  internet: { background: "#1e3a8a", color: "#dbeafe", border: "2px solid #3b82f6", icon: Globe },
  source: { background: "#7c2d12", color: "#fed7aa", border: "2px solid #ef4444", icon: Desktop },
  pivot: { background: "#1f2937", color: "#e2e8f0", border: "1.5px solid #6b7280", icon: HardDrivesIcon },
  target: { background: "#7f1d1d", color: "#fecaca", border: "2px solid #dc2626", icon: Crown },
};

function buildLayout(nodes, edges) {
  // Horizontal layered layout: internet → source → pivot → target
  const layers = { internet: 0, source: 1, pivot: 2, target: 3 };
  const cols = {};
  nodes.forEach(n => { const c = layers[n.role] ?? 2; cols[c] = (cols[c] || 0) + 1; });
  const counters = {};
  const rfNodes = nodes.map(n => {
    const layer = layers[n.role] ?? 2;
    counters[layer] = (counters[layer] || 0);
    const y = 60 + counters[layer] * 110;
    counters[layer]++;
    const style = NODE_STYLES[n.role] || NODE_STYLES.pivot;
    return {
      id: n.id,
      position: { x: 80 + layer * 280, y },
      data: {
        label: (
          <div style={{ padding: 6, minWidth: 130, color: style.color }}>
            <div style={{ fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{n.label}</div>
            <div style={{ fontSize: 9, opacity: 0.75, marginTop: 2 }}>
              {n.platform || n.role} {n.criticality ? `· ${n.criticality}` : ""}
            </div>
            <div style={{ fontSize: 9, opacity: 0.6, marginTop: 2 }}>{n.owner_team || ""}</div>
          </div>
        ),
      },
      style: { background: style.background, border: style.border, borderRadius: 8, padding: 0 },
    };
  });
  const rfEdges = edges.map(e => ({
    id: e.id, source: e.source, target: e.target, label: e.label,
    labelStyle: { fill: "#fca5a5", fontSize: 10, fontWeight: 600 },
    labelBgStyle: { fill: "#0D1117", fillOpacity: 0.9 },
    style: { stroke: "#ef4444", strokeWidth: 2, strokeDasharray: "5 4" },
    animated: true,
    markerEnd: { type: MarkerType.ArrowClosed, color: "#ef4444" },
  }));
  return { rfNodes, rfEdges };
}

export default function AttackPaths() {
  const [cves, setCves] = useState([]);
  const [selected, setSelected] = useState(null);
  const [graph, setGraph] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.get("/v1/attack-paths/cves").then(r => {
      setCves(r.data.items);
      if (r.data.items.length && !selected) {
        setSelected(r.data.items[0].cve);
      }
    });
  // eslint-disable-next-line
  }, []);

  useEffect(() => {
    if (!selected) return;
    setLoading(true);
    api.get("/v1/attack-paths/graph", { params: { cve: selected } })
      .then(r => setGraph(r.data))
      .finally(() => setLoading(false));
  }, [selected]);

  const { rfNodes, rfEdges } = graph ? buildLayout(graph.nodes, graph.edges) : { rfNodes: [], rfEdges: [] };

  return (
    <Layout title="Attack Path Analysis" subtitle="Real-time CVE-driven lateral-movement visualization">
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-3">
        {/* Left: CVE picker */}
        <div className="lg:col-span-1 border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
          <div className="px-3 py-2 border-b border-[#30363D] text-[11px] uppercase tracking-wider font-mono text-slate-400">CVEs with open findings</div>
          <div className="max-h-[640px] overflow-y-auto">
            {cves.map(c => (
              <button key={c.cve} data-testid={`cve-${c.cve}`} onClick={()=>setSelected(c.cve)}
                className={`w-full text-left px-3 py-2 border-b border-[#30363D]/40 hover:bg-slate-800/30 ${selected===c.cve?"bg-blue-500/10 border-l-2 border-l-blue-400":""}`}>
                <div className="font-mono text-[12px] text-blue-300">{c.cve}</div>
                <div className="text-[11px] text-slate-300 truncate mt-0.5">{c.title}</div>
                <div className="mt-1 flex items-center gap-1 flex-wrap">
                  <Chip color={c.severity==="Critical"?"red":"orange"}>{c.severity}</Chip>
                  {c.kev && <Chip color="red">KEV</Chip>}
                  <span className="text-[10px] font-mono text-slate-500">{c.affected_assets} assets</span>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Right: Graph */}
        <div className="lg:col-span-3 space-y-3">
          {graph && (
            <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3 flex items-center justify-between">
              <div>
                <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Attack Path</div>
                <div className="text-[14px] text-slate-100 mt-0.5" data-testid="path-summary">{graph.summary}</div>
              </div>
              <div className="flex items-center gap-2">
                <Chip color="red">{graph.stats?.internet_sources} sources</Chip>
                <Chip>{graph.stats?.pivots} pivots</Chip>
                <Chip color="red">{graph.stats?.crown_jewels} crown jewels</Chip>
              </div>
            </div>
          )}

          <div className="border border-[#30363D] bg-[#0D1117] rounded-md" style={{ height: 480 }}>
            {loading && <div className="flex items-center justify-center h-full text-slate-500">Computing path…</div>}
            {!loading && rfNodes.length > 0 && (
              <ReactFlow nodes={rfNodes} edges={rfEdges} fitView fitViewOptions={{ padding: 0.2 }}
                proOptions={{ hideAttribution: true }} nodesDraggable={true}>
                <Background color="#30363D" gap={20} />
                <Controls className="!bg-[#0D1117] !border-[#30363D]"/>
                <MiniMap className="!bg-[#0D1117]" nodeColor={(n)=>n.style?.background || "#30363D"} maskColor="rgba(13,17,23,0.7)" />
              </ReactFlow>
            )}
          </div>

          {graph?.remediation_options?.length > 0 && (
            <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
              <div className="px-3 py-2 border-b border-[#30363D] text-[11px] uppercase tracking-wider font-mono text-slate-400 flex items-center gap-2">
                <Lightning size={13}/> Path Remediation Options
              </div>
              <table className="dense w-full">
                <thead><tr><th className="text-left">Description</th><th>Assets</th><th>Remediations</th><th>Risk Reduction</th></tr></thead>
                <tbody>
                  {graph.remediation_options.map(o => (
                    <tr key={o.id} className="border-t border-[#30363D]">
                      <td className="text-slate-200">{o.description}</td>
                      <td className="text-center font-mono">{o.assets}</td>
                      <td className="text-center font-mono">{o.remediations}</td>
                      <td><div className="flex items-center gap-2">
                        <div className="h-1.5 w-20 bg-slate-800 rounded overflow-hidden"><div className="h-full bg-emerald-500" style={{width:`${o.risk_reduction}%`}}/></div>
                        <span className="font-mono text-[11px]">−{o.risk_reduction}%</span>
                      </div></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
