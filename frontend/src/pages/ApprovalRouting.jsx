import { useEffect, useMemo, useState, useCallback } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import ReactFlow, { Background, Controls, MarkerType } from "reactflow";
import "reactflow/dist/style.css";
import { toast } from "sonner";

const TIER_COLORS = { Critical: "#ef4444", High: "#f97316", Medium: "#f59e0b", Low: "#3b82f6" };
const ROW_H = 150;
const STEP_W = 210;
const STEP_GAP = 60;
const TIER_W = 150;

function TierNode({ data }) {
  const { tier, color, isDefault, dirty, saving, onSave, onReset } = data;
  return (
    <div style={{
      width: TIER_W, background: "#0D1117", border: `1.5px solid ${color}66`, borderLeft: `4px solid ${color}`,
      borderRadius: 8, padding: "10px 12px",
    }}>
      <div style={{ fontSize: 13, fontWeight: 600, color }}>{tier}</div>
      <div style={{ fontSize: 9.5, color: "#8B949E", marginTop: 2, lineHeight: 1.3 }}>
        {isDefault ? "Default — any manager or admin" : "Custom route"}
      </div>
      <div style={{ display: "flex", gap: 5, marginTop: 8 }}>
        <button className="nodrag nopan" onClick={onSave} disabled={!dirty || saving}
          style={{ fontSize: 10, padding: "3px 7px", borderRadius: 4, border: "1px solid #2F81F766",
                   background: dirty ? "#2F81F733" : "transparent", color: dirty ? "#7db8ff" : "#576069", cursor: dirty ? "pointer" : "default" }}>
          {saving ? "Saving…" : "Save"}
        </button>
        <button className="nodrag nopan" onClick={onReset}
          style={{ fontSize: 10, padding: "3px 7px", borderRadius: 4, border: "1px solid #30363D", background: "transparent", color: "#8B949E", cursor: "pointer" }}>
          Reset
        </button>
      </div>
    </div>
  );
}

function StepNode({ data }) {
  const { step, role, approver_email, roleOptions, onChangeRole, onChangeEmail, onDelete, canDelete } = data;
  return (
    <div style={{ width: STEP_W, background: "#161B22", border: "1.5px solid #30363D", borderRadius: 8, padding: "10px 12px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
        <span style={{ fontSize: 9, fontFamily: "JetBrains Mono", color: "#8B949E", letterSpacing: 0.5 }}>STEP {step}</span>
        {canDelete && (
          <button className="nodrag nopan" onClick={onDelete} style={{ color: "#f87171", background: "none", border: "none", cursor: "pointer", fontSize: 13, lineHeight: 1 }}>✕</button>
        )}
      </div>
      <select className="nodrag nopan" value={role} onChange={e => onChangeRole(e.target.value)}
        style={{ width: "100%", height: 26, background: "#0D1117", border: "1px solid #30363D", borderRadius: 4, color: "#e2e8f0", fontSize: 11.5, padding: "0 4px" }}>
        {roleOptions.map(r => <option key={r} value={r}>{r === "specific" ? "specific person" : r}</option>)}
      </select>
      {role === "specific" && (
        <input className="nodrag nopan" type="email" placeholder="person@company.com" value={approver_email || ""}
          onChange={e => onChangeEmail(e.target.value)}
          style={{ width: "100%", height: 26, marginTop: 6, background: "#0D1117", border: "1px solid #30363D", borderRadius: 4, color: "#e2e8f0", fontSize: 11, padding: "0 6px" }}/>
      )}
    </div>
  );
}

function AddStepNode({ data }) {
  return (
    <button className="nodrag nopan" onClick={data.onAdd}
      style={{ width: STEP_W, height: 62, borderRadius: 8, border: "1.5px dashed #30363D", background: "transparent",
               color: "#8B949E", fontSize: 11.5, cursor: "pointer" }}>
      + Add step
    </button>
  );
}

const nodeTypes = { tier: TierNode, step: StepNode, add: AddStepNode };

export default function ApprovalRouting() {
  const [tiers, setTiers] = useState(null); // { Critical: {chain:[...], is_default, dirty}, ... }
  const [roleOptions, setRoleOptions] = useState(["manager", "admin", "specific"]);
  const [saving, setSaving] = useState(null); // tier currently saving

  const load = useCallback(() => {
    api.get("/v1/admin/approval-routes").then(r => {
      setRoleOptions(r.data.role_options || ["manager", "admin", "specific"]);
      const obj = {};
      r.data.tiers.forEach(t => { obj[t.tier] = { chain: t.chain, is_default: t.is_default, dirty: false }; });
      setTiers(obj);
    });
  }, []);
  useEffect(() => { load(); }, [load]);

  const updateChain = (tier, nextChain) => {
    setTiers(prev => ({ ...prev, [tier]: { ...prev[tier], chain: nextChain, dirty: true } }));
  };
  const addStep = (tier) => {
    const chain = tiers[tier].chain;
    updateChain(tier, [...chain, { step: chain.length + 1, role: "manager", approver_email: null }]);
  };
  const removeStep = (tier, idx) => {
    const chain = tiers[tier].chain.filter((_, i) => i !== idx).map((c, i) => ({ ...c, step: i + 1 }));
    updateChain(tier, chain.length ? chain : [{ step: 1, role: "manager", approver_email: null }]);
  };
  const changeRole = (tier, idx, role) => {
    const chain = tiers[tier].chain.map((c, i) => i === idx ? { ...c, role, approver_email: role === "specific" ? c.approver_email : null } : c);
    updateChain(tier, chain);
  };
  const changeEmail = (tier, idx, email) => {
    const chain = tiers[tier].chain.map((c, i) => i === idx ? { ...c, approver_email: email } : c);
    updateChain(tier, chain);
  };
  const saveTier = async (tier) => {
    setSaving(tier);
    try {
      const chain = tiers[tier].chain;
      for (const c of chain) {
        if (c.role === "specific" && !c.approver_email?.trim()) {
          toast.error(`${tier}: every "specific person" step needs an email`);
          setSaving(null);
          return;
        }
      }
      await api.put(`/v1/admin/approval-routes/${tier}`, { chain: chain.map(c => ({ role: c.role, approver_email: c.approver_email })) });
      toast.success(`${tier} approval route saved.`);
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to save route");
    } finally { setSaving(null); }
  };
  const resetTier = async (tier) => {
    try {
      await api.delete(`/v1/admin/approval-routes/${tier}`);
      toast.success(`${tier} reset to default.`);
      await load();
    } catch (e) {
      toast.error("Failed to reset route");
    }
  };

  const { nodes, edges } = useMemo(() => {
    if (!tiers) return { nodes: [], edges: [] };
    const nodes = [], edges = [];
    const order = ["Critical", "High", "Medium", "Low"];
    order.forEach((tier, ti) => {
      const y = ti * ROW_H;
      const color = TIER_COLORS[tier];
      const t = tiers[tier];
      nodes.push({
        id: `tier-${tier}`, type: "tier", position: { x: 0, y }, draggable: false, selectable: false,
        data: { tier, color, isDefault: t.is_default, dirty: t.dirty, saving: saving === tier, onSave: () => saveTier(tier), onReset: () => resetTier(tier) },
      });
      let prevId = `tier-${tier}`;
      t.chain.forEach((c, i) => {
        const x = TIER_W + 50 + i * (STEP_W + STEP_GAP);
        const id = `${tier}-step-${i}`;
        nodes.push({
          id, type: "step", position: { x, y }, draggable: false, selectable: false,
          data: {
            step: c.step, role: c.role, approver_email: c.approver_email, roleOptions, canDelete: t.chain.length > 1,
            onChangeRole: (role) => changeRole(tier, i, role), onChangeEmail: (email) => changeEmail(tier, i, email),
            onDelete: () => removeStep(tier, i),
          },
        });
        edges.push({ id: `${prevId}-${id}`, source: prevId, target: id, animated: false,
          style: { stroke: `${color}88` }, markerEnd: { type: MarkerType.ArrowClosed, color: `${color}88` } });
        prevId = id;
      });
      const addId = `${tier}-add`;
      const addX = TIER_W + 50 + t.chain.length * (STEP_W + STEP_GAP);
      nodes.push({ id: addId, type: "add", position: { x: addX, y: y + 12 }, draggable: false, selectable: false, data: { onAdd: () => addStep(tier) } });
      edges.push({ id: `${prevId}-${addId}`, source: prevId, target: addId, style: { stroke: "#30363D" } });
    });
    return { nodes, edges };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tiers, saving, roleOptions]);

  return (
    <Layout title="Approval Routing" subtitle="Who has to sign off on a risk acceptance, by severity tier — build a sequential approval chain per tier">
      <div className="text-[12px] text-slate-500 mb-3">
        Each row is a severity tier. A risk acceptance request is routed through its tier's chain left-to-right — every
        step must approve before the exception goes active. Admins can always act on any step. Unconfigured tiers use
        the default (any manager or admin, single step).
      </div>
      <div style={{ height: 4 * ROW_H + 40 }} className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        {tiers && (
          <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView proOptions={{ hideAttribution: true }}
            nodesDraggable={false} nodesConnectable={false} elementsSelectable={false}>
            <Background color="#30363D" gap={20} />
            <Controls showInteractive={false} />
          </ReactFlow>
        )}
      </div>
    </Layout>
  );
}
