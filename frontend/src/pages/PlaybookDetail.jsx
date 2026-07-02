import { useEffect, useMemo, useState, useCallback } from "react";
import { useParams, useSearchParams, Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { categoryMeta } from "@/lib/playbookCategories";
import ReactFlow, { Background, Controls, MarkerType } from "reactflow";
import "reactflow/dist/style.css";
import {
  CheckCircle, Circle, ArrowCounterClockwise, PencilSimple, ArrowLeft,
  FlagCheckered, Play,
} from "@phosphor-icons/react";

const NODE_W = 260;

function StepNode({ data }) {
  const { index, text, done, onToggle } = data;
  return (
    <div
      onClick={onToggle}
      style={{
        width: NODE_W, cursor: "pointer",
        background: done ? "#0f2418" : "#161B22",
        border: `1.5px solid ${done ? "#22c55e88" : "#30363D"}`,
        borderRadius: 8, padding: "10px 12px",
        boxShadow: done ? "0 0 10px rgba(34,197,94,0.15)" : "none",
        transition: "all 120ms",
      }}
    >
      <div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
        {done
          ? <CheckCircle size={17} weight="fill" color="#22c55e" style={{ flexShrink: 0, marginTop: 1 }} />
          : <Circle size={17} color="#8B949E" style={{ flexShrink: 0, marginTop: 1 }} />}
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 9, fontFamily: "JetBrains Mono", color: "#8B949E", letterSpacing: 0.5 }}>
            STEP {index + 1}
          </div>
          <div style={{ fontSize: 12, color: done ? "#c9f5d9" : "#e2e8f0", marginTop: 2, lineHeight: 1.35 }}>
            {text}
          </div>
        </div>
      </div>
    </div>
  );
}

function EndpointNode({ data }) {
  const { label, sub, tone, Icon } = data;
  const tones = {
    start: { bg: "#1e2a1e", border: "#3b6b3b", fg: "#a7e8b3" },
    validate: { bg: "#1e2333", border: "#3b5b8b", fg: "#a7c8f5" },
    rollback: { bg: "#2a1a12", border: "#8b5a2a", fg: "#f5c99a" },
  };
  const t = tones[tone] || tones.start;
  return (
    <div style={{
      width: NODE_W, background: t.bg, border: `1.5px solid ${t.border}`, borderRadius: 8,
      padding: "10px 12px", display: "flex", alignItems: "center", gap: 8,
    }}>
      <Icon size={16} color={t.fg} style={{ flexShrink: 0 }} />
      <div>
        <div style={{ fontSize: 12, fontWeight: 600, color: t.fg }}>{label}</div>
        {sub && <div style={{ fontSize: 10, color: t.fg, opacity: 0.7, marginTop: 1 }}>{sub}</div>}
      </div>
    </div>
  );
}

const nodeTypes = { step: StepNode, endpoint: EndpointNode };

function buildFlow(playbook, doneSteps, toggleStep) {
  const steps = playbook.steps || [];
  const gapY = 92;
  let y = 0;
  const nodes = [];
  const edges = [];

  nodes.push({
    id: "start", type: "endpoint", position: { x: 0, y },
    data: { label: "Finding identified", sub: playbook.cve || playbook.cwe || "", tone: "start", Icon: Play },
    draggable: false,
  });
  y += gapY;

  steps.forEach((s, i) => {
    const id = `step-${i}`;
    nodes.push({
      id, type: "step", position: { x: 0, y },
      data: { index: i, text: s, done: doneSteps.has(i), onToggle: () => toggleStep(i) },
      draggable: false,
    });
    edges.push({
      id: `e-${i}`, source: i === 0 ? "start" : `step-${i - 1}`, target: id,
      animated: doneSteps.has(i) && (i === 0 || doneSteps.has(i - 1)) && !doneSteps.has(i),
      style: { stroke: doneSteps.has(i) ? "#22c55e" : "#30363D", strokeWidth: 1.5 },
      markerEnd: { type: MarkerType.ArrowClosed, color: doneSteps.has(i) ? "#22c55e" : "#484F58", width: 14, height: 14 },
    });
    y += gapY;
  });

  const allDone = steps.length > 0 && doneSteps.size === steps.length;
  nodes.push({
    id: "validate", type: "endpoint", position: { x: 0, y },
    data: { label: "Validate the fix", sub: `${playbook.validation_checks?.length || 0} check(s) below`, tone: "validate", Icon: CheckCircle },
    draggable: false,
  });
  edges.push({
    id: "e-validate",
    source: steps.length ? `step-${steps.length - 1}` : "start",
    target: "validate",
    style: { stroke: allDone ? "#22c55e" : "#30363D", strokeWidth: 1.5 },
    markerEnd: { type: MarkerType.ArrowClosed, color: allDone ? "#22c55e" : "#484F58", width: 14, height: 14 },
  });

  if (playbook.rollback_notes) {
    nodes.push({
      id: "rollback", type: "endpoint", position: { x: NODE_W + 60, y: Math.max(0, y - gapY / 2) },
      data: { label: "If it breaks something", sub: "Rollback path", tone: "rollback", Icon: ArrowCounterClockwise },
      draggable: false,
    });
    edges.push({
      id: "e-rollback",
      source: steps.length ? `step-${steps.length - 1}` : "start",
      target: "rollback",
      style: { stroke: "#8b5a2a", strokeWidth: 1.5, strokeDasharray: "4 3" },
      markerEnd: { type: MarkerType.ArrowClosed, color: "#8b5a2a", width: 12, height: 12 },
    });
  }

  return { nodes, edges, height: y + gapY };
}

export default function PlaybookDetail() {
  const { id } = useParams();
  const [searchParams] = useSearchParams();
  const findingId = searchParams.get("finding");
  const [playbook, setPlaybook] = useState(null);
  const [finding, setFinding] = useState(null);
  const [doneSteps, setDoneSteps] = useState(new Set());
  const [doneChecks, setDoneChecks] = useState(new Set());
  const [validated, setValidated] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api.get(`/v1/playbooks/${id}`).then(r => setPlaybook(r.data));
  }, [id]);

  useEffect(() => {
    if (!findingId) return;
    api.get(`/v1/findings/${findingId}`).then(r => setFinding(r.data));
    api.get(`/v1/findings/${findingId}/playbook`).then(r => {
      const p = r.data.progress;
      if (p && p.playbook_id === id) {
        setDoneSteps(new Set(p.steps_done || []));
        setDoneChecks(new Set(p.validated_checks || []));
        setValidated(!!p.validated);
      }
    });
  }, [findingId, id]);

  const persist = useCallback(async (steps, checks, isValidated) => {
    if (!findingId) return;
    setSaving(true);
    try {
      await api.put(`/v1/findings/${findingId}/playbook-progress`, {
        playbook_id: id, steps_done: Array.from(steps), validated_checks: Array.from(checks), validated: isValidated,
      });
    } catch (e) {
      toast.error("Failed to save checklist progress");
    } finally { setSaving(false); }
  }, [findingId, id]);

  const toggleStep = useCallback((i) => {
    setDoneSteps(prev => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i); else next.add(i);
      persist(next, doneChecks, validated);
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [doneChecks, validated, persist]);

  const toggleCheck = useCallback((i) => {
    setDoneChecks(prev => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i); else next.add(i);
      persist(doneSteps, next, validated);
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [doneSteps, validated, persist]);

  const markValidated = () => {
    setValidated(true);
    persist(doneSteps, doneChecks, true);
    toast.success("Marked as validated");
  };

  const { nodes, edges, height } = useMemo(
    () => playbook ? buildFlow(playbook, doneSteps, toggleStep) : { nodes: [], edges: [], height: 400 },
    [playbook, doneSteps, toggleStep],
  );

  if (!playbook) {
    return <Layout title="Playbook" subtitle="Loading…"><div className="text-[12.5px] text-slate-500">Loading…</div></Layout>;
  }

  const meta = categoryMeta(playbook.category);
  const Icon = meta.icon;
  const progress = playbook.steps?.length ? Math.round((doneSteps.size / playbook.steps.length) * 100) : 0;
  const allStepsDone = playbook.steps?.length > 0 && doneSteps.size === playbook.steps.length;
  const allChecksDone = !playbook.validation_checks?.length || doneChecks.size === playbook.validation_checks.length;

  return (
    <Layout
      title={playbook.title}
      subtitle={findingId
        ? `Checklist for finding: ${finding?.title?.slice(0, 60) || "…"}${findingId ? " — progress is saved" : ""}`
        : (playbook.description || "Step-by-step remediation flow — open from a finding to save your progress")}
      actions={<>
        <Link to={findingId ? `/findings/${findingId}` : "/admin/playbooks"} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300">
          <ArrowLeft size={14}/> {findingId ? "Back to finding" : "All playbooks"}
        </Link>
        <Link to={`/admin/playbooks?edit=${playbook.id}`} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300">
          <PencilSimple size={14}/> Edit
        </Link>
      </>}
    >
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 min-w-0 space-y-3">
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3 flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <div style={{ background: `${meta.color}22`, border: `1px solid ${meta.color}55` }} className="rounded-md p-1.5">
                <Icon size={16} style={{ color: meta.color }} />
              </div>
              <div>
                <div className="text-[12px] text-slate-200 font-medium" style={{ color: meta.color }}>{meta.label}</div>
                <div className="text-[10.5px] text-slate-500 font-mono">
                  {playbook.cve ? `Exact match: ${playbook.cve}` : playbook.cwe ? `Class match: ${playbook.cwe}` : "Unattached"}
                </div>
              </div>
            </div>
            <div className="text-right shrink-0">
              <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Your progress</div>
              <div className="text-[15px] font-mono font-semibold text-slate-100">{progress}%</div>
            </div>
          </div>

          <div className="text-[11px] text-slate-500 px-1 flex items-center gap-1.5">
            {findingId
              ? <>Click a step to check it off — saved against this finding{saving ? " (saving…)" : "."}</>
              : <>Click a step to check it off as you go — open this playbook from a specific finding to save your progress.</>}
          </div>

          <div style={{ height: Math.max(360, height + 60) }} className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={nodeTypes}
              fitView
              fitViewOptions={{ padding: 0.25 }}
              proOptions={{ hideAttribution: true }}
              nodesDraggable={false}
              nodesConnectable={false}
              elementsSelectable={false}
              zoomOnScroll={true}
            >
              <Background color="#21262d" gap={18} />
              <Controls showInteractive={false} />
            </ReactFlow>
          </div>
        </div>

        <div className="space-y-3">
          {playbook.rollback_notes && (
            <div className="border border-amber-500/30 bg-amber-500/5 rounded-md p-3.5">
              <div className="text-[10px] uppercase font-mono text-amber-400 tracking-wider mb-1.5 flex items-center gap-1.5">
                <ArrowCounterClockwise size={12}/> Rollback notes
              </div>
              <div className="text-[12px] text-amber-100/90 leading-relaxed">{playbook.rollback_notes}</div>
            </div>
          )}

          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3.5">
            <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider mb-2 flex items-center gap-1.5">
              <FlagCheckered size={12}/> Validation checks
            </div>
            {playbook.validation_checks?.length ? (
              <ul className="space-y-1.5">
                {playbook.validation_checks.map((v, i) => {
                  const done = doneChecks.has(i);
                  return (
                    <li key={i}>
                      {findingId ? (
                        <button onClick={() => toggleCheck(i)}
                          className="w-full flex items-start gap-1.5 text-[12px] text-left">
                          <span className={done ? "text-emerald-400 mt-0.5" : "text-slate-600 mt-0.5"}>✓</span>
                          <span className={done ? "text-emerald-100/80 line-through decoration-emerald-500/40" : "text-slate-300"}>{v}</span>
                        </button>
                      ) : (
                        <div className="text-[12px] text-slate-300 flex items-start gap-1.5">
                          <span className="text-emerald-400 mt-0.5">✓</span> {v}
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>
            ) : <div className="text-[12px] text-slate-500">None recorded.</div>}
          </div>

          {findingId && allStepsDone && allChecksDone && !validated && (
            <button onClick={markValidated}
              className="w-full h-9 text-[12.5px] bg-emerald-500/15 border border-emerald-500/40 hover:bg-emerald-500/25 text-emerald-200 rounded inline-flex items-center justify-center gap-1.5">
              <FlagCheckered size={14}/> Mark fix validated
            </button>
          )}

          <div className="text-[10.5px] text-slate-600 px-1">
            Created {playbook.created_by ? `by ${playbook.created_by}` : ""} {playbook.updated_at ? `· updated ${playbook.updated_at.slice(0,10)}` : ""}
          </div>
        </div>
      </div>
    </Layout>
  );
}
