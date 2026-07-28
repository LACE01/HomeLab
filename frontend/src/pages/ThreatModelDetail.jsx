import { useEffect, useState, useRef } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  ArrowLeft, Plus, X, FloppyDisk, CaretDown, CaretRight, TreeStructure,
  Cube, Database, Globe, Selection, ArrowRight, Trash, Sparkle, ShieldCheck,
} from "@phosphor-icons/react";

const RISK_COLOR = { Low: "blue", Medium: "amber", High: "orange", Critical: "red" };
const STRIDE_SHORT = { "Spoofing": "S", "Tampering": "T", "Repudiation": "R",
  "Information Disclosure": "I", "Denial of Service": "D", "Elevation of Privilege": "E" };
const EL_META = {
  process: { icon: Cube, label: "Process", color: "#3b82f6" },
  datastore: { icon: Database, label: "Data store", color: "#a855f7" },
  external: { icon: Globe, label: "External entity", color: "#f59e0b" },
  boundary: { icon: Selection, label: "Trust boundary", color: "#64748b" },
};
const DREAD_KEYS = [
  ["damage", "Damage"], ["reproducibility", "Reproducibility"], ["exploitability", "Exploitability"],
  ["affected_users", "Affected users"], ["discoverability", "Discoverability"],
];

export default function ThreatModelDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [model, setModel] = useState(null);
  const [threats, setThreats] = useState([]);
  const [meta, setMeta] = useState(null);
  const [elements, setElements] = useState([]);
  const [flows, setFlows] = useState([]);
  const [dirty, setDirty] = useState(false);
  const [selected, setSelected] = useState(null);       // element id
  const [connectFrom, setConnectFrom] = useState(null); // element id when in connect mode
  const [tab, setTab] = useState("threats");            // threats | tree | matrix

  const load = async () => {
    const [r, m] = await Promise.all([
      api.get(`/v1/threat-models/${id}`),
      meta ? Promise.resolve({ data: meta }) : api.get("/v1/threat-models/meta"),
    ]);
    setModel(r.data.model);
    setThreats(r.data.threats || []);
    setElements(r.data.model.elements || []);
    setFlows(r.data.model.flows || []);
    if (!meta) setMeta(m.data);
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [id]);

  if (!model || !meta) return <Layout title="Threat model…"><div className="text-slate-500">Loading…</div></Layout>;

  const saveDiagram = async () => {
    try {
      await api.put(`/v1/threat-models/${id}/diagram`, { elements, flows });
      setDirty(false);
      toast.success("Diagram saved");
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Save failed"); }
  };

  const addElement = (type) => {
    const el = {
      id: `new-${Date.now()}`, type,
      name: type === "boundary" ? "New boundary" : `New ${EL_META[type].label.toLowerCase()}`,
      x: 80 + Math.random() * 200, y: 80 + Math.random() * 150,
      ...(type === "boundary" ? { w: 260, h: 160 } : {}),
    };
    setElements(prev => [...prev, el]);
    setSelected(el.id);
    setDirty(true);
  };

  const removeElement = (elId) => {
    setElements(prev => prev.filter(e => e.id !== elId));
    setFlows(prev => prev.filter(f => f.from_id !== elId && f.to_id !== elId));
    if (selected === elId) setSelected(null);
    setDirty(true);
  };

  const clickElement = (el) => {
    if (connectFrom) {
      if (connectFrom !== el.id) {
        setFlows(prev => [...prev, { id: `new-${Date.now()}`, from_id: connectFrom, to_id: el.id, label: "data" }]);
        setDirty(true);
      }
      setConnectFrom(null);
      return;
    }
    setSelected(el.id);
  };

  const selectedEl = elements.find(e => e.id === selected);
  const openCount = threats.filter(t => t.status === "open").length;

  return (
    <Layout title={model.name}
      subtitle={`${elements.length} elements · ${flows.length} flows · ${threats.length} threats (${openCount} open)`}
      actions={
        <div className="flex items-center gap-2">
          <button onClick={() => navigate(-1)} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300">
            <ArrowLeft size={13}/> Back
          </button>
          {dirty && (
            <button onClick={saveDiagram}
              className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
              <FloppyDisk size={13}/> Save diagram
            </button>
          )}
        </div>
      }>

      <div className="grid lg:grid-cols-3 gap-4 mb-4">
        {/* Canvas */}
        <div className="lg:col-span-2 border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
          <div className="px-3 py-2 border-b border-[#30363D] flex items-center gap-1.5 flex-wrap">
            {Object.entries(EL_META).map(([type, m]) => {
              const Icon = m.icon;
              return (
                <button key={type} onClick={() => addElement(type)}
                  className="h-7 px-2 text-[11.5px] border border-[#30363D] hover:border-slate-500 text-slate-300 rounded inline-flex items-center gap-1">
                  <Icon size={12} style={{ color: m.color }}/> {m.label}
                </button>
              );
            })}
            <button onClick={() => { setConnectFrom(selected); if (!selected) toast.error("Select an element first"); }}
              disabled={!selected}
              className={`h-7 px-2 text-[11.5px] border rounded inline-flex items-center gap-1 disabled:opacity-40 ${connectFrom ? "border-blue-500/50 text-blue-300 bg-blue-500/10" : "border-[#30363D] text-slate-300"}`}>
              <ArrowRight size={12}/> {connectFrom ? "Click a target…" : "Connect flow"}
            </button>
            {selectedEl && (
              <button onClick={() => removeElement(selected)}
                className="h-7 px-2 text-[11.5px] border border-[#30363D] text-slate-400 hover:text-red-400 rounded inline-flex items-center gap-1">
                <Trash size={12}/> Delete element
              </button>
            )}
          </div>
          <DfdCanvas elements={elements} flows={flows} selected={selected}
            onSelect={clickElement}
            onMove={(elId, x, y) => {
              setElements(prev => prev.map(e => e.id === elId ? { ...e, x, y } : e));
              setDirty(true);
            }}/>
        </div>

        {/* Element / STRIDE panel */}
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          {selectedEl ? (
            <ElementPanel key={selectedEl.id} modelId={id} el={selectedEl} meta={meta}
              onRename={(name) => { setElements(prev => prev.map(e => e.id === selectedEl.id ? { ...e, name } : e)); setDirty(true); }}
              onThreatAdded={load} savedOnServer={!String(selectedEl.id).startsWith("new-")}/>
          ) : (
            <div className="text-[12px] text-slate-500">
              <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-2">STRIDE workspace</div>
              Select an element on the canvas to see which STRIDE categories apply to it and add threats.
              Drag elements to arrange; "Connect flow" links two elements; save when done.
            </div>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-[#30363D] mb-4">
        {[["threats", "Threats & DREAD"], ["tree", "Attack Tree"], ["matrix", "5×5 Matrix"]].map(([tid, label]) => (
          <button key={tid} onClick={() => setTab(tid)}
            className={`h-9 px-3 text-[12.5px] border-b-2 -mb-px ${tab === tid ? "border-blue-500 text-blue-300" : "border-transparent text-slate-400 hover:text-slate-200"}`}>
            {label}
          </button>
        ))}
      </div>

      {tab === "threats" && <ThreatsPanel modelId={id} threats={threats} elements={elements} meta={meta} onChange={load}/>}
      {tab === "tree" && <AttackTree modelId={id} threats={threats} elements={elements} onChange={load}/>}
      {tab === "matrix" && <MatrixPanel threats={threats}/>}
    </Layout>
  );
}

/* ------------------------------ DFD canvas ------------------------------ */

function DfdCanvas({ elements, flows, selected, onSelect, onMove }) {
  const svgRef = useRef(null);
  const drag = useRef(null);

  const height = Math.max(420, ...elements.map(e => (e.y || 0) + (e.h || 60) + 60));

  const startDrag = (e, el) => {
    e.stopPropagation();
    const pt = svgRef.current.createSVGPoint();
    pt.x = e.clientX; pt.y = e.clientY;
    const loc = pt.matrixTransform(svgRef.current.getScreenCTM().inverse());
    drag.current = { id: el.id, dx: loc.x - el.x, dy: loc.y - el.y, moved: false };
  };
  const onMouseMove = (e) => {
    if (!drag.current) return;
    const pt = svgRef.current.createSVGPoint();
    pt.x = e.clientX; pt.y = e.clientY;
    const loc = pt.matrixTransform(svgRef.current.getScreenCTM().inverse());
    drag.current.moved = true;
    onMove(drag.current.id, Math.round(loc.x - drag.current.dx), Math.round(loc.y - drag.current.dy));
  };
  const endDrag = (el) => {
    if (drag.current && !drag.current.moved && el) onSelect(el);
    drag.current = null;
  };

  const center = (el) => el.type === "boundary"
    ? { x: el.x + (el.w || 260) / 2, y: el.y + (el.h || 160) / 2 }
    : { x: el.x + 45, y: el.y + 27 };

  return (
    <svg ref={svgRef} viewBox={`0 0 640 ${height}`} className="w-full select-none" style={{ minHeight: 420 }}
      onMouseMove={onMouseMove} onMouseUp={() => endDrag(null)} onMouseLeave={() => { drag.current = null; }}>
      <defs>
        <marker id="tm-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#8B949E"/>
        </marker>
      </defs>
      {/* boundaries first (behind) */}
      {elements.filter(e => e.type === "boundary").map(el => (
        <g key={el.id} onMouseDown={(e) => startDrag(e, el)} onMouseUp={() => endDrag(el)} className="cursor-move">
          <rect x={el.x} y={el.y} width={el.w || 260} height={el.h || 160} rx={8}
            fill="none" stroke={selected === el.id ? "#3b82f6" : "#64748B"} strokeWidth={selected === el.id ? 2 : 1.2}
            strokeDasharray="7 5"/>
          <text x={el.x + 8} y={el.y + 16} fill="#8B949E" fontSize="10" fontFamily="monospace">{el.name}</text>
        </g>
      ))}
      {/* flows */}
      {flows.map(f => {
        const from = elements.find(e => e.id === f.from_id);
        const to = elements.find(e => e.id === f.to_id);
        if (!from || !to) return null;
        const a = center(from), b = center(to);
        return (
          <g key={f.id}>
            <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#8B949E" strokeWidth="1.2" markerEnd="url(#tm-arrow)"/>
            {f.label && (
              <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 5} fill="#576069" fontSize="9" textAnchor="middle">{f.label}</text>
            )}
          </g>
        );
      })}
      {/* nodes */}
      {elements.filter(e => e.type !== "boundary").map(el => {
        const m = EL_META[el.type] || EL_META.process;
        const isSel = selected === el.id;
        return (
          <g key={el.id} onMouseDown={(e) => startDrag(e, el)} onMouseUp={() => endDrag(el)} className="cursor-move">
            {el.type === "datastore" ? (
              <g>
                <rect x={el.x} y={el.y + 4} width={90} height={46} fill="#161B22" stroke={isSel ? "#3b82f6" : m.color} strokeWidth={isSel ? 2 : 1.2}/>
                <line x1={el.x} y1={el.y + 12} x2={el.x + 90} y2={el.y + 12} stroke={m.color} strokeWidth="1"/>
              </g>
            ) : el.type === "external" ? (
              <rect x={el.x} y={el.y} width={90} height={54} fill="#161B22" stroke={isSel ? "#3b82f6" : m.color} strokeWidth={isSel ? 2 : 1.2}/>
            ) : (
              <rect x={el.x} y={el.y} width={90} height={54} rx={26} fill="#161B22" stroke={isSel ? "#3b82f6" : m.color} strokeWidth={isSel ? 2 : 1.2}/>
            )}
            <text x={el.x + 45} y={el.y + 32} fill="#E6EDF3" fontSize="10" textAnchor="middle">
              {el.name.length > 14 ? el.name.slice(0, 13) + "…" : el.name}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

/* --------------------------- Element STRIDE panel --------------------------- */

function ElementPanel({ modelId, el, meta, onRename, onThreatAdded, savedOnServer }) {
  const [suggestions, setSuggestions] = useState(null);
  const [adding, setAdding] = useState(null); // {stride, title, description}

  useEffect(() => {
    if (!savedOnServer) { setSuggestions(null); return; }
    api.get(`/v1/threat-models/${modelId}/stride-suggestions/${el.id}`)
      .then(r => setSuggestions(r.data.suggestions))
      .catch(() => setSuggestions(null));
  }, [modelId, el.id, savedOnServer]);

  const m = EL_META[el.type] || EL_META.process;
  const Icon = m.icon;
  const applicable = meta.stride_by_element[el.type] || [];

  const addThreat = async () => {
    if (!adding.title.trim()) { toast.error("Title required"); return; }
    try {
      await api.post(`/v1/threat-models/${modelId}/threats`, {
        element_id: el.id, stride: adding.stride, title: adding.title, description: adding.description,
      });
      toast.success("Threat added");
      setAdding(null);
      onThreatAdded();
      const r = await api.get(`/v1/threat-models/${modelId}/stride-suggestions/${el.id}`);
      setSuggestions(r.data.suggestions);
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to add threat"); }
  };

  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <Icon size={16} style={{ color: m.color }}/>
        <input value={el.name} onChange={e => onRename(e.target.value)}
          className="flex-1 h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100"/>
      </div>
      <div className="text-[10.5px] text-slate-500 mb-3">{m.label}{el.asset_id ? " · linked to asset inventory" : ""}</div>
      {applicable.length === 0 ? (
        <div className="text-[11.5px] text-slate-500">Trust boundaries organize the diagram — threats live on the elements and flows that cross them.</div>
      ) : !savedOnServer ? (
        <div className="text-[11.5px] text-amber-300">Save the diagram first, then add threats to this element.</div>
      ) : (
        <div className="space-y-1.5">
          <div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500">STRIDE checklist for this {m.label.toLowerCase()}</div>
          {(suggestions || applicable.map(s => ({ stride: s, example: meta.stride_examples[s].replace("{name}", el.name), covered: false }))).map(s => (
            <div key={s.stride} className={`border rounded-md px-2.5 py-2 ${s.covered ? "border-emerald-500/30 bg-emerald-500/5" : "border-[#30363D]"}`}>
              <div className="flex items-center justify-between">
                <div className="text-[12px] text-slate-200">
                  <span className="font-mono text-[10px] text-slate-500 mr-1.5">{STRIDE_SHORT[s.stride]}</span>{s.stride}
                </div>
                {s.covered ? <Chip color="emerald">covered</Chip> : (
                  <button onClick={() => setAdding({ stride: s.stride, title: "", description: s.example })}
                    className="h-6 px-2 text-[10.5px] border border-[#30363D] text-slate-300 rounded hover:border-blue-500/40 hover:text-blue-300">+ threat</button>
                )}
              </div>
              <div className="text-[10.5px] text-slate-500 mt-1">{s.example}</div>
            </div>
          ))}
        </div>
      )}
      {adding && (
        <div className="mt-3 border border-blue-500/30 bg-blue-500/5 rounded-md p-3 space-y-2">
          <div className="text-[11px] text-blue-300">New {adding.stride} threat on {el.name}</div>
          <input placeholder="Threat title" value={adding.title} onChange={e => setAdding({ ...adding, title: e.target.value })}
            className="w-full h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/>
          <textarea rows={3} value={adding.description} onChange={e => setAdding({ ...adding, description: e.target.value })}
            className="w-full px-2 py-1.5 bg-[#161B22] border border-[#30363D] rounded text-[11.5px] text-slate-200"/>
          <div className="flex gap-2">
            <button onClick={addThreat} className="h-7 px-2.5 text-[11.5px] bg-blue-500 hover:bg-blue-400 text-white rounded">Add</button>
            <button onClick={() => setAdding(null)} className="h-7 px-2.5 text-[11.5px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ------------------------------ Threats + DREAD ------------------------------ */

function ThreatsPanel({ modelId, threats, elements, meta, onChange }) {
  const [expanded, setExpanded] = useState(new Set());
  const elName = (id) => elements.find(e => e.id === id)?.name || "(unplaced)";

  const patch = async (t, body) => {
    try { await api.patch(`/v1/threat-models/${modelId}/threats/${t.id}`, body); onChange(); }
    catch (e) { toast.error(e.response?.data?.detail || "Update failed"); }
  };
  const remove = async (t) => {
    if (!window.confirm("Delete this threat (children become roots)?")) return;
    await api.delete(`/v1/threat-models/${modelId}/threats/${t.id}`); onChange();
  };

  const sorted = [...threats].sort((a, b) => (b.likelihood * b.impact) - (a.likelihood * a.impact));

  return (
    <div className="space-y-2">
      {sorted.length === 0 && <div className="text-[12.5px] text-slate-500 py-6 text-center border border-[#30363D] bg-[#0D1117] rounded-md">No threats yet — select an element on the canvas and use its STRIDE checklist.</div>}
      {sorted.map(t => {
        const isOpen = expanded.has(t.id);
        return (
          <div key={t.id} className="border border-[#30363D] bg-[#0D1117] rounded-md">
            <div className="px-3.5 py-2.5 flex items-center gap-2.5 cursor-pointer"
              onClick={() => setExpanded(prev => { const n = new Set(prev); n.has(t.id) ? n.delete(t.id) : n.add(t.id); return n; })}>
              {isOpen ? <CaretDown size={13} className="text-slate-500"/> : <CaretRight size={13} className="text-slate-500"/>}
              <span className="font-mono text-[10px] text-slate-500 w-4">{STRIDE_SHORT[t.stride]}</span>
              <span className={`text-[12.5px] flex-1 ${t.status !== "open" ? "text-slate-500 line-through" : "text-slate-200"}`}>{t.title}</span>
              {t.source === "auto" && <Chip color="blue">auto</Chip>}
              {t.dread_score != null && <span className="text-[10.5px] text-purple-300 font-mono">DREAD {t.dread_score}</span>}
              <Chip color={RISK_COLOR[t.band] || "slate"}>{t.band}</Chip>
              <Chip color={t.status === "open" ? "amber" : t.status === "mitigated" ? "emerald" : "slate"}>{t.status}</Chip>
            </div>
            {isOpen && (
              <div className="border-t border-[#30363D] px-4 py-3 space-y-3">
                <div className="text-[12px] text-slate-300">{t.description || "No description."}</div>
                <div className="text-[10.5px] text-slate-500">On: {elName(t.element_id)} · {t.stride}</div>
                {t.linked_finding_ids?.length > 0 && (
                  <div className="text-[11px]">
                    <Link to={`/findings?q=${encodeURIComponent(elName(t.element_id))}`} className="text-blue-300 hover:underline">
                      {t.linked_finding_ids.length} linked finding(s) →
                    </Link>
                  </div>
                )}
                {/* DREAD sliders */}
                <div>
                  <div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">DREAD (1–10 each)</div>
                  <div className="grid sm:grid-cols-5 gap-2">
                    {DREAD_KEYS.map(([k, label]) => (
                      <div key={k}>
                        <div className="text-[10px] text-slate-500">{label}</div>
                        <input type="range" min={1} max={10} value={t.dread?.[k] ?? 5}
                          onChange={e => patch(t, { dread: { [k]: parseInt(e.target.value, 10) } })}
                          className="w-full"/>
                        <div className="text-[10.5px] text-slate-400 text-center">{t.dread?.[k] ?? "—"}</div>
                      </div>
                    ))}
                  </div>
                  {t.dread_suggestion && (
                    <div className="text-[11px] text-purple-300 mt-1 flex items-center gap-2">
                      <Sparkle size={11}/> DREAD suggests likelihood {t.dread_suggestion.likelihood} × impact {t.dread_suggestion.impact} ({t.dread_suggestion.band})
                      <button onClick={() => patch(t, { likelihood: t.dread_suggestion.likelihood, impact: t.dread_suggestion.impact })}
                        className="h-6 px-2 text-[10.5px] border border-purple-500/40 rounded">Apply</button>
                    </div>
                  )}
                </div>
                {/* 5x5 */}
                <div className="flex items-center gap-4 flex-wrap">
                  <div>
                    <div className="text-[10px] text-slate-500 mb-0.5">Likelihood</div>
                    <div className="flex gap-1">{[1, 2, 3, 4, 5].map(n => (
                      <button key={n} onClick={() => patch(t, { likelihood: n })}
                        className={`h-7 w-7 text-[11.5px] rounded border ${t.likelihood === n ? "bg-blue-500/20 border-blue-500/50 text-blue-300" : "border-[#30363D] text-slate-400"}`}>{n}</button>
                    ))}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-slate-500 mb-0.5">Impact</div>
                    <div className="flex gap-1">{[1, 2, 3, 4, 5].map(n => (
                      <button key={n} onClick={() => patch(t, { impact: n })}
                        className={`h-7 w-7 text-[11.5px] rounded border ${t.impact === n ? "bg-purple-500/20 border-purple-500/50 text-purple-300" : "border-[#30363D] text-slate-400"}`}>{n}</button>
                    ))}</div>
                  </div>
                  <div className="flex gap-1.5 ml-auto">
                    {["open", "mitigated", "accepted"].map(s => (
                      <button key={s} onClick={() => patch(t, { status: s })}
                        className={`h-7 px-2.5 text-[11px] rounded border capitalize ${t.status === s ? "bg-blue-500/15 border-blue-500/40 text-blue-300" : "border-[#30363D] text-slate-400"}`}>{s}</button>
                    ))}
                    <button onClick={() => remove(t)} className="h-7 px-2 text-[11px] border border-[#30363D] text-slate-500 hover:text-red-400 rounded"><Trash size={12}/></button>
                  </div>
                </div>
                <Mitigations modelId={modelId} threat={t} onChange={onChange}/>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function Mitigations({ modelId, threat, onChange }) {
  const [text, setText] = useState("");
  const add = async () => {
    if (!text.trim()) return;
    await api.post(`/v1/threat-models/${modelId}/threats/${threat.id}/mitigations`, { description: text });
    setText(""); onChange();
  };
  const setStatus = async (mit, status) => {
    await api.patch(`/v1/threat-models/${modelId}/threats/${threat.id}/mitigations/${mit.id}`, { status });
    onChange();
  };
  return (
    <div>
      <div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1.5 flex items-center gap-1">
        <ShieldCheck size={11}/> Mitigations ({(threat.mitigations || []).length})
      </div>
      {(threat.mitigations || []).map(m => (
        <div key={m.id} className="flex items-center gap-2 py-1 text-[11.5px]">
          <span className={`flex-1 ${m.status === "done" ? "text-slate-500 line-through" : "text-slate-300"}`}>{m.description}</span>
          {["planned", "in_progress", "done"].map(s => (
            <button key={s} onClick={() => setStatus(m, s)}
              className={`h-6 px-1.5 text-[10px] rounded border capitalize ${m.status === s ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-300" : "border-[#30363D] text-slate-500"}`}>
              {s.replace("_", " ")}
            </button>
          ))}
        </div>
      ))}
      <div className="flex gap-2 mt-1">
        <input value={text} onChange={e => setText(e.target.value)} onKeyDown={e => e.key === "Enter" && add()}
          placeholder="Add a mitigation…" className="flex-1 h-7 px-2 bg-[#161B22] border border-[#30363D] rounded text-[11.5px] text-slate-200"/>
        <button onClick={add} className="h-7 px-2.5 text-[11px] border border-[#30363D] rounded text-slate-300">Add</button>
      </div>
    </div>
  );
}

/* ------------------------------ Attack tree ------------------------------ */

function AttackTree({ modelId, threats, elements, onChange }) {
  const [addingChild, setAddingChild] = useState(null); // parent threat id
  const [childForm, setChildForm] = useState({ title: "", stride: "Elevation of Privilege" });
  const roots = threats.filter(t => !t.parent_threat_id);
  const childrenOf = (id) => threats.filter(t => t.parent_threat_id === id);

  const addChild = async (parent) => {
    if (!childForm.title.trim()) { toast.error("Title required"); return; }
    try {
      await api.post(`/v1/threat-models/${modelId}/threats`, {
        element_id: parent.element_id, stride: childForm.stride, title: childForm.title,
        parent_threat_id: parent.id,
      });
      setAddingChild(null); setChildForm({ title: "", stride: "Elevation of Privilege" });
      onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed"); }
  };

  const Node = ({ t, depth }) => (
    <div style={{ marginLeft: depth * 22 }} className="py-1">
      <div className="flex items-center gap-2">
        <TreeStructure size={12} className="text-slate-600 shrink-0"/>
        <span className={`text-[12.5px] ${t.status !== "open" ? "text-slate-500 line-through" : "text-slate-200"}`}>{t.title}</span>
        <span className="font-mono text-[10px] text-slate-500">{STRIDE_SHORT[t.stride]}</span>
        <Chip color={RISK_COLOR[t.band] || "slate"}>{t.band}</Chip>
        <button onClick={() => setAddingChild(addingChild === t.id ? null : t.id)}
          className="h-6 px-1.5 text-[10px] border border-[#30363D] text-slate-400 rounded hover:border-blue-500/40 hover:text-blue-300">+ sub-goal</button>
      </div>
      {addingChild === t.id && (
        <div className="flex gap-2 mt-1.5 ml-5">
          <input value={childForm.title} onChange={e => setChildForm({ ...childForm, title: e.target.value })}
            placeholder="Attacker sub-goal / step…" className="flex-1 h-7 px-2 bg-[#161B22] border border-[#30363D] rounded text-[11.5px] text-slate-200"/>
          <button onClick={() => addChild(t)} className="h-7 px-2.5 text-[11px] bg-blue-500 text-white rounded">Add</button>
        </div>
      )}
      {childrenOf(t.id).map(c => <Node key={c.id} t={c} depth={depth + 1}/>)}
    </div>
  );

  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
      <div className="text-[11px] text-slate-500 mb-3">
        Each root is a threat goal; children are the sub-goals/steps an attacker chains to reach it. Add depth where the path matters.
      </div>
      {roots.length === 0 ? <div className="text-[12.5px] text-slate-500">No threats yet.</div>
        : roots.map(t => <Node key={t.id} t={t} depth={0}/>)}
    </div>
  );
}

/* ------------------------------ 5x5 matrix ------------------------------ */

function MatrixPanel({ threats }) {
  const open = threats.filter(t => t.status === "open");
  const cellBand = (l, i) => {
    const s = l * i;
    if (s <= 4) return "bg-blue-500/10";
    if (s <= 9) return "bg-amber-500/10";
    if (s <= 16) return "bg-orange-500/15";
    return "bg-red-500/20";
  };
  return (
    <div className="max-w-xl border border-[#30363D] bg-[#0D1117] rounded-md p-5">
      <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-3">Open threats — Impact → / Likelihood ↑</div>
      <div className="grid grid-cols-6 gap-1 text-[11px]">
        {[5, 4, 3, 2, 1].map(l => ([
          <div key={`l${l}`} className="flex items-center justify-center text-slate-500 h-14">{l}</div>,
          ...[1, 2, 3, 4, 5].map(i => {
            const here = open.filter(t => t.likelihood === l && t.impact === i);
            return (
              <div key={`${l}-${i}`} className={`h-14 rounded border border-[#30363D]/60 flex items-center justify-center ${cellBand(l, i)}`}
                title={here.map(t => t.title).join("\n")}>
                {here.length > 0 && <span className="text-[15px] font-semibold text-slate-100">{here.length}</span>}
              </div>
            );
          })]))}
        <div/>
        {[1, 2, 3, 4, 5].map(i => <div key={`i${i}`} className="text-center text-slate-500">{i}</div>)}
      </div>
      <div className="flex gap-3 mt-3 text-[11px] text-slate-500">
        {["Low", "Medium", "High", "Critical"].map(b => {
          const n = open.filter(t => t.band === b).length;
          return <span key={b}><Chip color={RISK_COLOR[b]}>{b}</Chip> {n}</span>;
        })}
      </div>
    </div>
  );
}
