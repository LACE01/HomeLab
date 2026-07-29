import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  Path, ArrowsClockwise, CaretDown, CaretRight, Globe, Desktop,
  Database, Table as TableIcon, Lightning, Target,
} from "@phosphor-icons/react";

const SEV_COLOR = { Critical: "red", High: "orange", Medium: "amber", Low: "blue" };
const CONF_COLOR = { confirmed: "red", likely: "amber", possible: "slate" };
const STATUS_COLOR = {
  open: "red", investigating: "amber", mitigating: "blue", accepted: "slate", resolved: "emerald",
};
const ACTION_META = {
  patch: { label: "Patch", color: "red" },
  network: { label: "Close exposure", color: "orange" },
  segmentation: { label: "Segment", color: "blue" },
  identity: { label: "Identity", color: "purple" },
};
const EDGE_LABEL = {
  exposed_service: "exposed to internet",
  exploitable: "exploitable via",
  lateral_service: "can reach",
  credential_reuse: "shared credentials",
  same_segment: "same segment",
};

export default function AttackPaths() {
  const [summary, setSummary] = useState(null);
  const [view, setView] = useState("paths");   // paths | chokepoints | graph | crown
  const [running, setRunning] = useState(false);

  const load = () => api.get("/v1/attack-paths/summary").then(r => setSummary(r.data)).catch(() => {});
  useEffect(() => { load(); }, []);

  const analyze = async () => {
    setRunning(true);
    try {
      const r = await api.post("/v1/attack-paths/analyze", { max_hops: 4 });
      const s = r.data.summary;
      toast.success(`${s.paths_found} path(s) found across ${s.assets_scanned} asset(s)`);
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Analysis failed"); }
    finally { setRunning(false); }
  };

  return (
    <Layout title="Attack Path Analysis"
      subtitle="Every route an attacker could take from the internet to something that matters — and the single fixes that break the most of them"
      actions={
        <button onClick={analyze} disabled={running}
          className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded inline-flex items-center gap-1.5">
          <ArrowsClockwise size={13} className={running ? "animate-spin" : ""}/>
          {running ? "Analyzing…" : "Run analysis"}
        </button>
      }>

      {summary?.needs_crown_jewels && (
        <div className="border border-amber-500/30 bg-amber-500/5 rounded-md px-3.5 py-3 mb-4 text-[12.5px] text-amber-100">
          <div className="font-medium mb-1">No crown jewels defined yet.</div>
          An attack path is only meaningful if it ends somewhere valuable. Mark the assets that actually matter —
          domain controllers, databases holding PII/CJIS/PHI, finance systems — and the analysis will find the routes
          to them. Until then it deliberately returns nothing rather than inventing a target.
          <button onClick={() => setView("crown")}
            className="ml-2 underline hover:text-amber-50">Define crown jewels →</button>
        </div>
      )}

      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 mb-4">
          <Stat label="Open paths" value={summary.open_paths} tone={summary.open_paths ? "red" : "emerald"}/>
          <Stat label="Critical" value={summary.critical_paths} tone={summary.critical_paths ? "red" : null}/>
          <Stat label="Using exploited CVEs" value={summary.kev_paths} tone={summary.kev_paths ? "red" : null}/>
          <Stat label="Confirmed (not speculative)" value={summary.confirmed_paths}/>
          <Stat label="Crown jewels reachable" value={summary.crown_jewels_reachable}
            tone={summary.crown_jewels_reachable ? "amber" : null}/>
          <Stat label="Entry points" value={summary.entry_points}/>
        </div>
      )}

      <div className="flex items-center gap-1 border-b border-[#30363D] mb-4 overflow-x-auto">
        {[["paths", "Attack Paths", TableIcon], ["chokepoints", "Fix This First", Lightning],
          ["graph", "Full Graph", Path], ["crown", "Crown Jewels", Target]].map(([id, label, Icon]) => (
          <button key={id} onClick={() => setView(id)}
            className={`h-9 px-3 text-[12.5px] inline-flex items-center gap-1.5 border-b-2 -mb-px whitespace-nowrap ${
              view === id ? "border-blue-500 text-blue-300" : "border-transparent text-slate-400 hover:text-slate-200"}`}>
            <Icon size={14}/> {label}
          </button>
        ))}
      </div>

      {view === "paths" && <PathList onChange={load}/>}
      {view === "chokepoints" && <ChokePoints/>}
      {view === "graph" && <FullGraph/>}
      {view === "crown" && <CrownJewels onChange={load}/>}

      {summary?.last_run && (
        <div className="text-[10.5px] text-slate-600 mt-4 font-mono">
          Last analysis {new Date(summary.last_run.generated_at).toLocaleString()} ·
          {" "}{summary.last_run.assets_scanned} assets · {summary.last_run.findings_considered} open findings considered
          {summary.last_run.resolved_since_last_run > 0 &&
            ` · ${summary.last_run.resolved_since_last_run} path(s) resolved since the previous run`}
        </div>
      )}
    </Layout>
  );
}

function Stat({ label, value, tone }) {
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-3.5 py-3">
      <div className="text-[10.5px] text-slate-500 uppercase tracking-wider">{label}</div>
      <div className={`text-[20px] font-semibold mt-0.5 ${
        tone === "red" ? "text-red-300" : tone === "amber" ? "text-amber-300"
        : tone === "emerald" ? "text-emerald-300" : "text-slate-100"}`}>{value ?? 0}</div>
    </div>
  );
}

function NodeIcon({ node, size = 14 }) {
  if (node.type === "internet") return <Globe size={size} className="text-blue-300"/>;
  if (node.crown_jewel) return <Target size={size} className="text-red-300"/>;
  if (node.type === "datastore") return <Database size={size} className="text-purple-300"/>;
  return <Desktop size={size} className="text-slate-300"/>;
}

/* ------------------------------ Path list ------------------------------ */

function PathList({ onChange }) {
  const [items, setItems] = useState([]);
  const [expanded, setExpanded] = useState(new Set());
  const [filter, setFilter] = useState("all");
  const [detail, setDetail] = useState({});

  const load = () => {
    const params = {};
    if (filter === "kev") params.kev_only = true;
    if (filter === "confirmed") params.confirmed_only = true;
    if (filter === "critical") params.severity = "Critical";
    api.get("/v1/attack-paths", { params }).then(r => setItems(r.data.items || []));
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [filter]);

  const toggle = async (p) => {
    const n = new Set(expanded);
    if (n.has(p.id)) { n.delete(p.id); setExpanded(n); return; }
    n.add(p.id); setExpanded(n);
    if (!detail[p.id]) {
      const r = await api.get(`/v1/attack-paths/${p.id}`);
      setDetail(d => ({ ...d, [p.id]: r.data }));
    }
  };

  const setStatus = async (p, status) => {
    await api.patch(`/v1/attack-paths/${p.id}`, { status });
    toast.success(`Marked ${status}`);
    load(); onChange();
  };

  return (
    <div className="space-y-2.5">
      <div className="flex items-center gap-1.5 flex-wrap">
        {[["all", "All"], ["critical", "Critical only"], ["kev", "Uses exploited CVEs"],
          ["confirmed", "Confirmed only"]].map(([id, label]) => (
          <button key={id} onClick={() => setFilter(id)}
            className={`h-7 px-2.5 text-[11.5px] rounded border ${filter === id
              ? "bg-blue-500/15 border-blue-500/40 text-blue-300" : "border-[#30363D] text-slate-400 hover:border-slate-500"}`}>
            {label}
          </button>
        ))}
      </div>

      {items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No attack paths. Either nothing reaches a crown jewel, or the analysis hasn&apos;t run yet.
        </div>
      ) : items.map(p => {
        const isOpen = expanded.has(p.id);
        const d = detail[p.id];
        return (
          <div key={p.id} className="border border-[#30363D] bg-[#0D1117] rounded-md">
            <div className="px-4 py-3 cursor-pointer" onClick={() => toggle(p)}>
              <div className="flex items-center gap-2 flex-wrap">
                {isOpen ? <CaretDown size={12} className="text-slate-500"/> : <CaretRight size={12} className="text-slate-500"/>}
                <Chip color={SEV_COLOR[p.severity]}>{p.severity}</Chip>
                <span className="text-[12.5px] text-slate-200">{p.risk_score}</span>
                <Chip color={CONF_COLOR[p.confidence]}>{p.confidence}</Chip>
                {p.uses_kev && <Chip color="red">actively exploited</Chip>}
                {p.entry_vector === "unproven" && <Chip color="slate">entry unproven</Chip>}
                <Chip color={STATUS_COLOR[p.status] || "slate"}>{p.status}</Chip>
                <span className="ml-auto text-[11px] text-slate-500">{p.hops} hop(s)</span>
              </div>
              {/* the chain, rendered inline the way you'd sketch it on a whiteboard */}
              <div className="flex items-center gap-1.5 mt-2 flex-wrap">
                {p.nodes.map((n, i) => (
                  <span key={`${n.id}-${i}`} className="inline-flex items-center gap-1.5">
                    {i > 0 && (
                      <span className="text-[10px] text-slate-600 font-mono">
                        —{EDGE_LABEL[p.edges[i - 1]?.kind] || ""}→
                      </span>
                    )}
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[11.5px] ${
                      n.crown_jewel ? "border-red-500/40 bg-red-500/10 text-red-200"
                      : n.type === "internet" ? "border-blue-500/40 bg-blue-500/10 text-blue-200"
                      : "border-[#30363D] bg-[#161B22] text-slate-300"}`}>
                      <NodeIcon node={n} size={11}/> {n.label}
                    </span>
                  </span>
                ))}
              </div>
              <div className="text-[11.5px] text-slate-400 mt-2">{p.narrative}</div>
            </div>

            {isOpen && (
              <div className="border-t border-[#30363D] px-4 py-3 space-y-3">
                <div>
                  <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1">Evidence for each hop</div>
                  <div className="space-y-1">
                    {p.edges.map((e, i) => (
                      <div key={e.id || i} className="text-[11.5px] flex items-start gap-2">
                        <Chip color={CONF_COLOR[e.confidence]}>{e.confidence}</Chip>
                        <span className="text-slate-300">{e.evidence}</span>
                        {e.technique && <span className="text-slate-600 font-mono text-[10px] ml-auto shrink-0">{e.technique}</span>}
                      </div>
                    ))}
                  </div>
                </div>

                {p.risk_factors?.length > 0 && (
                  <div className="flex gap-1.5 flex-wrap">
                    {p.risk_factors.map((rf, i) => <Chip key={i} color="amber">{rf}</Chip>)}
                  </div>
                )}

                {d?.findings?.length > 0 && (
                  <div>
                    <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1">Underlying findings</div>
                    {d.findings.map(f => (
                      <div key={f.id} className="text-[11.5px] flex items-center gap-2 py-0.5">
                        <Chip color={SEV_COLOR[f.severity]}>{f.severity}</Chip>
                        <Link to={`/findings/${f.id}`} className="text-blue-300 hover:underline">
                          {f.cve || f.title}
                        </Link>
                        <span className="text-slate-500">{f.asset_hostname}</span>
                        {f.kev_flag && <Chip color="red">KEV</Chip>}
                      </div>
                    ))}
                  </div>
                )}

                {d?.remediation_options?.length > 0 && (
                  <div>
                    <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1">
                      Break this path
                    </div>
                    {d.remediation_options.map(o => (
                      <div key={o.id} className="text-[11.5px] flex items-start gap-2 py-1">
                        <Chip color={ACTION_META[o.action_type]?.color || "slate"}>
                          {ACTION_META[o.action_type]?.label || o.action_type}
                        </Chip>
                        <span className="text-slate-200">{o.title}</span>
                        <span className="ml-auto text-slate-500 shrink-0">
                          breaks {o.paths_broken} path(s)
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                <div className="flex gap-1.5 flex-wrap">
                  {["open", "investigating", "mitigating", "accepted"].map(s => (
                    <button key={s} onClick={() => setStatus(p, s)}
                      className={`h-7 px-2.5 text-[11px] rounded border capitalize ${p.status === s
                        ? "bg-blue-500/15 border-blue-500/40 text-blue-300" : "border-[#30363D] text-slate-400"}`}>
                      {s}
                    </button>
                  ))}
                </div>
                {p.analyst_note && <div className="text-[11px] text-slate-500">Note: {p.analyst_note}</div>}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* --------------------------- Choke points --------------------------- */

function ChokePoints() {
  const [data, setData] = useState(null);
  useEffect(() => { api.get("/v1/attack-paths/choke-points").then(r => setData(r.data)); }, []);
  if (!data) return <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>;
  if (!data.items.length) {
    return <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
      Nothing to rank — no open attack paths.
    </div>;
  }
  const max = data.items[0].paths_broken || 1;
  return (
    <div className="space-y-2">
      <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3.5 py-2.5 text-[12px] text-blue-200">
        If you only did one thing, do the top item. Each remediation is ranked by how many of your
        {" "}{data.total_paths} open attack path(s) it would eliminate — not by CVSS.
      </div>
      {data.items.map((c, i) => (
        <div key={c.id} className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[13px] font-mono text-slate-500 w-5">{i + 1}</span>
            <Chip color={ACTION_META[c.action_type]?.color || "slate"}>
              {ACTION_META[c.action_type]?.label || c.action_type}
            </Chip>
            <span className="text-[12.5px] text-slate-100">{c.title}</span>
            <span className="ml-auto text-[12px] text-slate-200 shrink-0">
              breaks <span className="text-emerald-300 font-semibold">{c.paths_broken}</span> of {data.total_paths}
              {" "}<span className="text-slate-500">({c.paths_broken_pct}%)</span>
            </span>
          </div>
          <div className="mt-1.5 h-1.5 bg-slate-800 rounded overflow-hidden">
            <div className="h-full bg-emerald-500" style={{ width: `${(c.paths_broken / max) * 100}%` }}/>
          </div>
          {c.detail && <div className="text-[11px] text-slate-500 mt-1.5">{c.detail}</div>}
        </div>
      ))}
    </div>
  );
}

/* ------------------------------ Full graph ------------------------------ */

function FullGraph() {
  const [g, setG] = useState(null);
  const [onlyPaths, setOnlyPaths] = useState(true);
  useEffect(() => { api.get("/v1/attack-paths/graph").then(r => setG(r.data)); }, []);
  if (!g) return <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>;

  const nodes = onlyPaths ? g.nodes.filter(n => n.on_attack_path) : g.nodes;
  const keep = new Set(nodes.map(n => n.id));
  const edges = g.edges.filter(e => keep.has(e.from) && keep.has(e.to) && (!onlyPaths || e.on_attack_path));

  // simple layered layout: internet, then entry hosts, then the rest, crown last
  const layers = [
    nodes.filter(n => n.type === "internet"),
    nodes.filter(n => n.type !== "internet" && n.internet_facing),
    nodes.filter(n => n.type !== "internet" && !n.internet_facing && !n.crown_jewel),
    nodes.filter(n => n.crown_jewel),
  ];
  const pos = {};
  const W = 900, colGap = W / (layers.length + 1);
  layers.forEach((layer, li) => {
    layer.forEach((n, i) => {
      pos[n.id] = { x: colGap * (li + 1), y: 60 + i * 62 };
    });
  });
  const height = Math.max(340, ...Object.values(pos).map(p => p.y + 70));

  return (
    <div className="space-y-3">
      <label className="text-[12px] text-slate-400 inline-flex items-center gap-1.5">
        <input type="checkbox" checked={onlyPaths} onChange={e => setOnlyPaths(e.target.checked)}/>
        Only show nodes and edges that are part of an attack path
      </label>
      <div className="text-[11px] text-slate-500">
        {nodes.length} of {g.total_nodes} node(s), {edges.length} of {g.total_edges} edge(s)
        {g.truncated && " · view truncated to keep it legible"}
      </div>
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-x-auto">
        <svg viewBox={`0 0 ${W} ${height}`} className="w-full" style={{ minHeight: 340 }}>
          <defs>
            <marker id="ap-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#8B949E"/>
            </marker>
          </defs>
          {edges.map((e, i) => {
            const a = pos[e.from], b = pos[e.to];
            if (!a || !b) return null;
            const dashed = e.confidence !== "confirmed";
            const color = e.on_attack_path ? "#f97316" : "#30363D";
            return (
              <g key={e.id || i}>
                <line x1={a.x + 60} y1={a.y} x2={b.x - 60} y2={b.y}
                  stroke={color} strokeWidth={e.on_attack_path ? 1.8 : 1}
                  strokeDasharray={dashed ? "5 4" : undefined} markerEnd="url(#ap-arrow)"/>
              </g>
            );
          })}
          {nodes.map(n => {
            const p = pos[n.id];
            if (!p) return null;
            const stroke = n.crown_jewel ? "#ef4444" : n.type === "internet" ? "#3b82f6"
              : n.on_attack_path ? "#f97316" : "#30363D";
            return (
              <g key={n.id}>
                <rect x={p.x - 62} y={p.y - 17} width={124} height={34} rx={6}
                  fill="#161B22" stroke={stroke} strokeWidth={n.on_attack_path ? 1.8 : 1}/>
                <text x={p.x} y={p.y - 2} fill="#E6EDF3" fontSize="9.5" textAnchor="middle">
                  {(n.label || "").length > 18 ? n.label.slice(0, 17) + "…" : n.label}
                </text>
                <text x={p.x} y={p.y + 10} fill="#8B949E" fontSize="8" textAnchor="middle">
                  {n.crown_jewel ? "crown jewel" : n.type === "internet" ? "untrusted"
                    : `${n.critical_high || 0} crit/high`}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
      <div className="flex gap-4 text-[10.5px] text-slate-500 flex-wrap">
        <span><span className="inline-block w-4 border-t-2 border-orange-500 align-middle mr-1"/> on an attack path</span>
        <span><span className="inline-block w-4 border-t-2 border-dashed border-slate-500 align-middle mr-1"/> unconfirmed reachability</span>
        <span><span className="inline-block h-2.5 w-2.5 border border-red-500 align-middle mr-1"/> crown jewel</span>
      </div>
    </div>
  );
}

/* ------------------------------ Crown jewels ------------------------------ */

function CrownJewels({ onChange }) {
  const [items, setItems] = useState([]);
  const [picker, setPicker] = useState(null);
  const [mode, setMode] = useState("individual");
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(new Set());
  const [teams, setTeams] = useState(new Set());
  const [tags, setTags] = useState(new Set());
  const [reason, setReason] = useState("");

  const load = () => api.get("/v1/attack-paths/crown-jewels").then(r => setItems(r.data.items || []));
  const loadPicker = (search) => api.get("/v1/security-reviews/asset-picker",
    { params: search ? { q: search } : {} }).then(r => setPicker(r.data)).catch(() => {});
  useEffect(() => { load(); loadPicker(); }, []);

  const toggle = (set, setter, v) => {
    const n = new Set(set); n.has(v) ? n.delete(v) : n.add(v); setter(n);
  };

  const save = async () => {
    const body = {
      asset_ids: mode === "individual" ? Array.from(sel) : [],
      teams: mode === "team" ? Array.from(teams) : [],
      tags: mode === "tag" ? Array.from(tags) : [],
      reason,
    };
    try {
      const r = await api.post("/v1/attack-paths/crown-jewels", body);
      toast.success(`${r.data.updated} asset(s) marked as crown jewels — re-run the analysis to see the paths to them`);
      setSel(new Set()); setTeams(new Set()); setTags(new Set()); setReason("");
      load(); onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed"); }
  };

  const unset = async (a) => {
    await api.post("/v1/attack-paths/crown-jewels", { asset_ids: [a.id], unset: true });
    load(); onChange();
  };

  return (
    <div className="space-y-3">
      <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3.5 py-2.5 text-[12px] text-blue-200">
        Crown jewels are what the analysis aims at — the assets whose compromise would actually hurt. Anything tagged
        {" "}<span className="font-mono">crown_jewel</span>, carrying a sensitive-data tag (PII, PHI, PCI, CJIS,
        elections), or rated business-critical counts automatically.
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 space-y-3">
        <div className="inline-flex rounded border border-[#30363D] overflow-hidden">
          {[["individual", "Individual"], ["team", "By team"], ["tag", "By tag"]].map(([m, label], i) => (
            <button key={m} onClick={() => setMode(m)}
              className={`h-7 px-3 text-[11.5px] ${i > 0 ? "border-l border-[#30363D]" : ""} ${
                mode === m ? "bg-blue-500/15 text-blue-300" : "text-slate-400 hover:text-slate-200"}`}>{label}</button>
          ))}
        </div>
        {mode === "individual" && picker && (
          <>
            <input value={q} onChange={e => { setQ(e.target.value); loadPicker(e.target.value); }}
              placeholder="Search hostname or IP…"
              className="w-full h-8 px-3 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/>
            <div className="max-h-56 overflow-y-auto border border-[#30363D] rounded divide-y divide-[#30363D]">
              {picker.items.map(a => (
                <label key={a.id} className="flex items-center gap-2 px-3 py-1.5 text-[12px] cursor-pointer hover:bg-slate-800/30">
                  <input type="checkbox" checked={sel.has(a.id)} onChange={() => toggle(sel, setSel, a.id)}/>
                  <span className="font-mono text-slate-200">{a.hostname}</span>
                  <span className="text-slate-500">{a.ip}</span>
                  {a.owner_team && <Chip color="slate">{a.owner_team}</Chip>}
                </label>
              ))}
            </div>
          </>
        )}
        {mode === "team" && picker && (
          <div className="flex gap-1.5 flex-wrap">
            {picker.teams.map(t => (
              <button key={t} onClick={() => toggle(teams, setTeams, t)}
                className={`h-7 px-2.5 text-[11.5px] rounded border ${teams.has(t)
                  ? "bg-blue-500/15 border-blue-500/40 text-blue-300" : "border-[#30363D] text-slate-400"}`}>{t}</button>
            ))}
          </div>
        )}
        {mode === "tag" && picker && (
          <div className="flex gap-1.5 flex-wrap">
            {picker.tags.map(t => (
              <button key={t} onClick={() => toggle(tags, setTags, t)}
                className={`h-7 px-2.5 text-[11.5px] rounded border ${tags.has(t)
                  ? "bg-blue-500/15 border-blue-500/40 text-blue-300" : "border-[#30363D] text-slate-400"}`}>{t}</button>
            ))}
          </div>
        )}
        <input value={reason} onChange={e => setReason(e.target.value)}
          placeholder="Why does this matter? (e.g. holds resident PII)"
          className="w-full h-8 px-3 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200"/>
        <button onClick={save}
          className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">Mark as crown jewels</button>
      </div>

      {items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-8 text-center text-[12.5px] text-slate-500">
          None defined yet.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
          {items.map(a => (
            <div key={a.id} className="px-4 py-2.5 flex items-center gap-3 text-[12.5px]">
              <Target size={13} className="text-red-300 shrink-0"/>
              <Link to={`/assets/${a.id}`} className="text-blue-300 hover:underline font-mono">{a.hostname}</Link>
              <span className="text-slate-500">{a.reason}</span>
              {a.owner_team && <Chip color="slate">{a.owner_team}</Chip>}
              {a.criticality === "crown_jewel" && (
                <button onClick={() => unset(a)} className="ml-auto text-[11px] text-slate-500 hover:text-slate-300">
                  Unmark
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
