import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  Play, Clock, Plus, Trash, CheckCircle, XCircle, CircleNotch, Info,
  MagnifyingGlass, Eye, GearSix, ArrowSquareOut,
} from "@phosphor-icons/react";

const CATEGORY_META = {
  recon: { label: "Recon / Discovery", color: "blue", desc: "Passive subdomain/host/contact discovery — feeds the EASM candidate queue" },
  "threat-intel": { label: "Threat Intel", color: "red", desc: "Breach/paste/credential exposure monitoring — notifies on real hits, sourced from HIBP and your own OpenCTI instance" },
};

const TARGET_TYPE_META = {
  domain: { label: "Domain", placeholder: "company.com" },
  ip: { label: "IP Address", placeholder: "203.0.113.10" },
  email: { label: "Email", placeholder: "user@company.com" },
};

export default function ReconOSINT() {
  const [tab, setTab] = useState("run");

  return (
    <Layout title="Recon & OSINT" subtitle="recon-ng modules — passive recon discovery and breach/exposure monitoring">
      <div className="border border-orange-500/30 bg-orange-500/5 rounded-md px-3 py-2.5 mb-4 text-[12px] text-orange-200 leading-relaxed flex items-start gap-2 max-w-3xl">
        <Info size={16} className="shrink-0 mt-0.5"/>
        <div>
          These modules reach out to third-party OSINT services (HackerTarget, Bing, HaveIBeenPwned, etc.) on
          your behalf. Only run them against domains/emails you're authorized to investigate. recon-ng's exact
          module set can drift by version — if a module errors, it may need <code className="text-orange-100">marketplace install</code> run
          once inside the container.
        </div>
      </div>

      <div className="flex gap-1 mb-4 border-b border-[#30363D]">
        {[{ key: "run", label: "Run a module" }, { key: "schedules", label: "Schedules" },
          { key: "history", label: "Run history" }, { key: "findings", label: "OSINT Findings" },
          { key: "keys", label: "API Keys" }].map(t => (
          <button key={t.key} onClick={() => setTab(t.key)}
            className={`px-3 py-2 text-[12.5px] border-b-2 -mb-px ${tab === t.key ? "border-blue-500 text-blue-300" : "border-transparent text-slate-500 hover:text-slate-300"}`}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "run" && <RunModule/>}
      {tab === "schedules" && <Schedules/>}
      {tab === "history" && <RunHistory/>}
      {tab === "findings" && <OsintFindings/>}
      {tab === "keys" && <ApiKeys/>}
    </Layout>
  );
}

function useModules() {
  const [modules, setModules] = useState([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    api.get("/v1/recon/modules").then(r => setModules(r.data.items || [])).finally(() => setLoading(false));
  }, []);
  return { modules, loading };
}

function ModuleCard({ m, selected, onToggle }) {
  const meta = CATEGORY_META[m.category] || CATEGORY_META.recon;
  return (
    <button onClick={() => onToggle(m)} disabled={!m.ready}
      className={`text-left border rounded-md p-3 transition-colors ${selected ? "border-blue-500/60 bg-blue-500/5" : "border-[#30363D] hover:border-[#484F58]"} ${!m.ready ? "opacity-50 cursor-not-allowed" : ""}`}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-[12.5px] text-slate-100 font-medium flex items-center gap-1.5">
          <input type="checkbox" checked={!!selected} readOnly disabled={!m.ready} className="pointer-events-none"/>
          {m.label}
        </span>
        <Chip color={meta.color}>{meta.label}</Chip>
      </div>
      <div className="text-[11px] text-slate-500 mt-1.5 leading-relaxed">{m.description}</div>
      {!m.ready && (
        <div className="text-[10.5px] text-amber-400 mt-1.5">Needs: {m.missing_keys.join(", ")} — set under API Keys tab</div>
      )}
    </button>
  );
}

function RunModule() {
  const { modules, loading } = useModules();
  const [targetType, setTargetType] = useState("domain");
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [target, setTarget] = useState("");
  const [running, setRunning] = useState(false);
  const [lastRun, setLastRun] = useState(null);

  const byId = Object.fromEntries(modules.map(m => [m.id, m]));
  const availableTypes = [...new Set(modules.map(m => m.target_type))];

  const toggleModule = (m) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(m.id)) next.delete(m.id); else next.add(m.id);
      return next;
    });
  };

  const changeType = (t) => { setTargetType(t); setSelectedIds(new Set()); setTarget(""); };

  const run = async () => {
    if (selectedIds.size === 0) { toast.error("Pick at least one module"); return; }
    if (!target.trim()) { toast.error(`Enter a target ${TARGET_TYPE_META[targetType]?.label.toLowerCase()}`); return; }
    setRunning(true);
    setLastRun(null);
    try {
      const r = await api.post("/v1/recon/run", { module_ids: [...selectedIds], target: target.trim() });
      toast.success(`Run started (${selectedIds.size} module${selectedIds.size > 1 ? "s" : ""}) — this can take a minute or two`);
      let done = false;
      for (let i = 0; i < 90 && !done; i++) {
        await new Promise(res => setTimeout(res, 3000));
        const detail = await api.get(`/v1/recon/runs/${r.data.id}`);
        setLastRun(detail.data);  // show partial progress as each module finishes
        if (detail.data.status !== "running") {
          done = true;
          if (detail.data.status === "success") toast.success("Run complete");
          else if (detail.data.status === "partial") toast.error("Some modules failed — see results below");
          else toast.error("Run failed");
        }
      }
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to start run");
    } finally { setRunning(false); }
  };

  if (loading) return <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading modules…</div>;

  const filtered = modules.filter(m => m.target_type === targetType);
  const grouped = { recon: filtered.filter(m => m.category === "recon"), "threat-intel": filtered.filter(m => m.category === "threat-intel") };

  return (
    <div className="space-y-5">
      <div className="flex gap-1.5">
        {availableTypes.map(t => (
          <button key={t} onClick={() => changeType(t)}
            className={`h-8 px-3 text-[12px] rounded border ${targetType === t ? "border-blue-500/60 bg-blue-500/10 text-blue-300" : "border-[#30363D] text-slate-400 hover:text-slate-200"}`}>
            {TARGET_TYPE_META[t]?.label || t}
          </button>
        ))}
      </div>

      {Object.entries(grouped).map(([cat, items]) => items.length > 0 && (
        <div key={cat}>
          <div className="text-[11px] uppercase font-mono text-slate-500 tracking-wider mb-2">{CATEGORY_META[cat].label} — {CATEGORY_META[cat].desc}</div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
            {items.map(m => <ModuleCard key={m.id} m={m} selected={selectedIds.has(m.id)} onToggle={toggleModule}/>)}
          </div>
        </div>
      ))}
      {filtered.length === 0 && (
        <div className="text-[12px] text-slate-500 border border-[#30363D] rounded-md py-6 text-center">No modules for this target type yet.</div>
      )}

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 max-w-xl">
        <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">
          Target ({TARGET_TYPE_META[targetType]?.label}) — {selectedIds.size} module{selectedIds.size === 1 ? "" : "s"} selected
        </label>
        <div className="flex gap-2 mt-1">
          <input value={target} onChange={e => setTarget(e.target.value)}
            placeholder={TARGET_TYPE_META[targetType]?.placeholder}
            className="flex-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200 font-mono"/>
          <button onClick={run} disabled={running || selectedIds.size === 0}
            className="h-9 px-3.5 text-[12.5px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded inline-flex items-center gap-1.5">
            {running ? <><CircleNotch size={14} className="animate-spin"/> Running…</> : <><Play size={14}/> Run {selectedIds.size > 1 ? `${selectedIds.size} modules` : "now"}</>}
          </button>
        </div>
      </div>

      {lastRun && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 max-w-xl">
          <div className="text-[12.5px] text-slate-200 font-medium mb-2 flex items-center gap-2">
            Results <Chip color={lastRun.status === "success" ? "green" : lastRun.status === "running" ? "blue" : lastRun.status === "partial" ? "orange" : "red"}>{lastRun.status}</Chip>
          </div>
          <div className="space-y-2.5">
            {(lastRun.results || []).map((res, i) => (
              <div key={i} className="text-[12px] text-slate-300 border-t border-[#30363D]/60 pt-2 first:border-t-0 first:pt-0">
                <div className="flex items-center gap-1.5 mb-0.5">
                  {res.status === "success" ? <CheckCircle size={13} className="text-emerald-400"/> : <XCircle size={13} className="text-red-400"/>}
                  <span className="font-medium text-slate-200">{byId[res.module_id]?.label || res.module_id}</span>
                </div>
                {res.status === "failed" ? (
                  <div className="text-[11.5px] text-red-400 pl-[19px]">{res.error}</div>
                ) : (
                  <div className="text-[11.5px] text-slate-400 pl-[19px] space-y-0.5">
                    <div>{res.result?.row_count ?? 0} row(s) returned</div>
                    {res.result?.easm_candidates_created != null && (
                      <div>{res.result.easm_candidates_created} new host(s) added to <Link to="/easm" className="text-blue-300 hover:underline">EASM Candidates</Link></div>
                    )}
                    {res.result?.osint_findings_created != null && (
                      <div>{res.result.osint_findings_created} new OSINT finding(s) — see the OSINT Findings tab</div>
                    )}
                  </div>
                )}
              </div>
            ))}
            {lastRun.status === "running" && (lastRun.results || []).length === 0 && (
              <div className="text-[11.5px] text-slate-500">Waiting on the first module…</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function Schedules() {
  const { modules } = useModules();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState({ module_id: "", target: "", interval_hours: 24, enabled: true });

  const load = () => api.get("/v1/admin/recon-schedules").then(r => setItems(r.data.items || [])).finally(() => setLoading(false));
  useEffect(() => { load(); }, []);

  const create = async () => {
    if (!form.module_id || !form.target.trim()) { toast.error("Pick a module and a target"); return; }
    try {
      await api.post("/v1/admin/recon-schedules", form);
      toast.success("Schedule created");
      setForm({ module_id: "", target: "", interval_hours: 24, enabled: true });
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to create schedule"); }
  };

  const remove = async (id) => {
    if (!window.confirm("Delete this schedule?")) return;
    await api.delete(`/v1/admin/recon-schedules/${id}`);
    load();
  };

  const toggle = async (s) => {
    await api.put(`/v1/admin/recon-schedules/${s.id}`, { ...s, enabled: !s.enabled });
    load();
  };

  return (
    <div className="space-y-4">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 max-w-2xl">
        <div className="text-[12.5px] text-slate-200 font-medium mb-3">New schedule</div>
        <div className="grid grid-cols-2 gap-2.5">
          <div>
            <label className="text-[10px] uppercase font-mono text-slate-500">Module</label>
            <select value={form.module_id} onChange={e => setForm({ ...form, module_id: e.target.value })}
              className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200">
              <option value="">Select…</option>
              {modules.map(m => <option key={m.id} value={m.id} disabled={!m.ready}>{m.label}{!m.ready ? " (missing key)" : ""}</option>)}
            </select>
          </div>
          <div>
            <label className="text-[10px] uppercase font-mono text-slate-500">Target</label>
            <input value={form.target} onChange={e => setForm({ ...form, target: e.target.value })}
              placeholder="company.com" className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200 font-mono"/>
          </div>
          <div>
            <label className="text-[10px] uppercase font-mono text-slate-500">Every (hours)</label>
            <input type="number" min={1} max={720} value={form.interval_hours}
              onChange={e => setForm({ ...form, interval_hours: Number(e.target.value) })}
              className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200"/>
          </div>
          <div className="flex items-end">
            <button onClick={create} className="h-9 px-3.5 text-[12.5px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
              <Plus size={14}/> Add schedule
            </button>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-6 text-center">Loading…</div>
      ) : items.length === 0 ? (
        <div className="text-[12.5px] text-slate-500 py-6 text-center border border-[#30363D] rounded-md">No schedules yet.</div>
      ) : (
        <div className="space-y-2">
          {items.map(s => (
            <div key={s.id} className="border border-[#30363D] bg-[#0D1117] rounded-md px-3.5 py-2.5 flex items-center justify-between">
              <div>
                <div className="text-[12.5px] text-slate-200">{modules.find(m => m.id === s.module_id)?.label || s.module_id} → <span className="font-mono text-slate-400">{s.target}</span></div>
                <div className="text-[11px] text-slate-500 flex items-center gap-1 mt-0.5"><Clock size={12}/> every {s.interval_hours}h{s.last_run_at ? ` · last run ${new Date(s.last_run_at).toLocaleString()}` : ""}</div>
              </div>
              <div className="flex items-center gap-1.5">
                {!s.enabled && <Chip color="slate">Disabled</Chip>}
                <button onClick={() => toggle(s)} className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-slate-200 rounded border border-[#30363D]">
                  {s.enabled ? <CheckCircle size={14}/> : <XCircle size={14}/>}
                </button>
                <button onClick={() => remove(s.id)} className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-red-400 rounded border border-[#30363D]">
                  <Trash size={14}/>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function RunHistory() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    api.get("/v1/recon/runs").then(r => setItems(r.data.items || [])).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>;
  if (items.length === 0) return <div className="text-[12.5px] text-slate-500 py-8 text-center border border-[#30363D] rounded-md">No runs yet.</div>;

  return (
    <div className="space-y-2">
      {items.map(r => (
        <div key={r.id} className="border border-[#30363D] bg-[#0D1117] rounded-md px-3.5 py-2.5">
          <div className="flex items-center justify-between">
            <div className="text-[12.5px] text-slate-200 flex items-center gap-2">
              {(r.module_labels || [r.module_label]).filter(Boolean).join(" + ")} → <span className="font-mono text-slate-400">{r.target}</span>
              {r.scheduled && <Chip color="purple">scheduled</Chip>}
            </div>
            <Chip color={r.status === "success" ? "green" : r.status === "running" ? "blue" : r.status === "partial" ? "orange" : "red"}>{r.status}</Chip>
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            {new Date(r.started_at).toLocaleString()} · by {r.triggered_by}
          </div>
          {(r.results || []).map((res, i) => (
            <div key={i} className="text-[11.5px] mt-1.5">
              <span className={res.status === "success" ? "text-slate-400" : "text-red-400"}>
                {(r.module_labels && r.module_labels[i]) || res.module_id}:{" "}
                {res.status === "success"
                  ? `${res.result?.row_count ?? 0} row(s)`
                    + (res.result?.easm_candidates_created != null ? ` · ${res.result.easm_candidates_created} EASM candidate(s)` : "")
                    + (res.result?.osint_findings_created != null ? ` · ${res.result.osint_findings_created} OSINT finding(s)` : "")
                  : res.error}
              </span>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

function OsintFindings() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const load = () => api.get("/v1/recon/osint-findings").then(r => setItems(r.data.items || [])).finally(() => setLoading(false));
  useEffect(() => { load(); }, []);

  const ack = async (f) => {
    await api.patch(`/v1/recon/osint-findings/${f.id}`, { acknowledged: !f.acknowledged });
    load();
  };

  if (loading) return <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>;
  if (items.length === 0) return <div className="text-[12.5px] text-slate-500 py-8 text-center border border-[#30363D] rounded-md">No OSINT findings yet — run a threat-intel module to check.</div>;

  return (
    <div className="space-y-2">
      {items.map(f => (
        <div key={f.id} className={`border rounded-md px-3.5 py-2.5 ${f.acknowledged ? "border-[#30363D] opacity-60" : "border-red-500/30 bg-red-500/5"}`}>
          <div className="flex items-center justify-between">
            <div className="text-[12.5px] text-slate-200 font-medium">{f.label}</div>
            <button onClick={() => ack(f)} className="h-7 px-2.5 text-[10.5px] border border-[#30363D] hover:border-emerald-500/50 hover:text-emerald-300 rounded inline-flex items-center gap-1">
              <Eye size={11}/> {f.acknowledged ? "Unacknowledge" : "Acknowledge"}
            </button>
          </div>
          <div className="text-[11.5px] text-slate-400 mt-1">{f.detail}</div>
          <div className="text-[10.5px] text-slate-500 mt-1 font-mono">{f.module_label} · target: {f.target} · {new Date(f.found_at).toLocaleString()}</div>
        </div>
      ))}
    </div>
  );
}

function ApiKeys() {
  const [hibpKey, setHibpKey] = useState("");
  const [status, setStatus] = useState(null);
  const [saving, setSaving] = useState(false);

  const load = () => api.get("/v1/admin/recon-config").then(r => setStatus(r.data));
  useEffect(() => { load(); }, []);

  const save = async () => {
    setSaving(true);
    try {
      await api.put("/v1/admin/recon-config", { hibp_api_key: hibpKey || undefined });
      toast.success("Saved");
      setHibpKey("");
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Save failed"); }
    finally { setSaving(false); }
  };

  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 max-w-lg">
      <div className="flex items-center gap-1.5 text-[12.5px] text-slate-200 mb-3"><GearSix size={15}/> recon-ng API Keys</div>
      <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">HaveIBeenPwned API Key</label>
      <input type="password" value={hibpKey} onChange={e => setHibpKey(e.target.value)}
        placeholder={status?.hibp_api_key_set ? "•••••• (leave blank to keep existing)" : "Paste your HIBP API key"}
        className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200 font-mono"/>
      <div className="text-[10.5px] text-slate-500 mt-1.5">Required for the hibp_breach and hibp_paste modules. Get one at haveibeenpwned.com/API/Key.</div>
      <button onClick={save} disabled={saving} className="mt-3 h-9 px-3.5 text-[12.5px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">
        {saving ? "Saving…" : "Save"}
      </button>
    </div>
  );
}
