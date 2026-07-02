import { useEffect, useState, useRef } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  UploadSimple, FileCode, Globe, House, Plus, X, Trash, PencilSimple, Play,
  Clock, ShieldWarning, CheckCircle, XCircle, CircleNotch, Terminal, Sliders, ListChecks,
  Info, ArrowSquareOut,
} from "@phosphor-icons/react";

const SCAN_TYPE_META = {
  quick: { label: "Quick", desc: "Top ~100 ports, no service/OS detection — seconds to a couple minutes" },
  standard: { label: "Standard", desc: "Top 1000 ports + service/OS detection — a few minutes" },
  thorough: { label: "Thorough", desc: "All 65535 ports + service/OS detection — can take a long time on big ranges" },
};

const MODE_META = {
  preset: { label: "Presets", icon: ListChecks, desc: "Quick / Standard / Thorough" },
  builder: { label: "Builder", icon: Sliders, desc: "GUI toggles for ports, timing, scripts" },
  raw: { label: "Command line", icon: Terminal, desc: "Paste a raw nmap command" },
};

const PORT_MODE_META = {
  top100: "Top 100 ports",
  top1000: "Top 1000 ports",
  all: "All 65535 ports",
  custom: "Custom port spec",
};

const SCRIPT_CATEGORY_META = {
  default: "Default (nmap -sC equivalent)",
  safe: "Safe (non-intrusive checks)",
  discovery: "Discovery (extra host/service info)",
  version: "Version (deeper service fingerprinting)",
  vuln: "Vuln (checks for known vulnerabilities)",
};

const SCHEDULE_PRESETS = [
  { label: "Manual only", hours: 0 },
  { label: "Every 6 hours", hours: 6 },
  { label: "Daily", hours: 24 },
  { label: "Weekly", hours: 168 },
];

export default function NmapUpload() {
  const [tab, setTab] = useState("scheduled");

  return (
    <Layout title="Nmap Scans" subtitle="Run scans yourself from within VulnOps, put them on a schedule, or upload XML from an external scan">
      <div className="flex gap-1 border-b border-[#30363D] mb-5">
        {[
          { key: "scheduled", label: "Scheduled Scans" },
          { key: "upload", label: "Manual Upload" },
        ].map(t => (
          <button key={t.key} onClick={() => setTab(t.key)}
            className={`px-4 py-2 text-[13px] border-b-2 -mb-px transition-colors ${
              tab === t.key ? "border-blue-500 text-blue-300" : "border-transparent text-slate-500 hover:text-slate-300"
            }`}>
            {t.label}
          </button>
        ))}
      </div>
      {tab === "scheduled" ? <ScheduledScans /> : <ManualUpload />}
    </Layout>
  );
}

function ManualUpload() {
  const fileRef = useRef(null);
  const [file, setFile] = useState(null);
  const [vantage, setVantage] = useState("internal");
  const [label, setLabel] = useState(`Nmap scan ${new Date().toISOString().slice(0,10)}`);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  const submit = async () => {
    if (!file) { toast.error("Pick an XML file first"); return; }
    setBusy(true); setResult(null);
    try {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("vantage", vantage);
      fd.append("label", label);
      const r = await api.post("/v1/admin/nmap/upload", fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setResult(r.data);
      toast.success(`Imported: ${r.data.hosts_parsed} host(s), ${r.data.findings_created} new finding(s)`);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Upload failed");
    } finally { setBusy(false); }
  };

  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-5 max-w-3xl">
      <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3 py-2.5 mb-4 text-[12px] text-blue-200 leading-relaxed">
        For scans run somewhere VulnOps can't reach directly — a laptop, another network, a scanner
        appliance. Run <code className="font-mono text-[11px] bg-black/30 px-1 py-0.5 rounded">nmap -sV -O -oX scan.xml &lt;targets&gt;</code>{" "}
        yourself and upload the XML here. For scans VulnOps runs on its own, use the Scheduled Scans tab instead.
      </div>

      <div className="grid grid-cols-1 gap-4">
        <div>
          <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Scan vantage point</label>
          <div className="flex gap-2">
            <button type="button" onClick={()=>setVantage("internal")}
              className={`flex-1 h-14 rounded-md border px-3 flex items-center gap-2.5 text-left transition-colors ${vantage==="internal" ? "border-blue-500/50 bg-blue-500/10" : "border-[#30363D] hover:border-[#484F58]"}`}>
              <House size={18} className={vantage==="internal" ? "text-blue-300" : "text-slate-500"}/>
              <div>
                <div className={`text-[12.5px] ${vantage==="internal" ? "text-blue-200" : "text-slate-300"}`}>Internal</div>
                <div className="text-[10.5px] text-slate-500">Run from inside your network — enrichment only</div>
              </div>
            </button>
            <button type="button" onClick={()=>setVantage("external")}
              className={`flex-1 h-14 rounded-md border px-3 flex items-center gap-2.5 text-left transition-colors ${vantage==="external" ? "border-orange-500/50 bg-orange-500/10" : "border-[#30363D] hover:border-[#484F58]"}`}>
              <Globe size={18} className={vantage==="external" ? "text-orange-300" : "text-slate-500"}/>
              <div>
                <div className={`text-[12.5px] ${vantage==="external" ? "text-orange-200" : "text-slate-300"}`}>External</div>
                <div className="text-[10.5px] text-slate-500">Run from outside — verifies real internet exposure</div>
              </div>
            </button>
          </div>
        </div>

        <div>
          <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Source label (for history)</label>
          <input
            data-testid="nmap-label"
            value={label}
            onChange={(e)=>setLabel(e.target.value)}
            className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100"
          />
        </div>

        <div>
          <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Nmap XML File</label>
          <div className="border-2 border-dashed border-[#30363D] hover:border-blue-500/40 rounded-md p-6 text-center cursor-pointer transition-colors"
               onClick={()=>fileRef.current?.click()}>
            <input
              data-testid="nmap-file"
              ref={fileRef}
              type="file"
              accept=".xml"
              onChange={(e)=>setFile(e.target.files?.[0] || null)}
              className="hidden"
            />
            <FileCode size={36} className="text-slate-500 mx-auto mb-2"/>
            {file ? (
              <>
                <div className="text-[13px] text-slate-200 font-mono">{file.name}</div>
                <div className="text-[11px] text-slate-500 mt-1">{(file.size/1024).toFixed(1)} KB · Click to change</div>
              </>
            ) : (
              <>
                <div className="text-[13px] text-slate-300">Click to choose an XML file</div>
                <div className="text-[11px] text-slate-500 mt-1">Output of <code className="font-mono">nmap -oX</code></div>
              </>
            )}
          </div>
        </div>

        <button
          data-testid="nmap-submit"
          onClick={submit}
          disabled={busy || !file}
          className="h-10 px-4 text-[13px] bg-blue-500 hover:bg-blue-400 disabled:opacity-40 text-white rounded inline-flex items-center justify-center gap-2"
        >
          <UploadSimple size={16}/> {busy ? "Importing…" : "Upload & Ingest"}
        </button>

        {result && (
          <div className="border border-[#30363D] bg-[#161B22] rounded-md p-3.5 text-[12.5px] text-slate-300 space-y-1">
            <div>{result.hosts_parsed} host(s) parsed · {result.assets_touched} asset(s) touched</div>
            <div>{result.findings_created} new finding(s) created</div>
            {result.vantage === "external" && (
              <div>{result.exposure_confirmed} exposure confirmed · {result.exposure_mismatches} exposure mismatch(es) flagged</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

const EMPTY_FORM = {
  name: "", targets: "", mode: "preset", scan_type: "standard", vantage: "internal",
  schedule_hours: 0, enabled: true, authorized: false,
  port_mode: "top1000", custom_ports: "", timing: 4, detect_service: true, detect_os: true,
  scripts: [], scan_technique: "syn", custom_command: "", skip_host_discovery: true,
};

function ScheduledScans() {
  const [configs, setConfigs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState(null);
  const [runningIds, setRunningIds] = useState(new Set());
  const pollRef = useRef(null);

  const load = async () => {
    try {
      const r = await api.get("/v1/admin/nmap/configs");
      setConfigs(r.data.items || []);
    } catch (e) {
      toast.error("Failed to load scan configs");
    } finally { setLoading(false); }
  };

  useEffect(() => {
    load();
    // Light poll so status/last_result update while a scan runs, without a manual refresh
    pollRef.current = setInterval(load, 8000);
    return () => clearInterval(pollRef.current);
  }, []);

  const runNow = async (cfg) => {
    setRunningIds(prev => new Set(prev).add(cfg.id));
    try {
      await api.post(`/v1/admin/nmap/configs/${cfg.id}/run-now`);
      toast.success(`${cfg.name}: scan started — this can take a few minutes`);
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to start scan");
    } finally {
      setRunningIds(prev => { const n = new Set(prev); n.delete(cfg.id); return n; });
    }
  };

  const remove = async (cfg) => {
    if (!window.confirm(`Delete scan config "${cfg.name}"?`)) return;
    try {
      await api.delete(`/v1/admin/nmap/configs/${cfg.id}`);
      toast.success("Deleted");
      load();
    } catch (e) {
      toast.error("Delete failed");
    }
  };

  const toggleEnabled = async (cfg) => {
    try {
      await api.put(`/v1/admin/nmap/configs/${cfg.id}`, { ...cfg, enabled: !cfg.enabled });
      load();
    } catch (e) {
      toast.error("Update failed");
    }
  };

  return (
    <div>
      <div className="border border-orange-500/30 bg-orange-500/5 rounded-md px-3 py-2.5 mb-4 text-[12px] text-orange-200 leading-relaxed flex items-start gap-2 max-w-3xl">
        <ShieldWarning size={16} className="shrink-0 mt-0.5"/>
        <div>
          VulnOps will originate real network traffic to whatever targets you configure. Only scan ranges
          you're authorized to scan — every config requires you to confirm that explicitly. Only one scan
          runs at a time, whether triggered manually or by schedule.
        </div>
      </div>

      <div className="flex justify-end mb-3">
        <button onClick={() => { setEditing(null); setModalOpen(true); }}
          className="h-9 px-3.5 text-[12.5px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
          <Plus size={15}/> New scan config
        </button>
      </div>

      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : configs.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No scan configs yet. Create one to run scans on a schedule, or on demand.
        </div>
      ) : (
        <div className="space-y-2.5">
          {configs.map(cfg => (
            <ScanConfigRow
              key={cfg.id}
              cfg={cfg}
              running={runningIds.has(cfg.id) || cfg.status === "running"}
              onRun={() => runNow(cfg)}
              onEdit={() => { setEditing(cfg); setModalOpen(true); }}
              onDelete={() => remove(cfg)}
              onToggle={() => toggleEnabled(cfg)}
            />
          ))}
        </div>
      )}

      {modalOpen && (
        <ScanConfigModal
          initial={editing || EMPTY_FORM}
          isEdit={!!editing}
          onClose={() => setModalOpen(false)}
          onSaved={() => { setModalOpen(false); load(); }}
        />
      )}
    </div>
  );
}

function ScanConfigRow({ cfg, running, onRun, onEdit, onDelete, onToggle }) {
  const [resultOpen, setResultOpen] = useState(false);
  const scheduleLabel = cfg.schedule_hours === 0
    ? "Manual only"
    : SCHEDULE_PRESETS.find(p => p.hours === cfg.schedule_hours)?.label || `Every ${cfg.schedule_hours}h`;
  const result = cfg.last_result;

  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3.5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[13.5px] text-slate-100 font-medium">{cfg.name}</span>
            <Chip color={cfg.vantage === "external" ? "orange" : "blue"}>{cfg.vantage}</Chip>
            {(!cfg.mode || cfg.mode === "preset") ? (
              <Chip color="slate">{SCAN_TYPE_META[cfg.scan_type]?.label || cfg.scan_type}</Chip>
            ) : (
              <Chip color="purple">{MODE_META[cfg.mode]?.label || cfg.mode}</Chip>
            )}
            {!cfg.enabled && <Chip color="slate">Disabled</Chip>}
            {running && (
              <span className="inline-flex items-center gap-1 text-[11px] text-blue-300">
                <CircleNotch size={12} className="animate-spin"/> Running…
              </span>
            )}
          </div>
          <div className="text-[11.5px] text-slate-500 font-mono mt-1 truncate">
            {cfg.mode && cfg.mode !== "preset" && cfg.resolved_command ? cfg.resolved_command : cfg.targets}
          </div>
          <div className="flex items-center gap-3 mt-1.5 text-[11px] text-slate-500">
            <span className="inline-flex items-center gap-1"><Clock size={12}/> {scheduleLabel}</span>
            {cfg.last_run_at && <span>Last run: {new Date(cfg.last_run_at).toLocaleString()}</span>}
          </div>
          {result && (
            <div className="mt-2 text-[11.5px]">
              {result.ok === false ? (
                <button onClick={() => setResultOpen(true)} className="inline-flex items-center gap-1.5 text-red-400 hover:underline">
                  <XCircle size={13}/> {result.error || "Scan failed"}
                </button>
              ) : (
                <button onClick={() => setResultOpen(true)} className="inline-flex items-center gap-1.5 text-emerald-400 hover:underline">
                  <CheckCircle size={13}/>
                  {result.hosts_parsed} host(s) · {result.findings_created} new finding(s)
                  {cfg.vantage === "external" ? ` · ${result.exposure_mismatches || 0} exposure mismatch(es)` : ""}
                </button>
              )}
              {result.ok !== false && result.hosts_parsed === 0 && (
                <div className="mt-1 flex items-start gap-1.5 text-[11px] text-slate-500">
                  <Info size={13} className="shrink-0 mt-0.5"/>
                  <span>No hosts responded — click above for troubleshooting tips.</span>
                </div>
              )}
            </div>
          )}
          {resultOpen && <ScanResultModal cfg={cfg} result={result} onClose={() => setResultOpen(false)}/>}
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <button onClick={onRun} disabled={running}
            className="h-8 px-2.5 text-[11.5px] bg-blue-500/10 hover:bg-blue-500/20 disabled:opacity-40 text-blue-300 rounded inline-flex items-center gap-1.5 border border-blue-500/30">
            <Play size={13}/> Run now
          </button>
          <button onClick={onToggle} title={cfg.enabled ? "Disable schedule" : "Enable schedule"}
            className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-slate-200 rounded border border-[#30363D]">
            {cfg.enabled ? <CheckCircle size={14}/> : <XCircle size={14}/>}
          </button>
          <button onClick={onEdit} className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-slate-200 rounded border border-[#30363D]">
            <PencilSimple size={14}/>
          </button>
          <button onClick={onDelete} className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-red-400 rounded border border-[#30363D]">
            <Trash size={14}/>
          </button>
        </div>
      </div>
    </div>
  );
}

function ScanResultModal({ cfg, result, onClose }) {
  const hosts = result?.hosts || [];
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-lg max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="text-[14px] text-slate-100 font-medium">Scan result — {cfg.name}</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>

        <div className="p-5 space-y-4">
          {cfg.resolved_command && (
            <div>
              <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Command that ran</div>
              <div className="rounded-md px-3 py-2 text-[11px] font-mono break-all border border-[#30363D] bg-[#161B22] text-slate-300">
                {cfg.resolved_command}
              </div>
            </div>
          )}

          {result?.ok === false ? (
            <div className="border border-red-500/30 bg-red-500/5 rounded-md px-3 py-2.5 text-[12px] text-red-300">
              {result.error || "Scan failed"}
            </div>
          ) : hosts.length === 0 ? (
            <div className="border border-orange-500/30 bg-orange-500/5 rounded-md px-3 py-2.5 text-[12px] text-orange-200 leading-relaxed space-y-1.5">
              <div className="font-medium">No hosts responded. A few things to check:</div>
              <div>• If this target is behind a router/firewall, it may be silently dropping Nmap's discovery
                probes — "Treat target as online (skip ping check)" is on by default for new configs, so if this
                config predates that, re-save it (or switch it to Builder mode) to pick it up.</div>
              <div>• Confirm the target IP/hostname is correct and reachable from wherever this container's Docker
                host sits on your network.</div>
              <div>• Some scan techniques (UDP, certain NSE scripts) are much slower and can time out on a big
                port range before finishing — try a narrower port spec first.</div>
            </div>
          ) : (
            <div>
              <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">
                {hosts.length} host(s) found
              </div>
              <div className="border border-[#30363D] rounded-md divide-y divide-[#30363D]">
                {hosts.map(h => (
                  <Link key={h.asset_id} to={`/assets/${h.asset_id}`}
                    className="flex items-center justify-between gap-3 px-3 py-2.5 hover:bg-[#161B22] transition-colors">
                    <div className="min-w-0">
                      <div className="text-[12.5px] text-slate-200 font-mono truncate">{h.hostname || h.ip}</div>
                      <div className="text-[10.5px] text-slate-500">
                        {h.ip}{h.os_guess ? ` · ${h.os_guess}` : ""} · {h.open_ports_count} open port(s)
                      </div>
                    </div>
                    <ArrowSquareOut size={14} className="text-slate-500 shrink-0"/>
                  </Link>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ScanConfigModal({ initial, isEdit, onClose, onSaved }) {
  const [form, setForm] = useState({
    name: initial.name || "", targets: initial.targets || "",
    mode: initial.mode || "preset", scan_type: initial.scan_type || "standard", vantage: initial.vantage || "internal",
    schedule_hours: initial.schedule_hours ?? 0, enabled: initial.enabled ?? true,
    authorized: initial.authorized ?? false,
    port_mode: initial.port_mode || "top1000", custom_ports: initial.custom_ports || "",
    timing: initial.timing ?? 4, detect_service: initial.detect_service ?? true, detect_os: initial.detect_os ?? true,
    scripts: initial.scripts || [], scan_technique: initial.scan_technique || "syn",
    custom_command: initial.custom_command || "",
    skip_host_discovery: initial.skip_host_discovery ?? true,
  });
  const [saving, setSaving] = useState(false);
  const [preview, setPreview] = useState(null);
  const [previewErr, setPreviewErr] = useState(null);
  const previewTimer = useRef(null);

  useEffect(() => {
    if (form.mode === "preset") { setPreview(null); setPreviewErr(null); return; }
    clearTimeout(previewTimer.current);
    previewTimer.current = setTimeout(async () => {
      try {
        const r = await api.post("/v1/admin/nmap/configs/preview", form);
        setPreview(r.data);
        setPreviewErr(null);
      } catch (e) {
        setPreview(null);
        setPreviewErr(e.response?.data?.detail || null);
      }
    }, 500);
    return () => clearTimeout(previewTimer.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [form.mode, form.targets, form.port_mode, form.custom_ports, form.timing, form.detect_service,
      form.detect_os, form.scripts, form.scan_technique, form.custom_command, form.authorized,
      form.skip_host_discovery]);

  const toggleScript = (cat) => {
    setForm(f => ({ ...f, scripts: f.scripts.includes(cat) ? f.scripts.filter(s => s !== cat) : [...f.scripts, cat] }));
  };

  const save = async () => {
    if (!form.name.trim()) { toast.error("Name is required"); return; }
    if (form.mode !== "raw" && !form.targets.trim()) { toast.error("Targets are required"); return; }
    if (form.mode === "raw" && !form.custom_command.trim()) { toast.error("Paste an nmap command first"); return; }
    if (!form.authorized) { toast.error("You must confirm you're authorized to scan these targets"); return; }
    setSaving(true);
    try {
      if (isEdit) {
        await api.put(`/v1/admin/nmap/configs/${initial.id}`, form);
      } else {
        await api.post(`/v1/admin/nmap/configs`, form);
      }
      toast.success(isEdit ? "Scan config updated" : "Scan config created");
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Save failed");
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="text-[14px] text-slate-100 font-medium">{isEdit ? "Edit scan config" : "New scan config"}</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>

        <div className="p-5 space-y-4">
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Name</label>
            <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}
              placeholder="e.g. DMZ weekly sweep"
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100"/>
          </div>

          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">How to configure this scan</label>
            <div className="grid grid-cols-3 gap-1.5">
              {Object.entries(MODE_META).map(([key, meta]) => {
                const Icon = meta.icon;
                return (
                  <button key={key} type="button" onClick={() => setForm({ ...form, mode: key })}
                    className={`rounded-md border px-2.5 py-2 text-left transition-colors ${form.mode === key ? "border-violet-500/50 bg-violet-500/10" : "border-[#30363D] hover:border-[#484F58]"}`}>
                    <div className={`flex items-center gap-1.5 text-[12px] ${form.mode === key ? "text-violet-200" : "text-slate-300"}`}>
                      <Icon size={13}/> {meta.label}
                    </div>
                    <div className="text-[10px] text-slate-500 mt-0.5 leading-tight">{meta.desc}</div>
                  </button>
                );
              })}
            </div>
          </div>

          {form.mode === "raw" ? (
            <div>
              <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Nmap command</label>
              <textarea value={form.custom_command} onChange={e => setForm({ ...form, custom_command: e.target.value })}
                placeholder="nmap -sV -O -p 1-1000 -T4 10.0.0.0/24"
                rows={3}
                className="w-full bg-[#161B22] border border-[#30363D] rounded px-3 py-2 text-[12.5px] text-slate-100 font-mono resize-none"/>
              <div className="text-[10.5px] text-slate-500 mt-1">
                Targets are parsed from the command itself. Output flags (-oX etc.), file-based target lists (-iL),
                decoys, and spoofing flags aren't allowed — VulnOps controls output and only scans exactly what you type.
              </div>
            </div>
          ) : (
            <div>
              <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Targets</label>
              <input value={form.targets} onChange={e => setForm({ ...form, targets: e.target.value })}
                placeholder="10.0.0.0/24, 192.168.1.10, host.example.com"
                className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100 font-mono"/>
              <div className="text-[10.5px] text-slate-500 mt-1">Comma or space separated IPs, CIDR blocks, or hostnames — up to 64 per config.</div>
            </div>
          )}

          {form.mode === "preset" && (
            <div>
              <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Scan depth</label>
              <div className="grid grid-cols-3 gap-1.5">
                {Object.entries(SCAN_TYPE_META).map(([key, meta]) => (
                  <button key={key} type="button" onClick={() => setForm({ ...form, scan_type: key })}
                    className={`rounded-md border px-2.5 py-2 text-left transition-colors ${form.scan_type === key ? "border-blue-500/50 bg-blue-500/10" : "border-[#30363D] hover:border-[#484F58]"}`}>
                    <div className={`text-[12px] ${form.scan_type === key ? "text-blue-200" : "text-slate-300"}`}>{meta.label}</div>
                    <div className="text-[10px] text-slate-500 mt-0.5 leading-tight">{meta.desc}</div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {form.mode === "builder" && (
            <div className="space-y-3 border border-[#30363D] rounded-md p-3.5 bg-[#0A0D12]">
              <div>
                <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Scan technique</label>
                <div className="grid grid-cols-3 gap-1.5">
                  {[{k:"syn",l:"SYN (-sS)"},{k:"connect",l:"Connect (-sT)"},{k:"udp",l:"UDP (-sU)"}].map(t => (
                    <button key={t.k} type="button" onClick={() => setForm({ ...form, scan_technique: t.k })}
                      className={`h-8 rounded border text-[11.5px] ${form.scan_technique === t.k ? "border-violet-500/50 bg-violet-500/10 text-violet-200" : "border-[#30363D] text-slate-400 hover:border-[#484F58]"}`}>
                      {t.l}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Ports</label>
                <div className="grid grid-cols-4 gap-1.5 mb-1.5">
                  {Object.entries(PORT_MODE_META).map(([key, label]) => (
                    <button key={key} type="button" onClick={() => setForm({ ...form, port_mode: key })}
                      className={`h-8 rounded border text-[11px] px-1 ${form.port_mode === key ? "border-violet-500/50 bg-violet-500/10 text-violet-200" : "border-[#30363D] text-slate-400 hover:border-[#484F58]"}`}>
                      {label}
                    </button>
                  ))}
                </div>
                {form.port_mode === "custom" && (
                  <input value={form.custom_ports} onChange={e => setForm({ ...form, custom_ports: e.target.value })}
                    placeholder="80,443,8080-8090"
                    className="w-full h-8 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12px] text-slate-100 font-mono"/>
                )}
              </div>

              <div>
                <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">
                  Timing: T{form.timing} {form.timing <= 1 ? "(slow/stealthy)" : form.timing >= 4 ? "(fast)" : ""}
                </label>
                <input type="range" min={0} max={5} value={form.timing}
                  onChange={e => setForm({ ...form, timing: parseInt(e.target.value, 10) })}
                  className="w-full"/>
              </div>

              <div className="flex gap-4 flex-wrap">
                <label className="flex items-center gap-2 text-[12px] text-slate-300 cursor-pointer">
                  <input type="checkbox" checked={form.detect_service} onChange={e => setForm({ ...form, detect_service: e.target.checked })}/>
                  Service/version detection (-sV)
                </label>
                <label className="flex items-center gap-2 text-[12px] text-slate-300 cursor-pointer">
                  <input type="checkbox" checked={form.detect_os} onChange={e => setForm({ ...form, detect_os: e.target.checked })}/>
                  OS detection (-O)
                </label>
              </div>

              <label className="flex items-start gap-2 text-[12px] text-slate-300 cursor-pointer border border-[#30363D] rounded-md px-2.5 py-2">
                <input type="checkbox" checked={form.skip_host_discovery} onChange={e => setForm({ ...form, skip_host_discovery: e.target.checked })}
                  className="mt-0.5"/>
                <span>
                  Treat target as online, skip the ping check (-Pn)
                  <span className="block text-[10.5px] text-slate-500 mt-0.5">
                    Recommended — many routers/firewalls silently drop the probes Nmap uses to check if a host is
                    up, which makes the scan report "0 hosts" even though the target is reachable. Turn this off
                    only if you specifically want Nmap's discovery step to skip unresponsive hosts on a big range.
                  </span>
                </span>
              </label>

              <div>
                <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">NSE scripts</label>
                <div className="space-y-1">
                  {Object.entries(SCRIPT_CATEGORY_META).map(([cat, desc]) => (
                    <label key={cat} className="flex items-center gap-2 text-[11.5px] text-slate-300 cursor-pointer">
                      <input type="checkbox" checked={form.scripts.includes(cat)} onChange={() => toggleScript(cat)}/>
                      <span className="font-mono text-slate-400">{cat}</span> — {desc}
                    </label>
                  ))}
                </div>
              </div>
            </div>
          )}

          {(preview || previewErr) && form.mode !== "preset" && (
            <div className={`rounded-md px-3 py-2 text-[11px] font-mono break-all ${previewErr ? "border border-red-500/30 bg-red-500/5 text-red-300" : "border border-emerald-500/30 bg-emerald-500/5 text-emerald-300"}`}>
              {previewErr || preview?.resolved_command}
            </div>
          )}

          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Vantage point</label>
            <div className="flex gap-2">
              <button type="button" onClick={() => setForm({ ...form, vantage: "internal" })}
                className={`flex-1 h-10 rounded-md border px-3 flex items-center gap-2 text-left transition-colors ${form.vantage === "internal" ? "border-blue-500/50 bg-blue-500/10" : "border-[#30363D] hover:border-[#484F58]"}`}>
                <House size={16} className={form.vantage === "internal" ? "text-blue-300" : "text-slate-500"}/>
                <span className={`text-[12px] ${form.vantage === "internal" ? "text-blue-200" : "text-slate-300"}`}>Internal</span>
              </button>
              <button type="button" onClick={() => setForm({ ...form, vantage: "external" })}
                className={`flex-1 h-10 rounded-md border px-3 flex items-center gap-2 text-left transition-colors ${form.vantage === "external" ? "border-orange-500/50 bg-orange-500/10" : "border-[#30363D] hover:border-[#484F58]"}`}>
                <Globe size={16} className={form.vantage === "external" ? "text-orange-300" : "text-slate-500"}/>
                <span className={`text-[12px] ${form.vantage === "external" ? "text-orange-200" : "text-slate-300"}`}>External</span>
              </button>
            </div>
            <div className="text-[10.5px] text-slate-500 mt-1">Only mark this "external" if this VulnOps host itself sits outside the network being scanned — that's what makes exposure verification meaningful.</div>
          </div>

          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Schedule</label>
            <div className="grid grid-cols-4 gap-1.5">
              {SCHEDULE_PRESETS.map(p => (
                <button key={p.hours} type="button" onClick={() => setForm({ ...form, schedule_hours: p.hours })}
                  className={`h-9 rounded-md border text-[11.5px] transition-colors ${form.schedule_hours === p.hours ? "border-blue-500/50 bg-blue-500/10 text-blue-200" : "border-[#30363D] text-slate-400 hover:border-[#484F58]"}`}>
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <label className="flex items-start gap-2.5 border border-[#30363D] rounded-md px-3 py-2.5 cursor-pointer hover:border-[#484F58]">
            <input type="checkbox" checked={form.authorized} onChange={e => setForm({ ...form, authorized: e.target.checked })}
              className="mt-0.5"/>
            <span className="text-[12px] text-slate-300 leading-relaxed">
              I confirm I'm authorized to run active scans against these targets.
            </span>
          </label>
        </div>

        <div className="flex justify-end gap-2 px-5 py-3.5 border-t border-[#30363D]">
          <button onClick={onClose} className="h-9 px-3.5 text-[12.5px] text-slate-400 hover:text-slate-200 rounded">Cancel</button>
          <button onClick={save} disabled={saving}
            className="h-9 px-4 text-[12.5px] bg-blue-500 hover:bg-blue-400 disabled:opacity-40 text-white rounded">
            {saving ? "Saving…" : isEdit ? "Save changes" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}
