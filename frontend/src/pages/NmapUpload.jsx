import { useEffect, useState, useRef } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  UploadSimple, FileCode, Globe, House, Plus, X, Trash, PencilSimple, Play,
  Clock, ShieldWarning, CheckCircle, XCircle, CircleNotch,
} from "@phosphor-icons/react";

const SCAN_TYPE_META = {
  quick: { label: "Quick", desc: "Top ~100 ports, no service/OS detection — seconds to a couple minutes" },
  standard: { label: "Standard", desc: "Top 1000 ports + service/OS detection — a few minutes" },
  thorough: { label: "Thorough", desc: "All 65535 ports + service/OS detection — can take a long time on big ranges" },
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

const EMPTY_FORM = { name: "", targets: "", scan_type: "standard", vantage: "internal", schedule_hours: 0, enabled: true, authorized: false };

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
            <Chip color="slate">{SCAN_TYPE_META[cfg.scan_type]?.label || cfg.scan_type}</Chip>
            {!cfg.enabled && <Chip color="slate">Disabled</Chip>}
            {running && (
              <span className="inline-flex items-center gap-1 text-[11px] text-blue-300">
                <CircleNotch size={12} className="animate-spin"/> Running…
              </span>
            )}
          </div>
          <div className="text-[11.5px] text-slate-500 font-mono mt-1 truncate">{cfg.targets}</div>
          <div className="flex items-center gap-3 mt-1.5 text-[11px] text-slate-500">
            <span className="inline-flex items-center gap-1"><Clock size={12}/> {scheduleLabel}</span>
            {cfg.last_run_at && <span>Last run: {new Date(cfg.last_run_at).toLocaleString()}</span>}
          </div>
          {result && (
            <div className="mt-2 text-[11.5px]">
              {result.ok === false ? (
                <div className="inline-flex items-center gap-1.5 text-red-400">
                  <XCircle size={13}/> {result.error || "Scan failed"}
                </div>
              ) : (
                <div className="inline-flex items-center gap-1.5 text-emerald-400">
                  <CheckCircle size={13}/>
                  {result.hosts_parsed} host(s) · {result.findings_created} new finding(s)
                  {cfg.vantage === "external" ? ` · ${result.exposure_mismatches || 0} exposure mismatch(es)` : ""}
                </div>
              )}
            </div>
          )}
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

function ScanConfigModal({ initial, isEdit, onClose, onSaved }) {
  const [form, setForm] = useState({
    name: initial.name || "", targets: initial.targets || "",
    scan_type: initial.scan_type || "standard", vantage: initial.vantage || "internal",
    schedule_hours: initial.schedule_hours ?? 0, enabled: initial.enabled ?? true,
    authorized: initial.authorized ?? false,
  });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!form.name.trim()) { toast.error("Name is required"); return; }
    if (!form.targets.trim()) { toast.error("Targets are required"); return; }
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
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-lg max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
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
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Targets</label>
            <input value={form.targets} onChange={e => setForm({ ...form, targets: e.target.value })}
              placeholder="10.0.0.0/24, 192.168.1.10, host.example.com"
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100 font-mono"/>
            <div className="text-[10.5px] text-slate-500 mt-1">Comma or space separated IPs, CIDR blocks, or hostnames — up to 64 per config.</div>
          </div>

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
