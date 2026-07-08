import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  Virus, FileCode, UploadSimple, CheckCircle, XCircle, Plus, X, Trash, PencilSimple,
  Warning, CircleNotch, Flask, LinkSimple,
} from "@phosphor-icons/react";

// Standard EICAR antivirus test string -- not malware, universally recognized by
// every scanner as the industry-standard "does the pipeline actually work" probe.
// Used for the one-click "Run test scan" button below so a first-time user can see
// the whole upload -> match -> finding-created flow without needing a real sample.
const EICAR_STRING = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

const SEVERITY_COLOR = { Critical: "red", High: "orange", Medium: "amber", Low: "slate" };

export default function Yara() {
  const [tab, setTab] = useState("scan");

  return (
    <Layout title="YARA Scanning" subtitle="Match uploaded files against your own YARA rule library — pattern-based malware/webshell detection">
      <div className="flex gap-1 border-b border-[#30363D] mb-5">
        {[{ key: "scan", label: "Scan a File" }, { key: "rules", label: "Rules" }].map(t => (
          <button key={t.key} onClick={() => setTab(t.key)}
            className={`px-4 py-2 text-[13px] border-b-2 -mb-px transition-colors ${
              tab === t.key ? "border-blue-500 text-blue-300" : "border-transparent text-slate-500 hover:text-slate-300"
            }`}>
            {t.label}
          </button>
        ))}
      </div>
      {tab === "scan" ? <ScanTab/> : <RulesTab/>}
    </Layout>
  );
}

function MatchList({ matches }) {
  if (!matches || matches.length === 0) {
    return <div className="text-[12.5px] text-slate-500 py-4 text-center">No rules matched.</div>;
  }
  return (
    <div className="space-y-2">
      {matches.map((m, i) => (
        <div key={i} className="border border-[#30363D] bg-[#161B22] rounded-md p-3">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="text-[12.5px] text-slate-100 font-medium font-mono">{m.matched_rule}</span>
            <Chip color={SEVERITY_COLOR[m.severity] || "slate"}>{m.severity}</Chip>
            {(m.tags || []).map(t => <Chip key={t} color="purple">{t}</Chip>)}
          </div>
          {m.meta?.description && <div className="text-[11.5px] text-slate-400 mb-1.5">{m.meta.description}</div>}
          {m.strings?.length > 0 && (
            <div className="mt-1.5 space-y-1">
              {m.strings.slice(0, 6).map((s, j) => (
                <div key={j} className="text-[10.5px] font-mono text-slate-500 bg-black/30 rounded px-2 py-1 break-all">
                  {s.identifier} @ offset {s.offset}: <span className="text-slate-300">{s.snippet}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function ScanTab() {
  const fileRef = useRef(null);
  const [file, setFile] = useState(null);
  const [label, setLabel] = useState("");
  const [assetQuery, setAssetQuery] = useState("");
  const [assetId, setAssetId] = useState("");
  const [assetOptions, setAssetOptions] = useState([]);
  const [busy, setBusy] = useState(false);
  const [testBusy, setTestBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [detail, setDetail] = useState(null);

  const loadHistory = async () => {
    try {
      const r = await api.get("/v1/admin/yara/history");
      setHistory(r.data.items || []);
    } catch (e) { /* non-fatal */ }
  };

  useEffect(() => { loadHistory(); }, []);

  // Lightweight asset search-as-you-type -- lets a scan get attributed to a real
  // asset (so the resulting finding shows up on that asset's page) instead of every
  // upload just floating as a generic, unattached finding.
  useEffect(() => {
    const h = setTimeout(async () => {
      if (!assetQuery.trim()) { setAssetOptions([]); return; }
      try {
        const r = await api.get("/v1/assets", { params: { q: assetQuery, limit: 20 } });
        setAssetOptions(r.data.items || []);
      } catch (e) { /* non-fatal */ }
    }, 250);
    return () => clearTimeout(h);
  }, [assetQuery]);

  const runScan = async (uploadFile, uploadLabel) => {
    setResult(null);
    const fd = new FormData();
    fd.append("file", uploadFile);
    fd.append("label", uploadLabel || "");
    if (assetId) fd.append("asset_id", assetId);
    const r = await api.post("/v1/admin/yara/scan", fd, { headers: { "Content-Type": "multipart/form-data" } });
    setResult(r.data);
    toast.success(`${r.data.matched_rule_count} rule match(es), ${r.data.findings_created} new finding(s)`);
    loadHistory();
  };

  const submit = async () => {
    if (!file) { toast.error("Pick a file first"); return; }
    setBusy(true);
    try {
      await runScan(file, label);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Scan failed");
    } finally { setBusy(false); }
  };

  // One-click pipeline smoke test using the industry-standard EICAR test string --
  // every AV/YARA tool recognizes it, it's not malware, and the seeded starter rule
  // library already ships an EICAR-detecting rule. Lets a first-time user confirm
  // upload -> match -> finding-created works before hunting for a real sample.
  const runEicarTest = async () => {
    setTestBusy(true);
    try {
      const blob = new Blob([EICAR_STRING], { type: "text/plain" });
      const eicarFile = new File([blob], "eicar-test-file.txt", { type: "text/plain" });
      await runScan(eicarFile, "Built-in EICAR pipeline test");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Test scan failed");
    } finally { setTestBusy(false); }
  };

  const openDetail = async (id) => {
    try {
      const r = await api.get(`/v1/admin/yara/history/${id}`);
      setDetail(r.data);
    } catch (e) {
      toast.error("Failed to load scan detail");
    }
  };

  return (
    <div>
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-5 max-w-3xl mb-5">
        <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3 py-2.5 mb-4 text-[12px] text-blue-200 leading-relaxed">
          Uploads any file (script, binary, archive member, config — up to 25MB) and checks it against every{" "}
          <span className="text-blue-100">enabled</span> rule in your library. Two starter rules are seeded by
          default (an EICAR test-string detector and a generic PHP webshell heuristic) so you can confirm the
          pipeline works before adding real rules — see the Rules tab.
        </div>

        <div className="grid grid-cols-1 gap-4">
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Label (optional)</label>
            <input value={label} onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. uploaded attachment from ticket #412"
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100"/>
          </div>

          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">File</label>
            <div className="border-2 border-dashed border-[#30363D] hover:border-blue-500/40 rounded-md p-6 text-center cursor-pointer transition-colors"
                 onClick={() => fileRef.current?.click()}>
              <input ref={fileRef} type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} className="hidden"/>
              <FileCode size={36} className="text-slate-500 mx-auto mb-2"/>
              {file ? (
                <>
                  <div className="text-[13px] text-slate-200 font-mono">{file.name}</div>
                  <div className="text-[11px] text-slate-500 mt-1">{(file.size / 1024).toFixed(1)} KB · Click to change</div>
                </>
              ) : (
                <div className="text-[13px] text-slate-300">Click to choose a file to scan</div>
              )}
            </div>
          </div>

          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Attribute to asset (optional)</label>
            <input value={assetId ? assetQuery : assetQuery} onChange={(e) => { setAssetQuery(e.target.value); setAssetId(""); }}
              placeholder="Search hostname/IP — leave blank to leave the finding unattached"
              list="yara-asset-options"
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100"/>
            <datalist id="yara-asset-options">
              {assetOptions.map(a => <option key={a.id} value={a.hostname} data-id={a.id}/>)}
            </datalist>
            {assetOptions.length > 0 && !assetId && (
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {assetOptions.slice(0, 5).map(a => (
                  <button type="button" key={a.id} onClick={() => { setAssetId(a.id); setAssetQuery(a.hostname); }}
                    className="h-6 px-2 text-[11px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 rounded text-slate-400">
                    {a.hostname}
                  </button>
                ))}
              </div>
            )}
            {assetId && <div className="text-[10.5px] text-emerald-400 mt-1">Attributed to {assetQuery}</div>}
          </div>

          <div className="flex gap-2">
            <button onClick={submit} disabled={busy || !file}
              className="h-10 px-4 text-[13px] bg-blue-500 hover:bg-blue-400 disabled:opacity-40 text-white rounded inline-flex items-center justify-center gap-2 flex-1">
              <UploadSimple size={16}/> {busy ? "Scanning…" : "Upload & Scan"}
            </button>
            <button onClick={runEicarTest} disabled={testBusy} type="button"
              title="Run a one-click smoke test with the standard (harmless) EICAR test string to confirm the pipeline works"
              className="h-10 px-4 text-[13px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 disabled:opacity-40 text-slate-300 rounded inline-flex items-center justify-center gap-2">
              <Flask size={16}/> {testBusy ? "Running…" : "Run test scan (EICAR)"}
            </button>
          </div>

          {result && (
            <div>
              <div className="border border-emerald-500/30 bg-emerald-500/5 rounded-md p-3.5 text-[12.5px] text-emerald-200 mb-3 space-y-1">
                <div className="flex items-center gap-1.5"><CheckCircle size={14}/> {result.rules_checked} rule(s) checked</div>
                <div>{result.matched_rule_count} match(es) · {result.findings_created} new finding(s) created</div>
                {result.rules_broken?.length > 0 && (
                  <div className="text-amber-300">{result.rules_broken.length} enabled rule(s) skipped — compile error, see Rules tab</div>
                )}
                {result.findings_created > 0 && (
                  <Link to="/findings?source_tool=YARA" className="inline-flex items-center gap-1 text-blue-300 hover:text-blue-200 mt-1">
                    <LinkSimple size={12}/> View YARA finding(s) in Findings
                  </Link>
                )}
              </div>
              <MatchList matches={result.matches}/>
            </div>
          )}
        </div>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md max-w-3xl">
        <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">Scan History</h3></div>
        {history.length === 0 ? (
          <div className="p-5 text-center text-[12.5px] text-slate-500">No scans yet.</div>
        ) : (
          <div className="divide-y divide-[#30363D]">
            {history.map(h => (
              <button key={h.id} onClick={() => openDetail(h.id)}
                className="w-full px-4 py-3 flex items-center justify-between gap-3 hover:bg-[#161B22] transition-colors text-left">
                <div className="flex items-center gap-2 min-w-0">
                  <Virus size={14} className="text-slate-500 shrink-0"/>
                  <div className="min-w-0">
                    <div className="text-[12.5px] text-slate-200 truncate">{h.label || h.filename}</div>
                    <div className="text-[10.5px] text-slate-500 font-mono">{h.filename} · {new Date(h.scanned_at).toLocaleString()}</div>
                  </div>
                </div>
                <div className="text-[11px] text-slate-400 shrink-0">
                  {h.matched_rule_count} match(es) · {h.findings_created} new
                </div>
              </button>
            ))}
          </div>
        )}
      </div>

      {detail && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={() => setDetail(null)}>
          <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-xl max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
              <div className="text-[14px] text-slate-100 font-medium truncate">{detail.label || detail.filename}</div>
              <button onClick={() => setDetail(null)} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
            </div>
            <div className="p-5">
              <div className="text-[10.5px] text-slate-500 font-mono mb-3">
                sha256: {detail.sha256} · {detail.size_bytes} bytes · {new Date(detail.scanned_at).toLocaleString()}
              </div>
              {detail.findings_created > 0 && (
                <Link to="/findings?source_tool=YARA" className="inline-flex items-center gap-1 text-[11.5px] text-blue-300 hover:text-blue-200 mb-3">
                  <LinkSimple size={12}/> View YARA finding(s) in Findings
                </Link>
              )}
              <MatchList matches={detail.matches}/>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function RuleModal({ initial, isEdit, onClose, onSaved }) {
  const [form, setForm] = useState({
    name: initial.name || "", description: initial.description || "",
    source: initial.source || "rule MyRule\n{\n    meta:\n        description = \"\"\n        severity = \"Medium\"\n    strings:\n        $s1 = \"suspicious string\"\n    condition:\n        $s1\n}\n",
    enabled: initial.enabled ?? true,
  });
  const [saving, setSaving] = useState(false);
  const [validation, setValidation] = useState(null);
  const [validating, setValidating] = useState(false);

  const validate = async () => {
    setValidating(true);
    try {
      const r = await api.post("/v1/admin/yara/rules/validate", { source: form.source });
      setValidation(r.data);
    } catch (e) {
      setValidation({ ok: false, error: "Validation request failed" });
    } finally { setValidating(false); }
  };

  const save = async () => {
    if (!form.name.trim()) { toast.error("Name is required"); return; }
    if (!form.source.trim()) { toast.error("Rule source is required"); return; }
    setSaving(true);
    try {
      if (isEdit) {
        await api.put(`/v1/admin/yara/rules/${initial.id}`, form);
      } else {
        await api.post("/v1/admin/yara/rules", form);
      }
      toast.success(isEdit ? "Rule updated" : "Rule created");
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Save failed");
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="text-[14px] text-slate-100 font-medium">{isEdit ? "Edit rule" : "New rule"}</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Name</label>
            <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100"/>
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Description (optional)</label>
            <input value={form.description} onChange={e => setForm({ ...form, description: e.target.value })}
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100"/>
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Rule source</label>
            <textarea value={form.source} onChange={e => { setForm({ ...form, source: e.target.value }); setValidation(null); }}
              rows={12}
              className="w-full bg-[#161B22] border border-[#30363D] rounded px-3 py-2 text-[11.5px] text-slate-100 font-mono resize-y"/>
            <div className="flex items-center gap-2 mt-1.5">
              <button type="button" onClick={validate} disabled={validating}
                className="h-7 px-2.5 text-[11px] border border-[#30363D] hover:border-[#484F58] rounded text-slate-300 inline-flex items-center gap-1.5">
                {validating ? <CircleNotch size={12} className="animate-spin"/> : null} Validate
              </button>
              {validation && (
                validation.ok
                  ? <span className="text-[11px] text-emerald-400 inline-flex items-center gap-1"><CheckCircle size={13}/> Compiles cleanly</span>
                  : <span className="text-[11px] text-red-400 inline-flex items-center gap-1"><Warning size={13}/> {validation.error}</span>
              )}
            </div>
          </div>
          <label className="flex items-center gap-2 text-[12px] text-slate-300 cursor-pointer">
            <input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })}/>
            Enabled — included in scans
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

function RulesTab() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState(null);

  const load = async () => {
    try {
      const r = await api.get("/v1/admin/yara/rules");
      setRules(r.data.items || []);
    } catch (e) {
      toast.error("Failed to load rules");
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const toggleEnabled = async (r) => {
    try {
      await api.put(`/v1/admin/yara/rules/${r.id}`, { ...r, enabled: !r.enabled });
      load();
    } catch (e) { toast.error("Update failed"); }
  };

  const remove = async (r) => {
    if (!window.confirm(`Delete rule "${r.name}"?`)) return;
    try {
      await api.delete(`/v1/admin/yara/rules/${r.id}`);
      toast.success("Deleted");
      load();
    } catch (e) { toast.error("Delete failed"); }
  };

  return (
    <div>
      <div className="flex justify-end mb-3">
        <button onClick={() => { setEditing(null); setModalOpen(true); }}
          className="h-9 px-3.5 text-[12.5px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
          <Plus size={15}/> New rule
        </button>
      </div>

      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : rules.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No rules yet.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D] max-w-3xl">
          {rules.map(r => (
            <div key={r.id} className="px-4 py-3 flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[12.5px] text-slate-200 font-medium">{r.name}</span>
                  {!r.enabled && <Chip color="slate">Disabled</Chip>}
                  {r.valid === false && (
                    <span title={r.compile_error} className="inline-flex items-center gap-1 text-[11px] text-red-400">
                      <Warning size={12}/> Won't compile
                    </span>
                  )}
                </div>
                {r.description && <div className="text-[11px] text-slate-500 mt-0.5">{r.description}</div>}
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <button onClick={() => toggleEnabled(r)} title={r.enabled ? "Disable" : "Enable"}
                  className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-slate-200 rounded border border-[#30363D]">
                  {r.enabled ? <CheckCircle size={14}/> : <XCircle size={14}/>}
                </button>
                <button onClick={() => { setEditing(r); setModalOpen(true); }}
                  className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-slate-200 rounded border border-[#30363D]">
                  <PencilSimple size={14}/>
                </button>
                <button onClick={() => remove(r)} className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-red-400 rounded border border-[#30363D]">
                  <Trash size={14}/>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {modalOpen && (
        <RuleModal
          initial={editing || {}}
          isEdit={!!editing}
          onClose={() => setModalOpen(false)}
          onSaved={() => { setModalOpen(false); load(); }}
        />
      )}
    </div>
  );
}
