import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  Plus, X, Trash, PencilSimple, ArrowsClockwise, Key, CheckCircle, XCircle,
  CircleNotch, WarningCircle,
} from "@phosphor-icons/react";

function statusChip(t) {
  const latest = t.latest;
  if (!latest) return <Chip color="slate">Not scanned yet</Chip>;
  if (latest.error) return <Chip color="red">Scan failed</Chip>;
  const found = latest.secrets_found || 0;
  if (found > 0) return <Chip color="red">{found} possible secret{found > 1 ? "s" : ""}</Chip>;
  return <Chip color="green">Clean</Chip>;
}

const EMPTY_FORM = { repo_url: "", branch: "", token: "", label: "", enabled: true };

export default function SecretsScanning() {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState(null);
  const [scanningAll, setScanningAll] = useState(false);
  const [scanningIds, setScanningIds] = useState(new Set());
  const pollRef = useRef(null);

  const load = async () => {
    try {
      const r = await api.get("/v1/admin/secrets-scan/targets");
      setTargets(r.data.items || []);
    } catch (e) {
      toast.error("Failed to load repository watch targets");
    } finally { setLoading(false); }
  };

  useEffect(() => {
    load();
    pollRef.current = setInterval(load, 20000);
    return () => clearInterval(pollRef.current);
  }, []);

  const scanNow = async (t) => {
    setScanningIds(prev => new Set(prev).add(t.id));
    try {
      const r = await api.post(`/v1/admin/secrets-scan/targets/${t.id}/scan-now`);
      toast.success(`${t.repo_url}: ${r.data.secrets_found} possible secret(s), ${r.data.findings_created} new finding(s)`);
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Scan failed");
    } finally {
      setScanningIds(prev => { const n = new Set(prev); n.delete(t.id); return n; });
    }
  };

  const scanAll = async () => {
    setScanningAll(true);
    try {
      const r = await api.post("/v1/admin/secrets-scan/scan-all");
      toast.success(`Scanned ${r.data.scanned} repo(s) — ${r.data.findings_created} new finding(s), ${r.data.failed} failed`);
      await load();
    } catch (e) {
      toast.error("Bulk scan failed");
    } finally { setScanningAll(false); }
  };

  const remove = async (t) => {
    if (!window.confirm(`Stop tracking "${t.repo_url}"?`)) return;
    try {
      await api.delete(`/v1/admin/secrets-scan/targets/${t.id}`);
      toast.success("Removed");
      load();
    } catch (e) {
      toast.error("Delete failed");
    }
  };

  const toggleEnabled = async (t) => {
    try {
      await api.put(`/v1/admin/secrets-scan/targets/${t.id}`, { ...t, enabled: !t.enabled });
      load();
    } catch (e) {
      toast.error("Update failed");
    }
  };

  return (
    <Layout title="Secrets Scanning" subtitle="Scans git repositories for hardcoded credentials (detect-secrets) -- the actual value is never stored, only a one-way hash used to dedup findings">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 mb-5 flex items-start gap-2.5">
        <WarningCircle size={16} className="text-slate-500 mt-0.5 shrink-0"/>
        <div className="text-[12px] text-slate-500 leading-relaxed">
          Each scan shallow-clones the current state of one branch and checks it -- not the repo's full commit
          history. A secret that was committed and later removed in a subsequent commit won't be caught by this.
          For a private repo, add an access token (a fine-grained, read-only PAT is enough); it's stored to allow
          scheduled re-scans and is masked everywhere it's displayed.
        </div>
      </div>

      <div className="flex justify-between items-center mb-3 flex-wrap gap-2">
        <button onClick={scanAll} disabled={scanningAll}
          className="h-9 px-3.5 text-[12.5px] bg-[#161B22] hover:bg-[#1c232c] disabled:opacity-40 text-slate-200 rounded inline-flex items-center gap-1.5 border border-[#30363D]">
          {scanningAll ? <CircleNotch size={15} className="animate-spin"/> : <ArrowsClockwise size={15}/>} Scan all now
        </button>
        <button onClick={() => { setEditing(null); setModalOpen(true); }}
          className="h-9 px-3.5 text-[12.5px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
          <Plus size={15}/> Watch a repository
        </button>
      </div>

      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : targets.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No repositories being tracked yet. Add one to start scanning it for hardcoded credentials.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
          {targets.map(t => (
            <div key={t.id} className="px-4 py-3 flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <Key size={14} className="text-slate-500"/>
                  <span className="text-[13px] text-slate-100 font-mono">{t.repo_url}</span>
                  {t.branch && <span className="text-[11px] text-slate-500 font-mono">@{t.branch}</span>}
                  {t.label && <span className="text-[11.5px] text-slate-500">{t.label}</span>}
                  {statusChip(t)}
                  {!t.enabled && <Chip color="slate">Disabled</Chip>}
                </div>
                {t.latest && (
                  <div className="flex items-center gap-3 mt-1.5 text-[11px] text-slate-500 flex-wrap">
                    {t.latest.error ? (
                      <span className="text-red-400">{t.latest.error}</span>
                    ) : (
                      <>
                        <span>{t.latest.secrets_found} possible secret(s)</span>
                        <span>Last scanned {t.latest.scanned_at && new Date(t.latest.scanned_at).toLocaleString()}</span>
                      </>
                    )}
                  </div>
                )}
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <button onClick={() => scanNow(t)} disabled={scanningIds.has(t.id)}
                  className="h-8 px-2.5 text-[11.5px] bg-blue-500/10 hover:bg-blue-500/20 disabled:opacity-40 text-blue-300 rounded inline-flex items-center gap-1.5 border border-blue-500/30">
                  {scanningIds.has(t.id) ? <CircleNotch size={12} className="animate-spin"/> : <ArrowsClockwise size={12}/>} Scan now
                </button>
                <button onClick={() => toggleEnabled(t)} title={t.enabled ? "Disable" : "Enable"}
                  className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-slate-200 rounded border border-[#30363D]">
                  {t.enabled ? <CheckCircle size={14}/> : <XCircle size={14}/>}
                </button>
                <button onClick={() => { setEditing(t); setModalOpen(true); }}
                  className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-slate-200 rounded border border-[#30363D]">
                  <PencilSimple size={14}/>
                </button>
                <button onClick={() => remove(t)}
                  className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-red-400 rounded border border-[#30363D]">
                  <Trash size={14}/>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {modalOpen && (
        <RepoTargetModal
          initial={editing || EMPTY_FORM}
          isEdit={!!editing}
          onClose={() => setModalOpen(false)}
          onSaved={() => { setModalOpen(false); load(); }}
        />
      )}
    </Layout>
  );
}

function RepoTargetModal({ initial, isEdit, onClose, onSaved }) {
  const [form, setForm] = useState({
    repo_url: initial.repo_url || "", branch: initial.branch || "",
    token: initial.token || "", label: initial.label || "", enabled: initial.enabled ?? true,
  });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!form.repo_url.trim()) { toast.error("Repository URL is required"); return; }
    setSaving(true);
    try {
      const body = { ...form, branch: form.branch || null, token: form.token || null };
      if (isEdit) {
        await api.put(`/v1/admin/secrets-scan/targets/${initial.id}`, body);
      } else {
        await api.post(`/v1/admin/secrets-scan/targets`, body);
      }
      toast.success(isEdit ? "Updated" : "Now tracking this repository");
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Save failed");
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="text-[14px] text-slate-100 font-medium">{isEdit ? "Edit watch target" : "Watch a repository"}</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Repository URL</label>
            <input value={form.repo_url} onChange={e => setForm({ ...form, repo_url: e.target.value })}
              placeholder="https://github.com/org/repo.git"
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100 font-mono"/>
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Branch (optional)</label>
            <input value={form.branch} onChange={e => setForm({ ...form, branch: e.target.value })}
              placeholder="main (defaults to the repo's default branch)"
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100 font-mono"/>
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Access Token (optional, for private repos)</label>
            <input type="password" value={form.token} onChange={e => setForm({ ...form, token: e.target.value })}
              placeholder={isEdit ? "•••• (leave as-is to keep current token)" : "read-only PAT"}
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100 font-mono"/>
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Label (optional)</label>
            <input value={form.label} onChange={e => setForm({ ...form, label: e.target.value })}
              placeholder="Internal API service" className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100"/>
          </div>
        </div>
        <div className="flex justify-end gap-2 px-5 py-3.5 border-t border-[#30363D]">
          <button onClick={onClose} className="h-9 px-3.5 text-[12.5px] text-slate-400 hover:text-slate-200 rounded">Cancel</button>
          <button onClick={save} disabled={saving}
            className="h-9 px-4 text-[12.5px] bg-blue-500 hover:bg-blue-400 disabled:opacity-40 text-white rounded">
            {saving ? "Saving…" : isEdit ? "Save changes" : "Add"}
          </button>
        </div>
      </div>
    </div>
  );
}
