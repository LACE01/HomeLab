import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  Plus, X, Trash, PencilSimple, ArrowsClockwise, Cube, CheckCircle, XCircle,
  CircleNotch, WarningCircle,
} from "@phosphor-icons/react";

function statusChip(t) {
  const latest = t.latest;
  if (!latest) return <Chip color="slate">Not scanned yet</Chip>;
  if (latest.error) return <Chip color="red">Scan failed</Chip>;
  const created = latest.findings_created || 0;
  if (created > 0) return <Chip color="orange">{created} new finding{created > 1 ? "s" : ""}</Chip>;
  return <Chip color="green">No new findings</Chip>;
}

const EMPTY_FORM = { image_ref: "", label: "", enabled: true };

export default function ContainerScanning() {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState(null);
  const [scanningAll, setScanningAll] = useState(false);
  const [scanningIds, setScanningIds] = useState(new Set());
  const pollRef = useRef(null);

  const load = async () => {
    try {
      const r = await api.get("/v1/admin/container-scan/targets");
      setTargets(r.data.items || []);
    } catch (e) {
      toast.error("Failed to load container image watch targets");
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
      const r = await api.post(`/v1/admin/container-scan/targets/${t.id}/scan-now`);
      toast.success(`${t.image_ref}: ${r.data.components_parsed} package(s) scanned, ${r.data.findings_created} new finding(s)`);
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
      const r = await api.post("/v1/admin/container-scan/scan-all");
      toast.success(`Scanned ${r.data.scanned} image(s) — ${r.data.findings_created} new finding(s), ${r.data.failed} failed`);
      await load();
    } catch (e) {
      toast.error("Bulk scan failed");
    } finally { setScanningAll(false); }
  };

  const remove = async (t) => {
    if (!window.confirm(`Stop tracking "${t.image_ref}"?`)) return;
    try {
      await api.delete(`/v1/admin/container-scan/targets/${t.id}`);
      toast.success("Removed");
      load();
    } catch (e) {
      toast.error("Delete failed");
    }
  };

  const toggleEnabled = async (t) => {
    try {
      await api.put(`/v1/admin/container-scan/targets/${t.id}`, { ...t, enabled: !t.enabled });
      load();
    } catch (e) {
      toast.error("Update failed");
    }
  };

  return (
    <Layout title="Container Image Scanning" subtitle="Generates an SBOM for each watched image (Trivy) and matches it against OSV.dev -- same pipeline as manual SBOM uploads, just pointed at a registry instead of a file">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 mb-5 flex items-start gap-2.5">
        <WarningCircle size={16} className="text-slate-500 mt-0.5 shrink-0"/>
        <div className="text-[12px] text-slate-500 leading-relaxed">
          Images are pulled directly by Trivy from their registry (Docker Hub, GHCR, a private registry, etc.) --
          this never needs access to a local Docker daemon or docker.sock. Only package inventory is generated
          locally (no vulnerability database download); the actual CVE matching reuses the same OSV.dev lookup
          as manual SBOM uploads, so a package with no known purl-resolvable ecosystem (most RPM-based images,
          for example) won't be covered -- consistent with SBOM Upload's existing scope.
        </div>
      </div>

      <div className="flex justify-between items-center mb-3 flex-wrap gap-2">
        <button onClick={scanAll} disabled={scanningAll}
          className="h-9 px-3.5 text-[12.5px] bg-[#161B22] hover:bg-[#1c232c] disabled:opacity-40 text-slate-200 rounded inline-flex items-center gap-1.5 border border-[#30363D]">
          {scanningAll ? <CircleNotch size={15} className="animate-spin"/> : <ArrowsClockwise size={15}/>} Scan all now
        </button>
        <button onClick={() => { setEditing(null); setModalOpen(true); }}
          className="h-9 px-3.5 text-[12.5px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
          <Plus size={15}/> Watch an image
        </button>
      </div>

      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : targets.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No images being tracked yet. Add one (e.g. "nginx:1.25", "postgres:16", "ghcr.io/org/app:latest") to start scanning it.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
          {targets.map(t => (
            <div key={t.id} className="px-4 py-3 flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <Cube size={14} className="text-slate-500"/>
                  <span className="text-[13px] text-slate-100 font-mono">{t.image_ref}</span>
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
                        <span>{t.latest.components_parsed} package(s) inventoried</span>
                        <span>{t.latest.components_vulnerable} with known vulnerabilities</span>
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
        <ImageTargetModal
          initial={editing || EMPTY_FORM}
          isEdit={!!editing}
          onClose={() => setModalOpen(false)}
          onSaved={() => { setModalOpen(false); load(); }}
        />
      )}
    </Layout>
  );
}

function ImageTargetModal({ initial, isEdit, onClose, onSaved }) {
  const [form, setForm] = useState({
    image_ref: initial.image_ref || "", label: initial.label || "", enabled: initial.enabled ?? true,
  });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!form.image_ref.trim()) { toast.error("Image reference is required"); return; }
    setSaving(true);
    try {
      if (isEdit) {
        await api.put(`/v1/admin/container-scan/targets/${initial.id}`, form);
      } else {
        await api.post(`/v1/admin/container-scan/targets`, form);
      }
      toast.success(isEdit ? "Updated" : "Now tracking this image");
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Save failed");
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="text-[14px] text-slate-100 font-medium">{isEdit ? "Edit watch target" : "Watch an image"}</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Image Reference</label>
            <input value={form.image_ref} onChange={e => setForm({ ...form, image_ref: e.target.value })}
              placeholder="nginx:1.25 or ghcr.io/org/app:latest"
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100 font-mono"/>
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Label (optional)</label>
            <input value={form.label} onChange={e => setForm({ ...form, label: e.target.value })}
              placeholder="Reverse proxy" className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100"/>
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
