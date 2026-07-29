import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  HardDrive, CloudArrowDown, CloudArrowUp, Trash, Warning, CircleNotch,
  Cloud, ShieldCheck,
} from "@phosphor-icons/react";

function fmtBytes(n) {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function verifiedChip(b) {
  if (b.verified == null) return null;
  if (b.verified) return <Chip color="green">Verified</Chip>;
  return <Chip color="red">Verification failed</Chip>;
}

function offsiteChip(b) {
  if (!b.offsite_attempted) return <Chip color="slate">Local only</Chip>;
  if (b.offsite_ok) return <Chip color="green">Off-site ✓</Chip>;
  return <Chip color="orange">Off-site failed</Chip>;
}

export default function Backups() {
  // Item 34 -- live database size, so "how big is the thing I'm backing up, and
  // will the next one fit" is answerable without shelling into the container.
  const [dbSize, setDbSize] = useState(null);
  const loadDbSize = () => api.get("/v1/admin/backups/db-size").then(r => setDbSize(r.data)).catch(() => {});
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [confirmText, setConfirmText] = useState("");
  const [restoreFile, setRestoreFile] = useState(null);
  const [offsiteStatus, setOffsiteStatus] = useState(null);
  const [busyIds, setBusyIds] = useState(new Set());
  const fileRef = useRef(null);

  const load = async () => {
    try {
      const r = await api.get("/v1/admin/backups");
      setItems(r.data.items || []);
    } catch (e) {
      toast.error("Failed to load backups");
    } finally { setLoading(false); }
  };

  const loadOffsiteStatus = async () => {
    try {
      const r = await api.get("/v1/admin/backups/offsite-status");
      setOffsiteStatus(r.data);
    } catch (e) { /* non-critical */ }
  };

  useEffect(() => { load(); loadOffsiteStatus(); loadDbSize(); }, []);

  const createNow = async () => {
    setCreating(true);
    try {
      const r = await api.post("/v1/admin/backups", {});
      const bits = [`${r.data.documents} document(s)`, fmtBytes(r.data.size_bytes)];
      bits.push(r.data.verified ? "verified ✓" : "verification FAILED");
      if (r.data.offsite_attempted) bits.push(r.data.offsite_ok ? "off-site ✓" : "off-site upload failed");
      toast.success(`Backup created: ${bits.join(", ")}`);
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Backup failed");
    } finally { setCreating(false); }
  };

  const download = async (b) => {
    try {
      const r = await api.get(`/v1/admin/backups/${b.id}/download`, { responseType: "blob" });
      const url = window.URL.createObjectURL(new Blob([r.data]));
      const a = document.createElement("a"); a.href = url; a.download = b.filename; a.click();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      toast.error("Download failed — the file may have been pruned");
    }
  };

  const remove = async (b) => {
    if (!window.confirm(`Delete backup "${b.filename}"? This can't be undone.`)) return;
    try {
      await api.delete(`/v1/admin/backups/${b.id}`);
      toast.success("Deleted");
      load();
    } catch (e) { toast.error("Delete failed"); }
  };

  const verifyNow = async (b) => {
    setBusyIds(prev => new Set(prev).add(b.id));
    try {
      const r = await api.post(`/v1/admin/backups/${b.id}/verify`);
      toast[r.data.valid ? "success" : "error"](r.data.valid ? "Backup verified intact" : `Verification failed: ${r.data.error}`);
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Verification failed");
    } finally {
      setBusyIds(prev => { const n = new Set(prev); n.delete(b.id); return n; });
    }
  };

  const uploadOffsite = async (b) => {
    setBusyIds(prev => new Set(prev).add(b.id));
    try {
      const r = await api.post(`/v1/admin/backups/${b.id}/upload-offsite`);
      toast[r.data.ok ? "success" : "error"](r.data.ok ? `Uploaded to ${r.data.bucket}` : `Off-site upload failed: ${r.data.error}`);
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Off-site upload failed");
    } finally {
      setBusyIds(prev => { const n = new Set(prev); n.delete(b.id); return n; });
    }
  };

  const restore = async () => {
    if (!restoreFile) { toast.error("Choose a backup file first"); return; }
    if (confirmText !== "RESTORE") { toast.error("Type RESTORE (all caps) to confirm"); return; }
    setRestoring(true);
    try {
      const fd = new FormData();
      fd.append("file", restoreFile);
      fd.append("confirm", confirmText);
      const r = await api.post("/v1/admin/backups/restore", fd, { headers: { "Content-Type": "multipart/form-data" } });
      toast.success(`Restored ${r.data.documents_restored} document(s) across ${r.data.collections_restored} collection(s)`);
      setRestoreFile(null); setConfirmText("");
      if (fileRef.current) fileRef.current.value = "";
    } catch (e) {
      toast.error(e.response?.data?.detail || "Restore failed");
    } finally { setRestoring(false); }
  };

  return (
    <Layout title="Backups" subtitle="Manual and scheduled database backups — the container itself is disposable, this is what isn't">
      {dbSize && <DbSizePanel data={dbSize} onRefresh={loadDbSize}/>}

      <div className="grid grid-cols-2 gap-5 max-w-5xl mb-5">
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-5">
          <div className="flex items-center gap-2 mb-3">
            <HardDrive size={18} className="text-slate-300"/>
            <div className="text-[14px] text-slate-100 font-medium">Create Backup</div>
          </div>
          <p className="text-[12px] text-slate-500 mb-4 leading-relaxed">
            Dumps every collection to a single file, stored on the <code className="font-mono">vulnops_backups</code> volume
            so it survives container restarts. Set <code className="font-mono">BACKUP_SCHEDULE_ENABLED=true</code> in your
            .env to also run this nightly (last 14 kept automatically). Every backup is automatically integrity-checked
            and, when off-site storage is configured below, uploaded there too.
          </p>
          <button onClick={createNow} disabled={creating}
            className="h-9 px-4 text-[12.5px] bg-blue-500 hover:bg-blue-400 disabled:opacity-40 text-white rounded inline-flex items-center gap-1.5">
            {creating ? <CircleNotch size={15} className="animate-spin"/> : <CloudArrowUp size={15}/>} Backup now
          </button>
        </div>

        <div className="border border-red-500/30 bg-red-500/5 rounded-md p-5">
          <div className="flex items-center gap-2 mb-3">
            <Warning size={18} className="text-red-400"/>
            <div className="text-[14px] text-red-200 font-medium">Restore (Destructive)</div>
          </div>
          <p className="text-[12px] text-red-200/80 mb-3 leading-relaxed">
            Replaces every current collection's contents with what's in the chosen backup file. There's no undo —
            take a fresh backup first if you want to keep current data around.
          </p>
          <input ref={fileRef} type="file" accept=".gz" onChange={(e) => setRestoreFile(e.target.files?.[0] || null)}
            className="w-full text-[11.5px] text-slate-300 mb-2.5"/>
          <input value={confirmText} onChange={(e) => setConfirmText(e.target.value)}
            placeholder="Type RESTORE to confirm"
            className="w-full h-9 bg-[#161B22] border border-red-500/30 rounded px-3 text-[12.5px] text-slate-100 mb-2.5"/>
          <button onClick={restore} disabled={restoring || !restoreFile}
            className="h-9 px-4 text-[12.5px] bg-red-500 hover:bg-red-400 disabled:opacity-40 text-white rounded inline-flex items-center gap-1.5">
            {restoring ? <CircleNotch size={15} className="animate-spin"/> : <CloudArrowDown size={15}/>} Restore from file
          </button>
        </div>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-5 max-w-5xl mb-5">
        <div className="flex items-center gap-2 mb-2">
          <Cloud size={17} className="text-slate-300"/>
          <div className="text-[13.5px] text-slate-100 font-medium">Off-Site Destination</div>
          {offsiteStatus && (offsiteStatus.configured
            ? <Chip color="green">Configured</Chip>
            : <Chip color="slate">Not configured</Chip>)}
        </div>
        {offsiteStatus?.configured ? (
          <div className="text-[12px] text-slate-500 leading-relaxed">
            Uploading to bucket <span className="font-mono text-slate-300">{offsiteStatus.bucket}</span>
            {offsiteStatus.endpoint_url && <> via <span className="font-mono text-slate-300">{offsiteStatus.endpoint_url}</span></>}
            , under prefix <span className="font-mono text-slate-300">{offsiteStatus.prefix}</span>. Every new backup
            is uploaded here automatically in addition to the local copy.
          </div>
        ) : (
          <div className="text-[12px] text-slate-500 leading-relaxed">
            No off-site destination configured — backups only exist on this host's <code className="font-mono">vulnops_backups</code> volume.
            Set <code className="font-mono">BACKUP_S3_BUCKET</code> (plus <code className="font-mono">BACKUP_S3_ENDPOINT_URL</code>,{" "}
            <code className="font-mono">BACKUP_S3_ACCESS_KEY_ID</code>, <code className="font-mono">BACKUP_S3_SECRET_ACCESS_KEY</code>{" "}
            for any S3-compatible provider — AWS S3, MinIO, Backblaze B2, Wasabi, etc.) in your .env to enable it.
          </div>
        )}
      </div>

      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No backups yet. Click "Backup now" above to create one.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D] max-w-5xl">
          {items.map(b => (
            <div key={b.id} className="px-4 py-3 flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[12.5px] text-slate-200 font-mono">{b.filename}</span>
                  {b.label && <Chip color="slate">{b.label}</Chip>}
                  {!b.file_exists && <Chip color="red">File missing on disk</Chip>}
                  {verifiedChip(b)}
                  {offsiteChip(b)}
                </div>
                <div className="text-[11px] text-slate-500 mt-1">
                  {new Date(b.created_at).toLocaleString()} · {b.documents} document(s) · {b.collections} collection(s) · {fmtBytes(b.size_bytes)}
                  {b.verification_error && <span className="text-red-400"> · {b.verification_error}</span>}
                  {b.offsite_error && <span className="text-orange-400"> · off-site: {b.offsite_error}</span>}
                </div>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <button onClick={() => verifyNow(b)} disabled={!b.file_exists || busyIds.has(b.id)} title="Re-verify"
                  className="h-8 px-2.5 text-[11.5px] bg-emerald-500/10 hover:bg-emerald-500/20 disabled:opacity-40 text-emerald-300 rounded inline-flex items-center gap-1.5 border border-emerald-500/30">
                  {busyIds.has(b.id) ? <CircleNotch size={13} className="animate-spin"/> : <ShieldCheck size={13}/>} Verify
                </button>
                <button onClick={() => uploadOffsite(b)} disabled={!b.file_exists || busyIds.has(b.id) || !offsiteStatus?.configured}
                  title={offsiteStatus?.configured ? "Upload to off-site storage" : "Configure BACKUP_S3_BUCKET to enable"}
                  className="h-8 px-2.5 text-[11.5px] bg-blue-500/10 hover:bg-blue-500/20 disabled:opacity-40 text-blue-300 rounded inline-flex items-center gap-1.5 border border-blue-500/30">
                  <Cloud size={13}/> Off-site
                </button>
                <button onClick={() => download(b)} disabled={!b.file_exists}
                  className="h-8 px-2.5 text-[11.5px] bg-blue-500/10 hover:bg-blue-500/20 disabled:opacity-40 text-blue-300 rounded inline-flex items-center gap-1.5 border border-blue-500/30">
                  <CloudArrowDown size={13}/> Download
                </button>
                <button onClick={() => remove(b)} className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-red-400 rounded border border-[#30363D]">
                  <Trash size={14}/>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </Layout>
  );
}


function DbSizePanel({ data, onRefresh }) {
  const [open, setOpen] = useState(false);
  const d = data.database || {};
  const v = data.backup_volume;
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-5 max-w-5xl mb-5">
      <div className="flex items-center justify-between mb-3">
        <div className="text-[14px] text-slate-100 font-medium">Current database</div>
        <button onClick={onRefresh} className="h-7 px-2.5 text-[11.5px] border border-[#30363D] hover:border-slate-500 text-slate-300 rounded">
          Refresh
        </button>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 mb-3">
        <Stat label="Documents" value={(d.document_count ?? 0).toLocaleString()}/>
        <Stat label="Collections" value={d.collection_count ?? 0}/>
        <Stat label="Data size" value={fmtBytes(d.data_size_bytes)}/>
        <Stat label="Total (data + indexes)" value={fmtBytes(d.total_size_bytes)}/>
      </div>
      {v && (
        <div className="border border-[#30363D] rounded p-3 mb-3">
          <div className="flex items-center justify-between text-[11.5px] mb-1.5">
            <span className="text-slate-400">Backup volume <code className="font-mono text-slate-500">{v.path}</code></span>
            <span className="text-slate-300">{fmtBytes(v.free_bytes)} free of {fmtBytes(v.total_bytes)}</span>
          </div>
          <div className="h-2 bg-slate-800 rounded overflow-hidden">
            <div className={`h-full ${v.used_pct > 90 ? "bg-red-500" : v.used_pct > 75 ? "bg-amber-500" : "bg-emerald-500"}`}
              style={{ width: `${v.used_pct ?? 0}%` }}/>
          </div>
          <div className="text-[10.5px] text-slate-500 mt-1">
            {v.backup_files} backup file(s) using {fmtBytes(v.backup_bytes)} · {v.used_pct}% of the volume used
          </div>
        </div>
      )}
      <button onClick={() => setOpen(!open)} className="text-[11.5px] text-blue-300 hover:underline">
        {open ? "Hide" : "Show"} per-collection breakdown ({(data.collections || []).length})
      </button>
      {open && (
        <div className="mt-2 max-h-64 overflow-y-auto border border-[#30363D] rounded">
          <table className="w-full text-[11.5px]">
            <thead>
              <tr className="text-left text-slate-500 border-b border-[#30363D]">
                <th className="px-3 py-1.5 font-medium">Collection</th>
                <th className="px-3 py-1.5 font-medium text-right">Documents</th>
                <th className="px-3 py-1.5 font-medium text-right">Size</th>
              </tr>
            </thead>
            <tbody>
              {(data.collections || []).map(c => (
                <tr key={c.name} className="border-b border-[#30363D] last:border-0">
                  <td className="px-3 py-1 font-mono text-slate-300">{c.name}</td>
                  <td className="px-3 py-1 text-right text-slate-400">{c.documents.toLocaleString()}</td>
                  <td className="px-3 py-1 text-right text-slate-400">{fmtBytes(c.size_bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {d.source === "counted" && (
        <div className="text-[10.5px] text-slate-600 mt-2">
          Byte-level sizes unavailable from this MongoDB deployment — document and collection counts are exact.
        </div>
      )}
    </div>
  );
}

function Stat({ label, value }) {
  return (
    <div className="border border-[#30363D] bg-[#161B22] rounded px-3 py-2">
      <div className="text-[10px] text-slate-500 uppercase tracking-wider">{label}</div>
      <div className="text-[16px] text-slate-100 font-semibold mt-0.5">{value}</div>
    </div>
  );
}
