import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { HardDrive, CloudArrowDown, CloudArrowUp, Trash, Warning, CircleNotch } from "@phosphor-icons/react";

function fmtBytes(n) {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export default function Backups() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [confirmText, setConfirmText] = useState("");
  const [restoreFile, setRestoreFile] = useState(null);
  const fileRef = useRef(null);

  const load = async () => {
    try {
      const r = await api.get("/v1/admin/backups");
      setItems(r.data.items || []);
    } catch (e) {
      toast.error("Failed to load backups");
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const createNow = async () => {
    setCreating(true);
    try {
      const r = await api.post("/v1/admin/backups", {});
      toast.success(`Backup created: ${r.data.documents} document(s), ${fmtBytes(r.data.size_bytes)}`);
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
      <div className="grid grid-cols-2 gap-5 max-w-5xl mb-5">
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-5">
          <div className="flex items-center gap-2 mb-3">
            <HardDrive size={18} className="text-slate-300"/>
            <div className="text-[14px] text-slate-100 font-medium">Create Backup</div>
          </div>
          <p className="text-[12px] text-slate-500 mb-4 leading-relaxed">
            Dumps every collection to a single file, stored on the <code className="font-mono">vulnops_backups</code> volume
            so it survives container restarts. Set <code className="font-mono">BACKUP_SCHEDULE_ENABLED=true</code> in your
            .env to also run this nightly (last 14 kept automatically).
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
                </div>
                <div className="text-[11px] text-slate-500 mt-1">
                  {new Date(b.created_at).toLocaleString()} · {b.documents} document(s) · {b.collections} collection(s) · {fmtBytes(b.size_bytes)}
                </div>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
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
