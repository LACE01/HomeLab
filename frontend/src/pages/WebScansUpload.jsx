import { useState, useRef } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { UploadSimple, FileXls, CheckCircle, Warning } from "@phosphor-icons/react";

export default function WebScansUpload() {
  const fileRef = useRef(null);
  const [file, setFile] = useState(null);
  const [label, setLabel] = useState(`CISA Web Scan ${new Date().toISOString().slice(0,10)}`);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  const submit = async () => {
    if (!file) { toast.error("Pick an XLSX file first"); return; }
    setBusy(true); setResult(null);
    try {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("label", label);
      const r = await api.post("/v1/admin/web-scans/upload", fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setResult(r.data);
      toast.success(`Imported: ${r.data.created} new · ${r.data.updated} updated · ${r.data.web_apps} web apps`);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Upload failed");
    } finally { setBusy(false); }
  };

  return (
    <Layout title="Web Scan Uploads" subtitle="Upload CISA Qualys WAS XLSX reports — dedup is automatic by VULN_ID + URL">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-5 max-w-3xl">
        <div className="grid grid-cols-1 gap-4">
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Source label (for history)</label>
            <input
              data-testid="ws-label"
              value={label}
              onChange={(e)=>setLabel(e.target.value)}
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100"
            />
          </div>

          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">XLSX File</label>
            <div className="border-2 border-dashed border-[#30363D] hover:border-blue-500/40 rounded-md p-6 text-center cursor-pointer transition-colors"
                 onClick={()=>fileRef.current?.click()}>
              <input
                data-testid="ws-file"
                ref={fileRef}
                type="file"
                accept=".xlsx"
                onChange={(e)=>setFile(e.target.files?.[0] || null)}
                className="hidden"
              />
              <FileXls size={36} className="text-slate-500 mx-auto mb-2"/>
              {file ? (
                <>
                  <div className="text-[13px] text-slate-200 font-mono">{file.name}</div>
                  <div className="text-[11px] text-slate-500 mt-1">{(file.size/1024).toFixed(1)} KB · Click to change</div>
                </>
              ) : (
                <>
                  <div className="text-[13px] text-slate-300">Click to choose an XLSX file</div>
                  <div className="text-[11px] text-slate-500 mt-1">Expected columns: VULN_ID, NAME, SEVERITY, CWE, CVE, WEB APPLICATION, URL, DESCRIPTION, IMPACT, SOLUTION…</div>
                </>
              )}
            </div>
          </div>

          <button
            data-testid="ws-submit"
            onClick={submit}
            disabled={busy || !file}
            className="h-10 px-4 text-[13px] bg-blue-500 hover:bg-blue-400 disabled:opacity-40 text-white rounded inline-flex items-center justify-center gap-2"
          >
            <UploadSimple size={16}/> {busy ? "Importing…" : "Upload & Ingest"}
          </button>

          {result && (
            <div data-testid="ws-result" className="border border-emerald-500/30 bg-emerald-500/5 rounded-md p-3 text-[12.5px]">
              <div className="text-emerald-300 font-medium mb-2 inline-flex items-center gap-1.5"><CheckCircle size={14}/> Import complete</div>
              <div className="grid grid-cols-3 gap-3 font-mono text-[12px]">
                <div><span className="text-slate-500">Created:</span> <span className="text-emerald-300">{result.created}</span></div>
                <div><span className="text-slate-500">Updated:</span> <span className="text-amber-300">{result.updated}</span></div>
                <div><span className="text-slate-500">Web apps:</span> <span className="text-blue-300">{result.web_apps}</span></div>
              </div>
              {result.errors?.length > 0 && (
                <div className="mt-3 text-[11px] text-amber-300 inline-flex items-center gap-1"><Warning size={12}/> {result.errors.length} row{result.errors.length===1?"":"s"} had errors (see Recent Imports panel)</div>
              )}
            </div>
          )}
        </div>

        <div className="mt-6 text-[11.5px] text-slate-500 leading-relaxed">
          Re-uploads are safe — same VULN_ID + Web App + URL is updated in-place. New entries are added with severity-based SLA, marked as <strong className="text-slate-300">internet-facing</strong>, and visible under Findings filtered by source <span className="font-mono text-slate-300">CISA Web Scan (Qualys WAS)</span>.
        </div>
      </div>
    </Layout>
  );
}
