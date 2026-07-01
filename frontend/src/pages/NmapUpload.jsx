import { useState, useRef } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { UploadSimple, FileCode, Globe, House } from "@phosphor-icons/react";

export default function NmapUpload() {
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
    <Layout title="Nmap Scan Upload" subtitle="Upload nmap -oX output — enriches assets with open ports/services and can verify exposure or flag risky ports">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-5 max-w-3xl">
        <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3 py-2.5 mb-4 text-[12px] text-blue-200 leading-relaxed">
          This is a passive import — VulnOps never scans anything itself. Run the scan yourself
          (or on a schedule you control) with something like{" "}
          <code className="font-mono text-[11px] bg-black/30 px-1 py-0.5 rounded">nmap -sV -O -oX scan.xml &lt;targets&gt;</code>{" "}
          and upload the XML here.
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
    </Layout>
  );
}
