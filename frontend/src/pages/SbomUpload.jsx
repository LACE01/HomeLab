import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Package, FileCode, UploadSimple, CheckCircle, Flask, LinkSimple, DownloadSimple } from "@phosphor-icons/react";

// A minimal, valid CycloneDX SBOM containing one real, known-vulnerable package
// (lodash 4.17.15, prototype pollution -- CVE-2020-8203) so a first-time user can
// see the whole upload -> OSV.dev match -> finding-created pipeline work without
// needing to generate a real SBOM first.
const SAMPLE_SBOM = {
  bomFormat: "CycloneDX", specVersion: "1.4", version: 1,
  components: [
    { type: "library", name: "lodash", version: "4.17.15", purl: "pkg:npm/lodash@4.17.15" },
    { type: "library", name: "express", version: "4.17.1", purl: "pkg:npm/express@4.17.1" },
  ],
};

export default function SbomUpload() {
  const fileRef = useRef(null);
  const [file, setFile] = useState(null);
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [testBusy, setTestBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);

  const loadHistory = async () => {
    try {
      const r = await api.get("/v1/admin/sbom/uploads");
      setHistory(r.data.items || []);
    } catch (e) { /* non-fatal */ }
  };

  useEffect(() => { loadHistory(); }, []);

  const runUpload = async (uploadFile, uploadLabel) => {
    setResult(null);
    const fd = new FormData();
    fd.append("file", uploadFile);
    fd.append("label", uploadLabel || "");
    const r = await api.post("/v1/admin/sbom/upload", fd, {
      headers: { "Content-Type": "multipart/form-data" },
    });
    setResult(r.data);
    toast.success(`${r.data.components_vulnerable} vulnerable component(s), ${r.data.findings_created} new finding(s)`);
    loadHistory();
  };

  const submit = async () => {
    if (!file) { toast.error("Pick a CycloneDX or SPDX JSON file first"); return; }
    setBusy(true);
    try {
      await runUpload(file, label);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Upload failed");
    } finally { setBusy(false); }
  };

  // One-click pipeline smoke test with a real (harmless) known-vulnerable package,
  // same idea as the YARA tab's EICAR button -- proves upload -> OSV.dev lookup ->
  // finding-created works before a real SBOM is on hand.
  const runSampleTest = async () => {
    setTestBusy(true);
    try {
      const blob = new Blob([JSON.stringify(SAMPLE_SBOM, null, 2)], { type: "application/json" });
      const sampleFile = new File([blob], "sample-sbom.cdx.json", { type: "application/json" });
      await runUpload(sampleFile, "Built-in sample SBOM pipeline test");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Test scan failed");
    } finally { setTestBusy(false); }
  };

  const downloadSample = () => {
    const blob = new Blob([JSON.stringify(SAMPLE_SBOM, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "sample-sbom.cdx.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Layout title="SBOM / Dependency Scanning" subtitle="Upload a CycloneDX or SPDX SBOM — matched against OSV.dev for known-vulnerable dependencies">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-5 max-w-3xl mb-5">
        <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3 py-2.5 mb-4 text-[12px] text-blue-200 leading-relaxed">
          Generate an SBOM with something like <code className="font-mono text-[11px] bg-black/30 px-1 py-0.5 rounded">syft . -o cyclonedx-json</code>,{" "}
          <code className="font-mono text-[11px] bg-black/30 px-1 py-0.5 rounded">npm sbom --sbom-format cyclonedx</code>, or{" "}
          <code className="font-mono text-[11px] bg-black/30 px-1 py-0.5 rounded">pip-audit --format cyclonedx-json</code>, then upload the JSON here.
          Components are matched against <span className="text-blue-100">OSV.dev</span> (npm, PyPI, Go, crates.io, Maven, NuGet, RubyGems, Packagist)
          — no scanner binary or vulnerability database to maintain in the container.
        </div>

        <div className="grid grid-cols-1 gap-4">
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Label (optional)</label>
            <input value={label} onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. billing-service main branch"
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100"/>
          </div>

          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">SBOM file (CycloneDX / SPDX JSON)</label>
            <div className="border-2 border-dashed border-[#30363D] hover:border-blue-500/40 rounded-md p-6 text-center cursor-pointer transition-colors"
                 onClick={() => fileRef.current?.click()}>
              <input ref={fileRef} type="file" accept=".json" onChange={(e) => setFile(e.target.files?.[0] || null)} className="hidden"/>
              <FileCode size={36} className="text-slate-500 mx-auto mb-2"/>
              {file ? (
                <>
                  <div className="text-[13px] text-slate-200 font-mono">{file.name}</div>
                  <div className="text-[11px] text-slate-500 mt-1">{(file.size / 1024).toFixed(1)} KB · Click to change</div>
                </>
              ) : (
                <div className="text-[13px] text-slate-300">Click to choose a .json SBOM file</div>
              )}
            </div>
          </div>

          <div className="flex gap-2">
            <button onClick={submit} disabled={busy || !file}
              className="h-10 px-4 text-[13px] bg-blue-500 hover:bg-blue-400 disabled:opacity-40 text-white rounded inline-flex items-center justify-center gap-2 flex-1">
              <UploadSimple size={16}/> {busy ? "Matching against OSV.dev…" : "Upload & Scan"}
            </button>
            <button onClick={runSampleTest} disabled={testBusy} type="button"
              title="Run a one-click smoke test with a small sample SBOM (real, known-vulnerable packages) to confirm the pipeline works"
              className="h-10 px-4 text-[13px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 disabled:opacity-40 text-slate-300 rounded inline-flex items-center justify-center gap-2">
              <Flask size={16}/> {testBusy ? "Running…" : "Run test scan"}
            </button>
            <button onClick={downloadSample} type="button" title="Download the sample SBOM used by the test-scan button, to see the expected format"
              className="h-10 px-3 text-[13px] border border-[#30363D] hover:border-[#484F58] text-slate-400 hover:text-slate-200 rounded inline-flex items-center justify-center gap-1.5">
              <DownloadSimple size={16}/>
            </button>
          </div>

          {result && (
            <div className="border border-emerald-500/30 bg-emerald-500/5 rounded-md p-3.5 text-[12.5px] text-emerald-200 space-y-1">
              <div className="flex items-center gap-1.5"><CheckCircle size={14}/> {result.components_parsed} component(s) parsed</div>
              <div>{result.components_vulnerable} vulnerable component(s) · {result.unique_vulns} unique known vulnerabilities</div>
              <div>{result.findings_created} new finding(s) created, {result.findings_updated} already tracked</div>
              {(result.findings_created > 0 || result.findings_updated > 0) && (
                <Link to="/findings?source_tool=SBOM%20%2F%20OSV.dev" className="inline-flex items-center gap-1 text-blue-300 hover:text-blue-200 mt-1">
                  <LinkSimple size={12}/> View SBOM finding(s) in Findings
                </Link>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md">
        <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">Upload History</h3></div>
        {history.length === 0 ? (
          <div className="p-5 text-center text-[12.5px] text-slate-500">No SBOMs uploaded yet.</div>
        ) : (
          <div className="divide-y divide-[#30363D]">
            {history.map(h => (
              <div key={h.id} className="px-4 py-3 flex items-center justify-between gap-3">
                <div className="flex items-center gap-2 min-w-0">
                  <Package size={14} className="text-slate-500 shrink-0"/>
                  <div className="min-w-0">
                    <div className="text-[12.5px] text-slate-200 truncate">{h.label || h.filename}</div>
                    <div className="text-[10.5px] text-slate-500 font-mono">{h.filename} · {new Date(h.uploaded_at).toLocaleString()}</div>
                  </div>
                </div>
                <div className="text-[11px] text-slate-400 shrink-0">
                  {h.components_vulnerable}/{h.components_total} vulnerable · {h.findings_created} new
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </Layout>
  );
}
