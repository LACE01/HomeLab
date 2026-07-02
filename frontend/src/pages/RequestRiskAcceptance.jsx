import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip, SevBadge } from "@/components/Badges";
import { ArrowLeft, MagnifyingGlass, X, Paperclip } from "@phosphor-icons/react";

const TARGET_TYPES = [
  { id: "finding", label: "Individual finding", hint: "Attach a single finding by searching for it." },
  { id: "host", label: "Host", hint: "Every open finding on a specific asset." },
  { id: "cve", label: "CVE", hint: "Every open finding for a CVE, across all assets." },
  { id: "tag", label: "Tag / Group", hint: "Every open finding on assets carrying a tag." },
];

const DURATION_PRESETS = [30, 60, 90, 180];

function Field({ label, children, hint }) {
  return (
    <div>
      <label className="text-[11px] uppercase font-mono text-slate-500">{label}</label>
      {children}
      {hint && <div className="text-[10.5px] text-slate-600 mt-1">{hint}</div>}
    </div>
  );
}

export default function RequestRiskAcceptance() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const prefillFindingId = searchParams.get("finding_id");
  const [targetType, setTargetType] = useState("finding");

  // "finding" target
  const [findingQuery, setFindingQuery] = useState("");
  const [findingResults, setFindingResults] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);

  // "host" / "cve" / "tag" targets
  const [targetValue, setTargetValue] = useState("");
  const [hostnameOptions, setHostnameOptions] = useState([]);
  const [tagOptions, setTagOptions] = useState([]);

  // live preview of matched findings
  const [preview, setPreview] = useState(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  // form fields
  const [justification, setJustification] = useState("");
  const [durationMode, setDurationMode] = useState("preset"); // preset | custom
  const [durationDays, setDurationDays] = useState(90);
  const [expiresAt, setExpiresAt] = useState("");
  const [reminderDays, setReminderDays] = useState(7);
  const [controls, setControls] = useState("");
  const [contactName, setContactName] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [attachments, setAttachments] = useState([]);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api.get("/v1/admin/assignment-rules/field-values", { params: { field: "hostname" } })
      .then(r => setHostnameOptions(r.data.values || [])).catch(() => {});
    api.get("/v1/admin/assignment-rules/field-values", { params: { field: "tags" } })
      .then(r => setTagOptions(r.data.values || [])).catch(() => {});
  }, []);

  // Arriving from a finding's "Request exception" button -- lock target type to
  // that finding and pre-select it instead of making the requester search again.
  useEffect(() => {
    if (!prefillFindingId) return;
    api.get(`/v1/findings/${prefillFindingId}`).then(r => {
      setTargetType("finding");
      setSelectedFinding({ id: r.data.id, title: r.data.title, severity: r.data.severity, asset_hostname: r.data.asset_hostname });
    }).catch(() => toast.error("Could not load that finding"));
  }, [prefillFindingId]);

  // finding search-as-you-type
  useEffect(() => {
    if (targetType !== "finding" || !findingQuery.trim() || findingQuery.length < 2) { setFindingResults([]); return; }
    const t = setTimeout(() => {
      api.get("/v1/findings", { params: { q: findingQuery, limit: 8 } })
        .then(r => setFindingResults(r.data.items || [])).catch(() => setFindingResults([]));
    }, 250);
    return () => clearTimeout(t);
  }, [findingQuery, targetType]);

  // live match-count preview for host/cve/tag targets
  useEffect(() => {
    if (targetType === "finding") {
      setPreview(selectedFinding ? { count: 1, items: [selectedFinding] } : null);
      return;
    }
    if (!targetValue.trim()) { setPreview(null); return; }
    setPreviewLoading(true);
    const t = setTimeout(() => {
      api.get("/v1/exceptions/target-preview", { params: { target_type: targetType, target_value: targetValue } })
        .then(r => setPreview(r.data)).catch(() => setPreview(null)).finally(() => setPreviewLoading(false));
    }, 350);
    return () => clearTimeout(t);
  }, [targetType, targetValue, selectedFinding]);

  const handleFiles = async (files) => {
    const arr = Array.from(files || []);
    const out = [...attachments];
    for (const file of arr) {
      if (!file.type.startsWith("image/") && file.type !== "application/pdf") { toast.error(`${file.name}: only images/PDFs allowed`); continue; }
      if (file.size > 1_000_000) { toast.error(`${file.name} > 1MB — skipped`); continue; }
      const reader = new FileReader();
      const data_url = await new Promise((res) => { reader.onload = () => res(reader.result); reader.readAsDataURL(file); });
      out.push({ name: file.name, mime: file.type, data_url });
    }
    setAttachments(out);
  };

  const submit = async () => {
    if (targetType === "finding" && !selectedFinding) { toast.error("Search for and select a finding"); return; }
    if (targetType !== "finding" && !targetValue.trim()) { toast.error(`Enter a ${targetType} to attach`); return; }
    if (!justification.trim()) { toast.error("Business justification is required"); return; }
    if (durationMode === "custom" && !expiresAt) { toast.error("Pick an expiry date"); return; }
    if (preview && preview.count === 0) { toast.error("No open findings match this target"); return; }

    setSaving(true);
    try {
      const body = {
        target_type: targetType,
        target_value: targetType === "finding" ? selectedFinding.id : targetValue,
        business_justification: justification,
        compensating_controls: controls.split(",").map(s => s.trim()).filter(Boolean),
        contact_name: contactName, contact_email: contactEmail,
        reminder_days_before: Number(reminderDays) || 7,
        evidence_files: attachments,
      };
      if (durationMode === "custom") body.expires_at = new Date(expiresAt).toISOString();
      else body.duration_days = durationDays;

      const r = await api.post("/v1/exceptions", body);
      toast.success("Risk acceptance requested — pending approval.");
      navigate(`/exceptions/${r.data.id}`);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to submit request");
    } finally { setSaving(false); }
  };

  return (
    <Layout title="Request Risk Acceptance" subtitle="Attach an individual finding, a whole host, a CVE, or a tag group, then route it for approval"
      actions={<button onClick={() => navigate("/exceptions")} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300"><ArrowLeft size={14}/> Back</button>}>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-4">

          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="text-[13px] font-medium text-slate-100 mb-3">What is this risk acceptance for?</div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3">
              {TARGET_TYPES.map(t => (
                <button key={t.id} data-testid={`target-type-${t.id}`}
                  onClick={() => { setTargetType(t.id); setSelectedFinding(null); setTargetValue(""); setPreview(null); }}
                  className={`px-2.5 py-2 rounded border text-[12px] text-left transition-colors ${targetType === t.id ? "bg-blue-500/15 border-blue-500/40 text-blue-200" : "border-[#30363D] text-slate-400 hover:border-[#484F58]"}`}>
                  {t.label}
                </button>
              ))}
            </div>
            <div className="text-[11.5px] text-slate-500 mb-3">{TARGET_TYPES.find(t => t.id === targetType)?.hint}</div>

            {targetType === "finding" && (
              <div className="relative">
                <div className="relative">
                  <MagnifyingGlass size={14} className="absolute left-2.5 top-2.5 text-slate-500" />
                  <input value={findingQuery} onChange={e => { setFindingQuery(e.target.value); setSelectedFinding(null); }}
                    placeholder="Search by title, CVE, hostname…" data-testid="finding-search-input"
                    className="w-full h-9 pl-8 pr-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200"/>
                </div>
                {selectedFinding ? (
                  <div className="mt-2 flex items-center gap-2 border border-blue-500/30 bg-blue-500/10 rounded px-2.5 py-2">
                    <SevBadge severity={selectedFinding.severity} />
                    <span className="text-[12px] text-slate-200 flex-1 truncate">{selectedFinding.title}</span>
                    <button onClick={() => setSelectedFinding(null)} className="text-slate-500 hover:text-slate-300"><X size={14}/></button>
                  </div>
                ) : findingResults.length > 0 ? (
                  <div className="mt-1 border border-[#30363D] rounded max-h-56 overflow-y-auto">
                    {findingResults.map(f => (
                      <button key={f.id} onClick={() => { setSelectedFinding(f); setFindingResults([]); }} data-testid={`finding-option-${f.id}`}
                        className="w-full text-left px-2.5 py-2 border-b border-[#30363D] last:border-0 hover:bg-slate-800/40 flex items-center gap-2">
                        <SevBadge severity={f.severity} />
                        <span className="text-[12px] text-slate-300 truncate flex-1">{f.title}</span>
                        <span className="text-[10.5px] font-mono text-slate-500">{f.asset_hostname}</span>
                      </button>
                    ))}
                  </div>
                ) : null}
              </div>
            )}

            {targetType === "host" && (
              <>
                <input value={targetValue} onChange={e => setTargetValue(e.target.value)} list="ra-hostnames"
                  placeholder="hostname or asset id" data-testid="target-value-input"
                  className="w-full h-9 px-2.5 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200"/>
                <datalist id="ra-hostnames">{hostnameOptions.map(h => <option key={h} value={h}/>)}</datalist>
              </>
            )}
            {targetType === "cve" && (
              <input value={targetValue} onChange={e => setTargetValue(e.target.value)} placeholder="CVE-2024-12345"
                data-testid="target-value-input" className="w-full h-9 px-2.5 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200 font-mono"/>
            )}
            {targetType === "tag" && (
              <>
                <input value={targetValue} onChange={e => setTargetValue(e.target.value)} list="ra-tags" placeholder="tag name"
                  data-testid="target-value-input" className="w-full h-9 px-2.5 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200"/>
                <datalist id="ra-tags">{tagOptions.map(t => <option key={t} value={t}/>)}</datalist>
              </>
            )}

            {targetType !== "finding" && (previewLoading || preview) && (
              <div className="mt-2 text-[11.5px]" data-testid="target-preview">
                {previewLoading ? <span className="text-slate-500">Checking matches…</span> : preview?.error ? (
                  <span className="text-amber-400">{preview.error}</span>
                ) : (
                  <span className={preview?.count ? "text-emerald-400" : "text-slate-500"}>
                    {preview?.count || 0} open finding{preview?.count === 1 ? "" : "s"} will be attached
                  </span>
                )}
              </div>
            )}
          </div>

          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 space-y-3">
            <div className="text-[13px] font-medium text-slate-100">Justification & duration</div>
            <Field label="Business justification">
              <textarea value={justification} onChange={e => setJustification(e.target.value)} rows={3} data-testid="ra-justification"
                placeholder="Why are we accepting this risk instead of remediating it now?"
                className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200"/>
            </Field>

            <Field label="How long do we plan to accept this risk?">
              <div className="flex items-center gap-1 mt-1 mb-2">
                <button onClick={() => setDurationMode("preset")} className={`px-2.5 py-1 text-[11.5px] rounded border ${durationMode === "preset" ? "border-blue-500/40 bg-blue-500/15 text-blue-200" : "border-[#30363D] text-slate-400"}`}>Preset</button>
                <button onClick={() => setDurationMode("custom")} className={`px-2.5 py-1 text-[11.5px] rounded border ${durationMode === "custom" ? "border-blue-500/40 bg-blue-500/15 text-blue-200" : "border-[#30363D] text-slate-400"}`}>Custom date</button>
              </div>
              {durationMode === "preset" ? (
                <div className="flex gap-1.5">
                  {DURATION_PRESETS.map(d => (
                    <button key={d} onClick={() => setDurationDays(d)} data-testid={`duration-${d}`}
                      className={`px-3 py-1.5 text-[12px] rounded border ${durationDays === d ? "border-blue-500/40 bg-blue-500/15 text-blue-200" : "border-[#30363D] text-slate-400 hover:border-[#484F58]"}`}>
                      {d}d
                    </button>
                  ))}
                </div>
              ) : (
                <input type="date" value={expiresAt} onChange={e => setExpiresAt(e.target.value)} data-testid="ra-expires-custom"
                  className="w-full h-9 px-2.5 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200"/>
              )}
            </Field>

            <Field label="Notify before expiry (days)" hint="The team gets a reminder this many days before the risk acceptance lapses and findings reopen.">
              <input type="number" min={1} max={90} value={reminderDays} onChange={e => setReminderDays(e.target.value)} data-testid="ra-reminder-days"
                className="w-28 h-9 mt-1 px-2.5 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200"/>
            </Field>

            <Field label="Compensating controls (comma-separated, optional)">
              <input value={controls} onChange={e => setControls(e.target.value)} placeholder="WAF rule, network segmentation"
                className="w-full h-9 mt-1 px-2.5 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200"/>
            </Field>
          </div>

          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 space-y-3">
            <div className="text-[13px] font-medium text-slate-100">Contact & evidence</div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Contact name">
                <input value={contactName} onChange={e => setContactName(e.target.value)}
                  className="w-full h-9 mt-1 px-2.5 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200"/>
              </Field>
              <Field label="Contact email">
                <input type="email" value={contactEmail} onChange={e => setContactEmail(e.target.value)}
                  className="w-full h-9 mt-1 px-2.5 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200"/>
              </Field>
            </div>
            <div>
              <label className="text-[11px] uppercase font-mono text-slate-500">Screenshots / evidence (optional)</label>
              <label className="mt-1 flex items-center gap-2 h-9 px-2.5 border border-dashed border-[#30363D] rounded text-[12px] text-slate-400 hover:border-[#484F58] cursor-pointer w-fit">
                <Paperclip size={14}/> Attach files
                <input type="file" multiple accept="image/*,application/pdf" className="hidden" onChange={e => handleFiles(e.target.files)}/>
              </label>
              {attachments.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-2">
                  {attachments.map((a, i) => (
                    <div key={i} className="flex items-center gap-1.5 px-2 py-1 border border-[#30363D] rounded bg-[#161B22] text-[11px]">
                      {a.mime?.startsWith("image/") && <img src={a.data_url} alt="" className="h-6 w-6 object-cover rounded"/>}
                      <span className="text-slate-300 truncate max-w-[140px]">{a.name}</span>
                      <button onClick={() => setAttachments(attachments.filter((_, j) => j !== i))} className="text-red-400 hover:text-red-300"><X size={12}/></button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="flex justify-end gap-2">
            <button onClick={() => navigate("/exceptions")} className="h-9 px-4 text-[12.5px] border border-[#30363D] rounded text-slate-300">Cancel</button>
            <button onClick={submit} disabled={saving} data-testid="ra-submit"
              className="h-9 px-4 text-[12.5px] bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/40 text-blue-200 rounded disabled:opacity-50">
              {saving ? "Submitting…" : "Submit for approval"}
            </button>
          </div>
        </div>

        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 h-fit">
          <div className="text-[13px] font-medium text-slate-100 mb-2">What happens next</div>
          <ol className="text-[12px] text-slate-400 space-y-2 list-decimal list-inside">
            <li>Your request is routed for approval — findings stay in their current status until then.</li>
            <li>A manager or admin approves or rejects it, with their own justification.</li>
            <li>If approved, every attached finding moves to <span className="text-slate-300">Accepted risk</span> and an internal ticket is created.</li>
            <li>You'll get a reminder before it expires; unless renewed, the findings automatically reopen.</li>
          </ol>
          {preview && preview.count > 0 && targetType !== "finding" && (
            <div className="mt-3 pt-3 border-t border-[#30363D]">
              <div className="text-[11px] uppercase font-mono text-slate-500 mb-1.5">Preview ({preview.count})</div>
              <div className="space-y-1.5 max-h-64 overflow-y-auto">
                {preview.items.map(f => (
                  <div key={f.id} className="flex items-center gap-1.5 text-[11.5px]">
                    <SevBadge severity={f.severity} />
                    <span className="text-slate-300 truncate">{f.title}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
