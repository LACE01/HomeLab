import { useEffect, useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import Layout from "@/components/Layout";
import { SevBadge, Chip, RiskBar } from "@/components/Badges";
import { fmtDate, fmtRel, isOverdue } from "@/lib/utils-fmt";
import { ArrowLeft, ChatCircle, ClockCounterClockwise, Ticket, Shield, BookOpen, CheckCircle, ArrowCounterClockwise, Plus, ShieldCheck, Trash, SealWarning, SealCheck, DotsSixVertical, SlidersHorizontal, FloppyDisk } from "@phosphor-icons/react";
import InfoTip from "@/components/InfoTip";
import { toast } from "sonner";

const DEFAULT_SIDEBAR_ORDER = ["status", "exception", "comments", "playbook", "mitigations",
  "risk_score", "identifiers", "scoring", "exploits", "asset", "sla", "source", "tickets", "references"];

const Section = ({ title, children, testid }) => (
  <div data-testid={testid} className="border border-[#30363D] bg-[#0D1117] rounded-md">
    <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">{title}</h3></div>
    <div className="p-4">{children}</div>
  </div>
);

const KV = ({ k, v, mono }) => (
  <div className="flex justify-between gap-3 py-1 border-b border-[#30363D]/50 last:border-0">
    <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500">{k}</div>
    <div className={`text-[12.5px] text-slate-200 text-right ${mono ? "font-mono" : ""}`}>{v ?? "—"}</div>
  </div>
);

// "Why does this matter HERE" -- the join across every module.
//
// Two deliberate choices in this rendering:
//   * every claim shows the module it came from. A panel that asserts things
//     without attribution is unfalsifiable, and an analyst who cannot check it
//     stops believing all of it.
//   * "missing" is its own visual weight, not an absent row. "No EDR has ever
//     reported on this machine" is one of the most important things the panel can
//     say, and hiding empty sections would turn a blind spot into apparent safety.
const WEIGHT_STYLE = {
  aggravating: { dot: "bg-red-500", text: "text-slate-200", label: "raises risk" },
  mitigating: { dot: "bg-emerald-500", text: "text-slate-300", label: "lowers risk" },
  missing: { dot: "bg-amber-500", text: "text-amber-200/90", label: "not checked" },
  neutral: { dot: "bg-slate-600", text: "text-slate-400", label: "context" },
};

function ContextItem({ item }) {
  const st = WEIGHT_STYLE[item.weight] || WEIGHT_STYLE.neutral;
  const body = (
    <div className="flex gap-2.5 py-1.5">
      <span className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${st.dot}`} title={st.label}/>
      <div className="min-w-0">
        <div className={`text-[12.5px] leading-snug ${st.text}`}>{item.headline}</div>
        {item.detail && <div className="text-[11px] text-slate-500 leading-relaxed mt-0.5">{item.detail}</div>}
        <div className="text-[10px] font-mono text-slate-600 mt-0.5">{item.source}</div>
      </div>
    </div>
  );
  return item.link
    ? <a href={item.link} className="block hover:bg-white/[0.02] rounded px-1 -mx-1">{body}</a>
    : body;
}

function ContextPanel({ ctx }) {
  const [open, setOpen] = useState(true);
  const v = ctx.verdict || {};
  return (
    <Section title="Why this matters here">
      <div className="border-l-2 border-blue-500/60 pl-3 mb-3">
        <div className="text-[13.5px] font-medium text-slate-100">{v.headline}</div>
        <div className="text-[12px] text-slate-400 leading-relaxed mt-1">{v.body}</div>
        <div className="flex gap-3 mt-1.5 text-[10px] font-mono text-slate-600">
          <span>{v.environmental_aggravators ?? 0} environmental</span>
          <span>{v.mitigating_count ?? 0} mitigating</span>
          {v.unknown_count > 0 && <span className="text-amber-500/80">{v.unknown_count} unchecked</span>}
        </div>
      </div>

      <button onClick={() => setOpen(o => !o)}
        className="text-[11px] text-blue-300 hover:underline mb-1">
        {open ? "Hide" : "Show"} the evidence
      </button>

      {open && Object.entries(ctx.sections || {}).map(([key, items]) =>
        items?.length ? (
          <div key={key} className="mt-2.5 pt-2.5 border-t border-[#30363D]">
            <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider mb-0.5">
              {ctx.section_labels?.[key] || key}
            </div>
            {items.map((it, i) => <ContextItem key={i} item={it}/>)}
          </div>
        ) : null)}
    </Section>
  );
}

function AddMitigationForm({ types, onCancel, onAdded, findingId }) {
  const [controlType, setControlType] = useState(types?.[0] || "Other");
  const [description, setDescription] = useState("");
  const [saving, setSaving] = useState(false);
  const submit = async () => {
    if (!description.trim()) { toast.error("Description is required"); return; }
    setSaving(true);
    try {
      await api.post(`/v1/findings/${findingId}/mitigations`, { control_type: controlType, description });
      toast.success("Mitigation recorded.");
      onAdded();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to add mitigation");
    } finally { setSaving(false); }
  };
  return (
    <div className="border border-[#30363D] rounded p-2.5 bg-[#161B22] space-y-2">
      <select value={controlType} onChange={e=>setControlType(e.target.value)} data-testid="mitigation-type-select"
        className="w-full h-8 bg-[#0D1117] border border-[#30363D] rounded px-2 text-[12px] text-slate-200">
        {(types||[]).map(t => <option key={t} value={t}>{t}</option>)}
      </select>
      <textarea value={description} onChange={e=>setDescription(e.target.value)} rows={2} placeholder="What was done, and where"
        data-testid="mitigation-description" className="w-full bg-[#0D1117] border border-[#30363D] rounded px-2 py-1.5 text-[12px] text-slate-200"/>
      <div className="flex justify-end gap-2">
        <button onClick={onCancel} className="h-7 px-2.5 text-[11px] border border-[#30363D] rounded text-slate-300">Cancel</button>
        <button onClick={submit} disabled={saving} data-testid="mitigation-save"
          className="h-7 px-2.5 text-[11px] bg-blue-500/20 border border-blue-500/40 text-blue-200 rounded disabled:opacity-50">
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </div>
  );
}

export default function FindingDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [f, setF] = useState(null);
  const [tickets, setTickets] = useState([]);
  const [obs, setObs] = useState([]);
  const [activity, setActivity] = useState([]);
  const [comments, setComments] = useState([]);
  const [newComment, setNewComment] = useState("");
  const [attachments, setAttachments] = useState([]);
  const [statusVal, setStatusVal] = useState("");
  const [kri, setKri] = useState(null);
  const [mitreCoverage, setMitreCoverage] = useState(null);
  const [context, setContext] = useState(null);
  const [intel, setIntel] = useState(null);
  const [playbook, setPlaybook] = useState(undefined); // undefined = loading, null = none found
  const [playbookBasis, setPlaybookBasis] = useState(null);
  const [playbookProgress, setPlaybookProgress] = useState(null);
  const [allPlaybooks, setAllPlaybooks] = useState([]);
  const [attachingPlaybook, setAttachingPlaybook] = useState(false);
  const [patchGroup, setPatchGroup] = useState(null);
  const [mitigations, setMitigations] = useState([]);
  const [mitigationTypes, setMitigationTypes] = useState([]);
  const [showAddMitigation, setShowAddMitigation] = useState(false);
  const [exceptions, setExceptions] = useState([]);
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [sidebarOrder, setSidebarOrder] = useState(DEFAULT_SIDEBAR_ORDER);
  const [customizingLayout, setCustomizingLayout] = useState(false);
  const [savingLayout, setSavingLayout] = useState(false);
  const [dragKey, setDragKey] = useState(null);

  const loadMitigations = () => api.get(`/v1/findings/${id}/mitigations`).then(r => { setMitigations(r.data.items); setMitigationTypes(r.data.types); });
  const loadExceptions = () => api.get("/v1/exceptions").then(r => setExceptions(r.data.items.filter(e => e.finding_id === id)));

  const loadSidebarLayout = () => api.get("/v1/admin/ui-layout/finding_detail_sidebar").then(r => setSidebarOrder(r.data.order));
  const saveSidebarLayout = async () => {
    setSavingLayout(true);
    try {
      await api.put("/v1/admin/ui-layout/finding_detail_sidebar", { order: sidebarOrder });
      toast.success("Layout saved for everyone.");
      setCustomizingLayout(false);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to save layout");
    } finally { setSavingLayout(false); }
  };
  const resetSidebarLayout = async () => {
    try {
      const r = await api.delete("/v1/admin/ui-layout/finding_detail_sidebar");
      setSidebarOrder(r.data.default);
      toast.success("Reset to default layout.");
    } catch (e) {
      toast.error("Failed to reset layout");
    }
  };
  const onTileDragStart = (key) => setDragKey(key);
  const onTileDrop = (key) => {
    if (!dragKey || dragKey === key) return;
    setSidebarOrder(prev => {
      const next = [...prev];
      const from = next.indexOf(dragKey), to = next.indexOf(key);
      if (from === -1 || to === -1) return prev;
      next.splice(from, 1);
      next.splice(to, 0, dragKey);
      return next;
    });
    setDragKey(null);
  };

  useEffect(() => {
    api.get(`/v1/findings/${id}`).then(r => { setF(r.data); setStatusVal(r.data.status); });
    // "Why does this matter HERE" -- joined from every module that knows something
    // about this finding's asset. Failing quietly is deliberate: the context panel
    // is additive, and a missing panel must never block the finding itself.
    api.get(`/v1/findings/${id}/context`).then(r => setContext(r.data)).catch(() => {});
    api.get(`/v1/findings/${id}/tickets`).then(r => setTickets(r.data.items));
    api.get(`/v1/findings/${id}/observations`).then(r => setObs(r.data.items));
    api.get(`/v1/findings/${id}/timeline`).then(r => setActivity(r.data.items));
    api.get(`/v1/findings/${id}/comments`).then(r => setComments(r.data.items));
    api.get(`/v1/findings/${id}/kri`).then(r => setKri(r.data));
    api.get("/v1/mitre/coverage").then(r => setMitreCoverage(r.data)).catch(() => {});
    loadPlaybook();
    api.get(`/v1/playbooks`).then(r => setAllPlaybooks(r.data.items || []));
    api.get(`/v1/findings/${id}/patch-group`).then(r => setPatchGroup(r.data));
    loadMitigations();
    loadExceptions();
    loadSidebarLayout();
  }, [id]); // eslint-disable-line

  const loadPlaybook = () => api.get(`/v1/findings/${id}/playbook`).then(r => {
    setPlaybook(r.data.playbook); setPlaybookBasis(r.data.match_basis); setPlaybookProgress(r.data.progress);
  });

  const attachPlaybook = async (playbookId) => {
    setAttachingPlaybook(true);
    try {
      await api.put(`/v1/findings/${id}/playbook-attach`, { playbook_id: playbookId || null });
      await loadPlaybook();
      toast.success(playbookId ? "Playbook attached" : "Playbook detached — reverted to auto-match");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to update attached playbook");
    } finally { setAttachingPlaybook(false); }
  };

  const saveProgress = async (next) => {
    setPlaybookProgress(next); // optimistic
    try {
      const saved = await api.put(`/v1/findings/${id}/playbook-progress`, {
        playbook_id: playbook.id, steps_done: next.steps_done, validated_checks: next.validated_checks,
        validated: next.validated,
      });
      setPlaybookProgress(saved.data);
    } catch (e) {
      toast.error("Failed to save checklist progress");
    }
  };

  const toggleStep = (i) => {
    const done = new Set(playbookProgress?.steps_done || []);
    done.has(i) ? done.delete(i) : done.add(i);
    saveProgress({
      steps_done: Array.from(done), validated_checks: playbookProgress?.validated_checks || [],
      validated: playbookProgress?.validated || false,
    });
  };

  const toggleCheck = (i) => {
    const done = new Set(playbookProgress?.validated_checks || []);
    done.has(i) ? done.delete(i) : done.add(i);
    saveProgress({
      steps_done: playbookProgress?.steps_done || [], validated_checks: Array.from(done),
      validated: playbookProgress?.validated || false,
    });
  };

  useEffect(() => {
    if (f?.cve) api.get(`/v1/threat-intel/${f.cve}`).then(r => setIntel(r.data));
  }, [f?.cve]);

  const updateStatus = async (s) => {
    await api.patch(`/v1/findings/${id}/status`, { status: s });
    setStatusVal(s);
    const r = await api.get(`/v1/findings/${id}/timeline`); setActivity(r.data.items);
    const fr = await api.get(`/v1/findings/${id}`); setF(fr.data);
  };

  const [verifying, setVerifying] = useState(false);
  const verifyNow = async () => {
    setVerifying(true);
    try {
      const r = await api.post(`/v1/findings/${id}/verify`);
      if (r.data.verified) toast.success(r.data.note);
      else toast(r.data.note, { icon: "⏳" });
      const fr = await api.get(`/v1/findings/${id}`); setF(fr.data);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Verification check failed");
    } finally {
      setVerifying(false);
    }
  };

  const addComment = async () => {
    if (!newComment.trim() && attachments.length === 0) return;
    await api.post(`/v1/findings/${id}/comments`, { text: newComment, attachments });
    setNewComment(""); setAttachments([]);
    const r = await api.get(`/v1/findings/${id}/comments`); setComments(r.data.items);
  };

  const handleFiles = async (files) => {
    const arr = Array.from(files || []);
    const out = [...attachments];
    for (const file of arr) {
      if (!file.type.startsWith("image/") && file.type !== "application/pdf") continue;
      if (file.size > 1_000_000) { alert(`${file.name} > 1MB — skipped`); continue; }
      const reader = new FileReader();
      const data_url = await new Promise((res) => { reader.onload = () => res(reader.result); reader.readAsDataURL(file); });
      out.push({ name: file.name, mime: file.type, data_url });
    }
    setAttachments(out);
  };

  if (!f) return <Layout title="Finding…"><div className="text-slate-500">Loading…</div></Layout>;

  return (
    <Layout title={f.title?.slice(0,90)} subtitle={`${f.cve || f.source_native_id} · ${f.source_tool}`}
      actions={<button onClick={() => navigate(-1)} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300"><ArrowLeft size={14}/> Back</button>}>

      <div className="flex flex-wrap gap-2 mb-4">
        <SevBadge severity={f.severity} />
        {f.kev_flag && <Chip color="red">KEV — actively exploited</Chip>}
        {f.cve && <Chip color="slate">{f.cve}</Chip>}
        {f.cwe && <Chip color="slate">{f.cwe}</Chip>}
        {f.internet_facing && <Chip color="orange">Internet Facing</Chip>}
        {f.patch_available === false && <Chip color="amber">No Patch Available</Chip>}
        {(f.rti || []).map(r => <Chip key={r} color="red">{r.replace(/_/g," ").toUpperCase()}</Chip>)}
        {(f.compliance_scope || []).map(c => <Chip key={c} color="blue">{c}</Chip>)}
      </div>

      {patchGroup?.siblings?.length > 0 && (
        <div className="border border-emerald-500/30 bg-emerald-500/5 rounded-md px-3 py-2 mb-4 text-[12px] text-emerald-200 flex items-center justify-between gap-3">
          <span>Shares the same patch/update with {patchGroup.siblings.length} other open finding{patchGroup.siblings.length===1?"":"s"} on this asset — one fix clears all of them.</span>
          <Link to={`/assets/${f.asset_id}`} className="text-emerald-300 hover:underline shrink-0">View asset →</Link>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-4">
          <Section title="Description" testid="section-description">
            <div className="text-[13px] text-slate-200 leading-relaxed whitespace-pre-wrap">{f.description}</div>
          </Section>

          <Section title="Consequence if Unpatched" testid="section-consequence">
            <div className="text-[13px] text-slate-300 leading-relaxed">{f.consequence}</div>
          </Section>

          <Section title="Business Impact" testid="section-impact">
            <div className="text-[13px] text-slate-300 leading-relaxed">{f.business_impact}</div>
          </Section>

          <Section title="Remediation Guidance" testid="section-remediation">
            <div className="text-[13px] text-slate-200 leading-relaxed">{f.remediation}</div>
            {f.compensating_controls && <div className="mt-2 text-[12px] text-slate-400">Compensating controls: {f.compensating_controls}</div>}
          </Section>

          <Section title="Detection Logic" testid="section-detection">
            <div className="text-[12.5px] text-slate-300 leading-relaxed font-mono whitespace-pre-wrap">{f.detection_logic}</div>
          </Section>

          {context && <ContextPanel ctx={context}/>}

          <Section title="MITRE ATT&CK Mapping">
            {/* The mapping now resolves from whatever the finding actually carries --
                CWE if present, otherwise what the finding SAYS, otherwise the
                scanner's category. Each layer is a different strength of claim, so
                the basis and confidence are shown rather than presenting an
                inference as if it were a lookup. */}
            <KV k="Tactic" v={f.mitre_tactic} />
            <KV k="Technique" v={
              f.mitre_technique_id
                ? <a href={f.mitre_url} target="_blank" rel="noreferrer"
                     className="text-blue-300 hover:underline">{f.mitre_technique}</a>
                : null} />

            {f.mitre_technique_id && (
              <div className="mt-2 flex items-start gap-2">
                <span className={`shrink-0 text-[9.5px] uppercase font-mono tracking-wider px-1.5 py-0.5 rounded border ${
                  f.mitre_confidence === "confirmed" ? "border-emerald-600/50 text-emerald-300 bg-emerald-500/10" :
                  f.mitre_confidence === "high" ? "border-blue-600/50 text-blue-300 bg-blue-500/10" :
                  f.mitre_confidence === "medium" ? "border-amber-600/50 text-amber-300 bg-amber-500/10" :
                  "border-slate-600/50 text-slate-400 bg-slate-500/10"}`}>
                  {f.mitre_confidence} confidence
                </span>
                <div className="text-[10.5px] text-slate-500 leading-relaxed">
                  {f.mitre_explanation}
                  {f.mitre_matched && f.mitre_basis === "signature" && (
                    <> Matched on <span className="font-mono text-slate-400">&ldquo;{f.mitre_matched}&rdquo;</span>.</>
                  )}
                </div>
              </div>
            )}

            {!f.mitre_technique_id && (
              <div className="text-[11.5px] text-slate-500">{f.mitre_explanation
                || "No technique could be determined for this finding."}</div>
            )}

            {mitreCoverage && (
              <div className="mt-2.5 pt-2.5 border-t border-[#30363D]">
                <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider mb-1">Mapping coverage</div>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-2 bg-slate-800 rounded overflow-hidden">
                    <div className={`h-full ${mitreCoverage.coverage_pct >= 60 ? "bg-emerald-500" : mitreCoverage.coverage_pct >= 30 ? "bg-amber-500" : "bg-red-500"}`}
                      style={{ width: `${mitreCoverage.coverage_pct}%` }}/>
                  </div>
                  <span className="text-[11.5px] text-slate-200">{mitreCoverage.coverage_pct}%</span>
                </div>
                <div className="text-[10.5px] text-slate-500 mt-1">
                  {mitreCoverage.findings_mapped?.toLocaleString()} of {mitreCoverage.findings_total?.toLocaleString()} open
                  findings map to a technique.
                  {mitreCoverage.by_basis?.length > 0 && (
                    <> By basis: {mitreCoverage.by_basis.map(b => `${b.count.toLocaleString()} ${b.basis}`).join(", ")}.</>
                  )}
                </div>
                {mitreCoverage.top_techniques?.length > 0 && (
                  <div className="mt-1.5">
                    <div className="text-[10px] uppercase font-mono text-slate-600 tracking-wider mb-0.5">Most common techniques in your backlog</div>
                    <div className="flex flex-wrap gap-1">
                      {mitreCoverage.top_techniques.slice(0, 6).map(t => (
                        <a key={t.technique_id} href={t.url} target="_blank" rel="noreferrer"
                           className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-[#30363D] text-slate-400 hover:text-blue-300 hover:border-blue-700">
                          {t.technique_id} · {t.count.toLocaleString()}
                        </a>
                      ))}
                    </div>
                  </div>
                )}
                {mitreCoverage.unmapped_count > 0 && (
                  <div className="text-[10.5px] text-slate-600 mt-1.5">
                    {mitreCoverage.unmapped_count.toLocaleString()} still unmapped
                    {mitreCoverage.top_unmapped_categories?.length > 0 && (
                      <>, mostly {mitreCoverage.top_unmapped_categories.slice(0, 3).map(c => `${c.category} (${c.count})`).join(", ")}</>
                    )}.
                  </div>
                )}
              </div>
            )}
          </Section>

          <Section title="Risk Score Breakdown" testid="section-breakdown">
            <div className="flex items-center gap-3 mb-3">
              <div className="text-[36px] font-mono font-semibold text-blue-300">{f.risk_score}</div>
              <div className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">/ 100 risk score</div>
            </div>
            <table className="dense w-full">
              <thead><tr><th className="text-left">Factor</th><th className="text-right">Points</th><th className="text-left">Reason</th></tr></thead>
              <tbody>
                {(f.risk_breakdown || []).map((b, i) => (
                  <tr key={i} className="border-t border-[#30363D]"><td className="text-slate-200">{b.factor}</td><td className="text-right font-mono text-slate-200">+{b.points}</td><td className="text-slate-400">{b.reason}</td></tr>
                ))}
              </tbody>
            </table>
          </Section>

                    {kri && (

            <Section title="Empirical Score (KRI / ZDES / BII)" testid="section-empirical">
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-3">
                <div className="border border-[#30363D] rounded p-2.5 bg-[#161B22]">
                  <div className="text-[9px] uppercase font-mono text-slate-500 tracking-wider flex items-center gap-1">
                    Empirical %ile
                    <InfoTip>
                      Where this finding's KRI ranks among every open finding in your environment. "Top 5%" means it's more urgent than 95% of your current backlog — a relative measure, not an absolute score.
                    </InfoTip>
                  </div>
                  <div className="text-[22px] font-mono font-semibold text-red-300 mt-0.5" data-testid="empirical-pct">{(100-kri.empirical.top_pct).toFixed(1)}%</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Top {kri.empirical.top_pct}%</div>
                </div>
                <div className="border border-[#30363D] rounded p-2.5 bg-[#161B22]">
                  <div className="text-[9px] uppercase font-mono text-slate-500 tracking-wider flex items-center gap-1">
                    KRI
                    <InfoTip>
                      Key Risk Indicator = EPSS × CVSS weight × CWE weight. Combines "how likely is this to be exploited in the next 30 days" (EPSS) with how severe it is and how common this weakness class has been in your environment. Higher = more urgent.
                    </InfoTip>
                  </div>
                  <div className="text-[22px] font-mono font-semibold text-blue-300 mt-0.5">{kri.kri_score}</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">EPSS × CVSS × CWE</div>
                </div>
                <div className="border border-[#30363D] rounded p-2.5 bg-[#161B22]">
                  <div className="text-[9px] uppercase font-mono text-slate-500 tracking-wider flex items-center gap-1">
                    ZDES
                    <InfoTip>
                      Zero-Day Exposure Score = (1 − KEV) × recency × CVSS weight. Runs high for findings that are severe and freshly discovered but NOT yet confirmed as actively exploited — i.e. your exposure to something that could turn into a zero-day before it's KEV-listed. Drops once CISA confirms active exploitation (KEV), since that risk has already materialized and is tracked elsewhere.
                    </InfoTip>
                  </div>
                  <div className="text-[22px] font-mono font-semibold text-amber-300 mt-0.5">{kri.zdes_score}</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Zero-day exposure</div>
                </div>
                <div className="border border-[#30363D] rounded p-2.5 bg-[#161B22]">
                  <div className="text-[9px] uppercase font-mono text-slate-500 tracking-wider flex items-center gap-1">
                    BII (Patch ROI)
                    <InfoTip>
                      Business Impact Index = (risk score ÷ estimated patch effort) × asset criticality. Answers "how much risk do I remove per hour of work, on this specific asset." Use it to sort your queue for maximum risk reduction per hour when time is limited, not just by raw severity.
                    </InfoTip>
                  </div>
                  <div className="text-[22px] font-mono font-semibold text-emerald-300 mt-0.5">{kri.bii_score}</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">{kri.patch_hours_estimated}h est. effort</div>
                </div>
              </div>
              <div className="flex items-center gap-2 mb-3">
                <span className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Urgency Tier:</span>
                <Chip color={kri.urgency_tier==="Urgent"?"red":kri.urgency_tier==="Standard"?"amber":"slate"}>{kri.urgency_tier}</Chip>
              </div>
              <div className="text-[11px] font-mono text-slate-500 mb-3 leading-relaxed">
                <span className="text-slate-400">Due basis:</span> {kri.due_basis}
              </div>

              <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider mb-2">Critical Indicators</div>
              <div className="grid grid-cols-2 lg:grid-cols-3 gap-1.5">
                {kri.critical_indicators.map(i => {
                  const sigColor = {high:"red", medium:"amber", low:"slate", none:"slate"}[i.signal];
                  const trendArrow = {up:"↑", down:"↓", flat:"→", unknown:"·"}[i.trend];
                  const trendColor = i.trend==="up"?"text-red-300":i.trend==="down"?"text-emerald-300":"text-slate-500";
                  return (
                    <div key={i.key} className="flex items-center justify-between border border-[#30363D] rounded px-2 py-1.5 bg-[#161B22]">
                      <span className="text-[12px] text-slate-200">{i.label}</span>
                      <div className="flex items-center gap-1.5">
                        <Chip color={sigColor}>{i.signal}</Chip>
                        <span className={`font-mono text-[14px] ${trendColor}`}>{trendArrow}</span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {kri.empirical.buckets?.length > 0 && (
                <div className="mt-4">
                  <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider mb-1">
                    Score Distribution (cohort: same severity)
                  </div>
                  <div className="text-[11px] text-slate-500 mb-1.5">
                    Where every other open <span className="text-slate-300">{f.severity}</span> finding&apos;s KRI score
                    falls on the 0–1 scale ({kri.empirical.cohort_size} finding{kri.empirical.cohort_size === 1 ? "" : "s"}).
                    The red bar is this one. Hover a bar for its range and count.
                  </div>
                  <div className="flex items-end gap-0.5 h-14">
                    {(() => {
                      const max = Math.max(...kri.empirical.buckets.map(b => b.count), 1);
                      return kri.empirical.buckets.map(b => {
                        const isMine = b.index === kri.empirical.my_bucket;
                        // Empty buckets keep a visible 2px stub so the axis reads as a
                        // continuous scale rather than a few floating bars.
                        const h = b.count === 0 ? 3 : Math.max(8, (b.count / max) * 100);
                        return (
                          <div key={b.index} className="flex-1 h-full flex items-end group relative"
                            title={`KRI ${b.from}–${b.to}: ${b.count} finding${b.count === 1 ? "" : "s"}${isMine ? " (this finding)" : ""}`}>
                            <div className={`w-full rounded-sm transition-colors ${isMine
                              ? "bg-red-400" : b.count === 0 ? "bg-slate-800" : "bg-slate-600 group-hover:bg-slate-500"}`}
                              style={{ height: `${h}%` }}/>
                            <div className="pointer-events-none absolute bottom-full left-1/2 -translate-x-1/2 mb-1 hidden group-hover:block whitespace-nowrap
                                            bg-[#161B22] border border-[#30363D] rounded px-2 py-1 text-[10.5px] text-slate-200 z-10">
                              {b.from}–{b.to}: {b.count}{isMine ? " · this finding" : ""}
                            </div>
                          </div>
                        );
                      });
                    })()}
                  </div>
                  <div className="flex justify-between text-[9.5px] text-slate-600 mt-0.5 font-mono">
                    <span>0.0</span>
                    <span>cohort {kri.empirical.cohort_min}–{kri.empirical.cohort_max}</span>
                    <span>1.0</span>
                  </div>
                </div>
              )}
            </Section>
          )}

          {f.cve && intel && (
            <Section title="Threat Intelligence (OpenCTI)" testid="section-threat-intel">
              {!intel.configured && (
                <div className="text-[12.5px] text-amber-300 bg-amber-900/10 border border-amber-500/30 rounded p-2.5">
                  {intel.message}
                  <div className="text-[11px] text-slate-400 mt-1">Go to Integrations → OpenCTI → Configure (endpoint + api_key).</div>
                </div>
              )}
              {intel.error && (
                <div className="text-[12px] text-red-300">OpenCTI error: {intel.error}</div>
              )}
              {intel.configured && !intel.error && (
                <div className="space-y-2">
                  <KV k="Threat Actors" v={intel.threat_actors?.join(", ") || "—"}/>
                  <KV k="Intrusion Sets" v={intel.intrusion_sets?.join(", ") || "—"}/>
                  <KV k="Malware Families" v={intel.malware?.join(", ") || "—"}/>
                  <KV k="Campaigns" v={intel.campaigns?.join(", ") || "—"}/>
                  {(intel.external_references||[]).slice(0,8).map((r,i) => (
                    <a key={i} href={r.url} target="_blank" rel="noopener noreferrer" className="block text-[12px] text-blue-300 hover:underline truncate">{r.source} — {r.url}</a>
                  ))}
                </div>
              )}
            </Section>
          )}

          <Section title="Observations / Detection History" testid="section-observations">
            <table className="dense w-full">
              <thead><tr><th className="text-left">Source</th><th className="text-left">Method</th><th className="text-left">Auth</th><th className="text-left">Detected</th><th className="text-left">Record ID</th></tr></thead>
              <tbody>
                {obs.map(o => (
                  <tr key={o.id} className="border-t border-[#30363D]">
                    <td>{o.source_tool}</td><td>{o.agent_or_network}</td><td>{o.auth_state}</td>
                    <td className="font-mono text-[11px]">{fmtDate(o.observed_at)}</td>
                    <td className="font-mono text-[11px] text-slate-500">{o.source_record_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>

          <Section title="Activity / Timeline" testid="section-timeline">
            <div className="space-y-2">
              {activity.map(a => (
                <div key={a.id} className="flex gap-3 items-start text-[12.5px]">
                  <ClockCounterClockwise size={14} className="text-slate-500 mt-0.5"/>
                  <div className="flex-1">
                    <div className="text-slate-200">{a.action.replace(/_/g," ")} <span className="text-slate-500">— {a.details}</span></div>
                    <div className="text-[10.5px] font-mono text-slate-600">{a.actor} · {fmtDate(a.timestamp)}</div>
                  </div>
                </div>
              ))}
            </div>
          </Section>

        </div>

        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="text-[10.5px] uppercase font-mono text-slate-600">Sidebar</div>
            {isAdmin && (
              customizingLayout ? (
                <div className="flex gap-1.5">
                  <button onClick={resetSidebarLayout} data-testid="layout-reset"
                    className="h-6 px-2 text-[10.5px] border border-[#30363D] hover:border-[#484F58] text-slate-400 rounded inline-flex items-center gap-1"><ArrowCounterClockwise size={11}/> Reset</button>
                  <button onClick={saveSidebarLayout} disabled={savingLayout} data-testid="layout-save"
                    className="h-6 px-2 text-[10.5px] bg-blue-500/20 border border-blue-500/40 text-blue-200 rounded inline-flex items-center gap-1 disabled:opacity-50"><FloppyDisk size={11}/> {savingLayout ? "Saving…" : "Save"}</button>
                  <button onClick={()=>setCustomizingLayout(false)} className="h-6 px-2 text-[10.5px] border border-[#30363D] text-slate-400 rounded">Done</button>
                </div>
              ) : (
                <button onClick={()=>setCustomizingLayout(true)} data-testid="layout-customize"
                  className="h-6 px-2 text-[10.5px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 text-slate-500 rounded inline-flex items-center gap-1">
                  <SlidersHorizontal size={11}/> Customize layout
                </button>
              )
            )}
          </div>

          {(() => {
            const sidebarSections = {
              status: { title: "Status & Triage", testid: "section-status", content: (
                <>
                  <select data-testid="status-select" value={statusVal} onChange={(e)=>updateStatus(e.target.value)}
                    className="w-full h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px]">
                    {["New","Needs triage","Valid","False positive","Duplicate","Mitigated","Accepted risk","Deferred","Fixed pending validation","Fixed validated","Reopened","Out of scope","Closed administratively"].map(s => <option key={s}>{s}</option>)}
                  </select>
                  <div className="mt-2 grid grid-cols-2 gap-1">
                    <KV k="Validation" v={f.validation_status}/>
                    <KV k="Reopened" v={f.reopened_count} mono/>
                  </div>
                  {f.verification_status && (
                    <div className="mt-3 border-t border-[#30363D] pt-2.5">
                      <div className="flex items-center justify-between mb-1">
                        <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Verification</div>
                        <Chip color={f.verification_status === "passed" ? "green" : f.verification_status === "failed" ? "red" : "amber"}>
                          {f.verification_status}
                        </Chip>
                      </div>
                      {f.verification_note && <div className="text-[11.5px] text-slate-400 leading-relaxed">{f.verification_note}</div>}
                      {statusVal === "Fixed pending validation" && (
                        <button data-testid="verify-now" onClick={verifyNow} disabled={verifying}
                          className="mt-2 h-7 px-2.5 text-[11px] bg-blue-500/15 border border-blue-500/40 hover:bg-blue-500/25 text-blue-300 rounded disabled:opacity-50">
                          {verifying ? "Checking…" : "Verify now"}
                        </button>
                      )}
                    </div>
                  )}
                </>
              ) },
              exception: { title: "Risk Exception", testid: "section-exception", content: (
                <>
                  {exceptions.length === 0 && (
                    <Link to={`/exceptions/new?finding_id=${id}`} data-testid="request-exception-btn"
                      className="w-full h-8 text-[11.5px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 text-slate-300 rounded inline-flex items-center justify-center gap-1.5">
                      <ShieldCheck size={13}/> Request risk acceptance
                    </Link>
                  )}
                  {exceptions.map(e => (
                    <Link key={e.id} to={`/exceptions/${e.id}`} className="block text-[12px] hover:bg-slate-800/30 -mx-1 px-1 py-1 rounded">
                      <Chip color={{pending_approval:"amber", active:"green", expired:"slate", rejected:"red"}[e.status] || "slate"}>{e.status?.replace("_"," ")}</Chip>
                      <div className="text-slate-400 mt-1.5">{e.business_justification || e.rationale}</div>
                      <div className="text-[10.5px] text-slate-500 mt-1">Expires {fmtDate(e.expires_at)}</div>
                    </Link>
                  ))}
                </>
              ) },
              comments: { title: "Comments", testid: "section-comments", content: (
                <>
                  <div className="space-y-2 mb-3">
                    {comments.length === 0 && <div className="text-[12px] text-slate-500">No comments yet.</div>}
                    {comments.map(c => (
                      <div key={c.id} className="border border-[#30363D] rounded p-2.5 bg-[#161B22]">
                        <div className="text-[10.5px] font-mono text-slate-500 flex items-center gap-1.5">
                          {c.author} · {fmtDate(c.created_at)}
                          {c.system && <span className="px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-300 text-[9.5px] font-sans">playbook</span>}
                        </div>
                        {c.text && <div className="text-[12.5px] text-slate-200 mt-1 whitespace-pre-wrap">{c.text}</div>}
                        {(c.attachments || []).length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-2">
                            {c.attachments.map((a, i) => a.mime?.startsWith("image/") ? (
                              <a key={i} href={a.data_url} target="_blank" rel="noopener noreferrer" title={a.name}>
                                <img src={a.data_url} alt={a.name} className="max-h-24 rounded border border-[#30363D] hover:border-blue-500/50"/>
                              </a>
                            ) : (
                              <a key={i} href={a.data_url} download={a.name} className="text-[11.5px] text-blue-300 hover:underline">📎 {a.name}</a>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                  {attachments.length > 0 && (
                    <div className="mb-2 flex flex-wrap gap-2">
                      {attachments.map((a, i) => (
                        <div key={i} className="flex items-center gap-1.5 px-2 py-1 border border-[#30363D] rounded bg-[#161B22] text-[11px]">
                          {a.mime?.startsWith("image/") && <img src={a.data_url} alt="" className="h-6 w-6 object-cover rounded"/>}
                          <span className="text-slate-300 truncate max-w-[140px]">{a.name}</span>
                          <button onClick={()=>setAttachments(attachments.filter((_,j)=>j!==i))} className="text-red-400 hover:text-red-300">×</button>
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="flex gap-2">
                    <input data-testid="comment-input" value={newComment} onChange={(e)=>setNewComment(e.target.value)} placeholder="Add a triage note (paste screenshot or attach below)…"
                      className="flex-1 h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200"
                      onPaste={(e) => { const items = e.clipboardData?.items; if (items) { const files=[]; for (const it of items) if (it.kind==='file') { const f=it.getAsFile(); if (f) files.push(f); } if (files.length) handleFiles(files); } }}
                    />
                    <label data-testid="comment-attach" className="h-8 px-2.5 text-[12px] border border-[#30363D] hover:border-blue-500/50 rounded inline-flex items-center gap-1 cursor-pointer text-slate-300">
                      📎
                      <input type="file" multiple accept="image/*,application/pdf" className="hidden" onChange={(e)=>handleFiles(e.target.files)}/>
                    </label>
                    <button data-testid="comment-add" onClick={addComment} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1">
                      <ChatCircle size={14}/> Add
                    </button>
                  </div>
                </>
              ) },
              playbook: { title: "Remediation Playbook", testid: "section-playbook", content: (
                <>

              {playbook === undefined && <div className="text-[12px] text-slate-500">Loading…</div>}
              {playbook === null && (
                <div className="space-y-2.5">
                  <div className="text-[12.5px] text-slate-500 flex items-center justify-between gap-3">
                    <span>No playbook yet for {f.cve || (f.cwe ? f.cwe : "this finding")}.</span>
                    <Link to={`/admin/playbooks?new=1&cve=${encodeURIComponent(f.cve||"")}&cwe=${encodeURIComponent(f.cwe||"")}`}
                      className="h-7 px-2.5 text-[11px] bg-blue-500/15 border border-blue-500/40 hover:bg-blue-500/25 text-blue-300 rounded inline-flex items-center gap-1 shrink-0">
                      <Plus size={11}/> Create one
                    </Link>
                  </div>
                  {allPlaybooks.length > 0 && (
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] text-slate-500 shrink-0">or attach an existing one:</span>
                      <select disabled={attachingPlaybook} defaultValue=""
                        onChange={(e) => { if (e.target.value) attachPlaybook(e.target.value); }}
                        className="h-8 flex-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200">
                        <option value="" disabled>Choose a playbook…</option>
                        {allPlaybooks.map(p => <option key={p.id} value={p.id}>{p.title}</option>)}
                      </select>
                    </div>
                  )}
                </div>
              )}
              {playbook && (
                <div>
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <BookOpen size={15} className="text-blue-300"/>
                    <Link to={`/admin/playbooks/${playbook.id}?finding=${id}`} className="text-[13px] text-slate-100 font-medium hover:underline hover:text-blue-200">{playbook.title}</Link>
                    <Chip color="blue">
                      {playbookBasis === "manual" ? "Manually attached" : playbookBasis === "cve" ? "Exact CVE match" : `CWE match: ${playbook.cwe}`}
                    </Chip>
                    {playbookProgress?.validated && <Chip color="green">Fix validated</Chip>}
                    <Link to={`/admin/playbooks/${playbook.id}?finding=${id}`} className="ml-auto text-[10.5px] text-blue-300 hover:underline shrink-0">Open interactive flow →</Link>
                  </div>
                  {playbook.description && <div className="text-[11.5px] text-slate-500 mb-2">{playbook.description}</div>}

                  {allPlaybooks.length > 0 && (
                    <div className="flex items-center gap-2 mb-3">
                      <span className="text-[10.5px] text-slate-500 shrink-0">Switch playbook:</span>
                      <select disabled={attachingPlaybook} value={playbookBasis === "manual" ? playbook.id : ""}
                        onChange={(e) => attachPlaybook(e.target.value || null)}
                        className="h-7 flex-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[11px] text-slate-300">
                        {playbookBasis !== "manual" && <option value="">{playbookBasis === "cve" ? "Exact CVE match" : "CWE match"} (auto)</option>}
                        {allPlaybooks.map(p => <option key={p.id} value={p.id}>{p.title}</option>)}
                      </select>
                      {playbookBasis === "manual" && (
                        <button onClick={() => attachPlaybook(null)} disabled={attachingPlaybook}
                          className="text-[10.5px] text-slate-400 hover:text-slate-200 shrink-0">Revert to auto-match</button>
                      )}
                    </div>
                  )}

                  <div className="flex items-center justify-between mb-1.5">
                    <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Steps — click to check off</div>
                    <div className="text-[10.5px] text-slate-500 font-mono">
                      {(playbookProgress?.steps_done?.length || 0)}/{playbook.steps.length}
                    </div>
                  </div>
                  <ol className="space-y-1 mb-3">
                    {playbook.steps.map((s, i) => {
                      const done = (playbookProgress?.steps_done || []).includes(i);
                      return (
                        <li key={i}>
                          <button onClick={() => toggleStep(i)}
                            className={`w-full flex items-start gap-2 text-[12.5px] text-left rounded px-2 py-1.5 -mx-2 transition-colors ${done ? "bg-emerald-500/5" : "hover:bg-[#161B22]"}`}>
                            {done
                              ? <CheckCircle size={15} weight="fill" className="text-emerald-400 mt-0.5 shrink-0"/>
                              : <span className="w-[15px] h-[15px] rounded-full border border-slate-600 mt-0.5 shrink-0"/>}
                            <span className={done ? "text-emerald-100/80 line-through decoration-emerald-500/40" : "text-slate-200"}>{s}</span>
                          </button>
                        </li>
                      );
                    })}
                  </ol>

                  {playbook.rollback_notes && (
                    <div className="mb-3 border border-amber-500/30 bg-amber-500/5 rounded p-2.5">
                      <div className="text-[10px] uppercase font-mono text-amber-400 tracking-wider mb-1 flex items-center gap-1.5">
                        <ArrowCounterClockwise size={12}/> Rollback notes
                      </div>
                      <div className="text-[12px] text-amber-100/90">{playbook.rollback_notes}</div>
                    </div>
                  )}

                  {playbook.validation_checks?.length > 0 && (
                    <div>
                      <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider mb-1.5 flex items-center gap-1.5">
                        <CheckCircle size={12}/> Validation checks — click to check off
                      </div>
                      <ul className="space-y-1">
                        {playbook.validation_checks.map((v, i) => {
                          const done = (playbookProgress?.validated_checks || []).includes(i);
                          return (
                            <li key={i}>
                              <button onClick={() => toggleCheck(i)}
                                className={`w-full flex items-start gap-1.5 text-[12px] text-left rounded px-2 py-1 -mx-2 transition-colors ${done ? "bg-emerald-500/5" : "hover:bg-[#161B22]"}`}>
                                <span className={done ? "text-emerald-400 mt-0.5" : "text-slate-600 mt-0.5"}>✓</span>
                                <span className={done ? "text-emerald-100/80 line-through decoration-emerald-500/40" : "text-slate-300"}>{v}</span>
                              </button>
                            </li>
                          );
                        })}
                      </ul>
                    </div>
                  )}
                </div>
              )}
                            </>
              ) },
              mitigations: { title: "Compensating Mitigations", testid: "section-mitigations", content: (
                <>

            <div className="text-[11.5px] text-slate-500 mb-2">Temporary controls applied while a real fix is pending -- separate from a formal risk exception.</div>
            {mitigations.length === 0 && <div className="text-[12px] text-slate-500 mb-2">None recorded yet.</div>}
            <div className="space-y-2 mb-2">
              {mitigations.map(m => (
                <div key={m.id} className="border border-[#30363D] rounded p-2.5 bg-[#161B22] flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5">
                      <Chip color={m.still_in_place ? "green" : "slate"}>{m.control_type}</Chip>
                      {!m.still_in_place && <span className="text-[10px] text-slate-500">removed {fmtDate(m.removed_at)}</span>}
                    </div>
                    <div className="text-[12px] text-slate-300 mt-1">{m.description}</div>
                    <div className="text-[10.5px] text-slate-500 mt-1">by {m.applied_by} · {fmtRel(m.applied_at)}</div>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    {m.still_in_place && (
                      <button onClick={async ()=>{ await api.patch(`/v1/mitigations/${m.id}`, {still_in_place:false}); loadMitigations(); }}
                        className="text-[10.5px] text-slate-400 hover:text-slate-200 border border-[#30363D] rounded px-2 h-6">Mark removed</button>
                    )}
                    <button onClick={async ()=>{ await api.delete(`/v1/mitigations/${m.id}`); loadMitigations(); }} className="text-slate-500 hover:text-red-400"><Trash size={13}/></button>
                  </div>
                </div>
              ))}
            </div>
            {!showAddMitigation ? (
              <button onClick={()=>setShowAddMitigation(true)} data-testid="add-mitigation-btn"
                className="text-[11.5px] text-blue-300 hover:text-blue-200 inline-flex items-center gap-1"><Plus size={12}/> Add mitigation</button>
            ) : (
              <AddMitigationForm
                types={mitigationTypes}
                onCancel={()=>setShowAddMitigation(false)}
                onAdded={()=>{ setShowAddMitigation(false); loadMitigations(); }}
                findingId={id}
              />
            )}
                          </>
              ) },
              risk_score: { title: "Risk Score", content: <RiskBar score={f.risk_score} /> },
              identifiers: { title: "Identifiers", content: (
                <>
                  <KV k="Internal ID" v={<span className="font-mono text-[10.5px]">{f.id}</span>} />
                  <KV k="CVE" v={f.cve} mono/>
                  <KV k="CWE" v={f.cwe} mono/>
                  <KV k="QID" v={f.qid} mono/>
                  <KV k="Plugin ID" v={f.plugin_id} mono/>
                  <KV k="Source ID" v={f.source_observation_id} mono/>
                  {f.port && <KV k="Port" v={`${f.port}/${f.protocol || "tcp"}`} mono/>}
                  {f.service && <KV k="Service" v={[f.service, f.service_product, f.service_version].filter(Boolean).join(" ")} />}
                </>
              ) },
              scoring: { title: "Scoring", content: (
                <>
                  <KV k="CVSS v3" v={f.cvss_score} mono/>
                  <KV k="CVSS Vector" v={<span className="font-mono text-[10px] break-all">{f.cvss_v3_vector}</span>} />
                  <KV k="EPSS" v={f.epss_score ? (f.epss_score*100).toFixed(2)+"%" : "—"} mono/>
                  <KV k="EPSS %ile" v={f.epss_percentile?.toFixed?.(1)} mono/>
                </>
              ) },
              exploits: (f.exploit_references || []).length > 0 ? { title: "Public Exploits", testid: "public-exploits-section", content: (
                <>
                  <div className="border border-orange-500/30 bg-orange-500/5 rounded-md px-3 py-2 mb-3 text-[11.5px] text-orange-200 leading-relaxed">
                    {f.exploit_references.length} public exploit{f.exploit_references.length === 1 ? "" : "s"} indexed for this CVE — a working
                    proof-of-concept exists in the wild, which materially lowers the bar for exploitation.
                  </div>
                  <div className="space-y-2">
                    {f.exploit_references.map((ex, i) => (
                      <a key={ex.edb_id || i} href={ex.url} target="_blank" rel="noopener noreferrer"
                        className="block border border-[#30363D] hover:border-orange-500/40 rounded-md px-3 py-2 transition-colors">
                        <div className="flex items-start justify-between gap-2">
                          <div className="text-[12px] text-slate-200 leading-snug">{ex.title || `Exploit-DB #${ex.edb_id}`}</div>
                          {ex.verified ? (
                            <span className="shrink-0 inline-flex items-center gap-1 text-[10px] text-emerald-400"><SealCheck size={12}/> Verified</span>
                          ) : (
                            <span className="shrink-0 inline-flex items-center gap-1 text-[10px] text-slate-500"><SealWarning size={12}/> Unverified</span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                          {ex.edb_id && <Chip color="orange">EDB-{ex.edb_id}</Chip>}
                          {ex.type && <Chip color="slate">{ex.type}</Chip>}
                          {ex.platform && <Chip color="slate">{ex.platform}</Chip>}
                          {ex.date_published && <span className="text-[10.5px] text-slate-500 font-mono">{ex.date_published}</span>}
                        </div>
                      </a>
                    ))}
                  </div>
                </>
              ) } : null,
              asset: { title: "Asset", content: (
                <>
                  <Link to={`/assets/${f.asset_id}`} className="text-blue-300 hover:underline font-mono text-[12.5px]">{f.asset_hostname}</Link>
                  <KV k="IP" v={f.asset_ip} mono/>
                  <KV k="Criticality" v={f.asset_criticality}/>
                  <KV k="Exposure" v={f.asset_exposure}/>
                  <KV k="Environment" v={f.asset_environment}/>
                  <KV k="Owner Team" v={f.owner_team}/>
                  <KV k="Ownership Confidence" v={f.ownership_confidence != null ? `${(f.ownership_confidence*100).toFixed(0)}%` : "—"} mono/>
                </>
              ) },
              sla: { title: "SLA / Lifecycle", content: (
                <>
                  <KV k="First Seen" v={fmtDate(f.first_seen_at)} mono/>
                  <KV k="Last Seen" v={fmtDate(f.last_seen_at)} mono/>
                  <KV k="Due" v={<span className={isOverdue(f.due_at) ? "text-red-300" : "text-slate-200"}>{fmtDate(f.due_at)}</span>} mono/>
                  <KV k="SLA (days)" v={f.sla_days} mono/>
                  <KV k="Days Open" v={f.days_open} mono/>
                </>
              ) },
              source: { title: "Source & Detection", content: (
                <>
                  <KV k="Source Tool" v={f.source_tool}/>
                  <KV k="Tool Type" v={f.source_tool_type}/>
                  <KV k="Scan Method" v={f.scan_method}/>
                  <KV k="Auth" v={f.scan_authenticated ? "Authenticated" : "Unauth"}/>
                  <KV k="Channel" v={f.detection_channel}/>
                  <KV k="Parser" v={`${f.parser_type || "—"} v${f.parser_version || "—"}`}/>
                </>
              ) },
              tickets: { title: "Tickets", content: (
                <>
                  {tickets.length === 0 && <div className="text-[12px] text-slate-500">No linked tickets.</div>}
                  {tickets.map(t => {
                    const notes = t.notes || [];
                    const last = notes[notes.length - 1];
                    return (
                      <div key={t.id} className="py-1.5 border-b border-[#30363D]/40 last:border-0">
                        <a href={t.url} target="_blank" rel="noopener noreferrer" className="flex justify-between gap-2 hover:text-blue-300">
                          <span className="font-mono text-[12px] text-blue-300">{t.external_id}</span>
                          <span className="text-[11px] text-slate-500">{t.system} · {t.status}</span>
                        </a>
                        {last && (
                          <div className="text-[11px] text-slate-500 mt-1">
                            Latest: <span className="text-slate-400 whitespace-pre-wrap">{last.text.split("\n")[0]}</span>
                            {notes.length > 1 && <span className="text-slate-600"> (+{notes.length - 1} more)</span>}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </>
              ) },
              references: { title: "References", content: (
                <>
                  {(f.advisory_links || []).map((l, i) => {
                    const url = typeof l === "string" ? l : l?.url;
                    const label = typeof l === "string" ? l : (l?.source || l?.url || "Reference");
                    return url ? <a key={i} href={url} target="_blank" rel="noopener noreferrer" className="block text-[12px] text-blue-300 hover:underline truncate">{label}</a> : null;
                  })}
                  {(f.external_references || []).slice(0, 12).map((r, i) => {
                    const url = Array.isArray(r) ? r[0] : (r?.url || (typeof r === "string" ? r : null));
                    const label = Array.isArray(r) ? (r[1] || r[0]) : (r?.source || r?.url || "Ref");
                    return url ? <a key={`e-${i}`} href={url} target="_blank" rel="noopener noreferrer" className="block text-[12px] text-slate-400 hover:text-blue-300 hover:underline truncate">{label}</a> : null;
                  })}
                </>
              ) },
            };

            return sidebarOrder.map(key => {
              const sec = sidebarSections[key];
              if (!sec) return null;
              return (
                <div key={key}
                  draggable={customizingLayout}
                  onDragStart={() => onTileDragStart(key)}
                  onDragOver={(e) => customizingLayout && e.preventDefault()}
                  onDrop={() => customizingLayout && onTileDrop(key)}
                  className={customizingLayout ? "cursor-move" : undefined}
                >
                  <Section title={sec.title} testid={sec.testid}>
                    {customizingLayout && (
                      <div className="flex items-center gap-1.5 text-slate-600 mb-2 -mt-1 select-none">
                        <DotsSixVertical size={14}/><span className="text-[10px] uppercase font-mono">Drag to reorder</span>
                      </div>
                    )}
                    {sec.content}
                  </Section>
                </div>
              );
            });
          })()}
        </div>
      </div>
    </Layout>
  );
}
