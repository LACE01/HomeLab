import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { SlackLogo, CheckCircle, XCircle, Eye, EyeSlash, Copy } from "@phosphor-icons/react";

export default function ChatOps() {
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [signingSecret, setSigningSecret] = useState("");
  const [workspaceLabel, setWorkspaceLabel] = useState("");
  const [showSecret, setShowSecret] = useState(false);
  const [saving, setSaving] = useState(false);

  const endpointUrl = `${window.location.origin}/api/v1/chatops/slack/command`;

  const load = async () => {
    try {
      const r = await api.get("/v1/admin/chatops/config");
      setConfig(r.data);
      setWorkspaceLabel(r.data.workspace_label || "");
    } catch (e) {
      toast.error("Failed to load ChatOps config");
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const save = async () => {
    if (!signingSecret.trim()) { toast.error("Paste your Slack app's Signing Secret first"); return; }
    setSaving(true);
    try {
      await api.put("/v1/admin/chatops/config", {
        signing_secret: signingSecret.trim(), enabled: true, workspace_label: workspaceLabel || null,
      });
      toast.success("ChatOps enabled");
      setSigningSecret("");
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Save failed");
    } finally { setSaving(false); }
  };

  const disable = async () => {
    try {
      await api.post("/v1/admin/chatops/config/disable");
      toast.success("ChatOps disabled");
      load();
    } catch (e) { toast.error("Failed to disable"); }
  };

  const copyEndpoint = () => {
    navigator.clipboard.writeText(endpointUrl);
    toast.success("Copied");
  };

  if (loading) return <Layout title="ChatOps"><div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div></Layout>;

  return (
    <Layout title="ChatOps" subtitle="Run VulnOps triage commands from Slack without leaving chat">
      <div className="grid grid-cols-2 gap-5 max-w-5xl">
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-5">
          <div className="flex items-center gap-2 mb-4">
            <SlackLogo size={20} className="text-slate-300"/>
            <div className="text-[14px] text-slate-100 font-medium">Slack Setup</div>
            {config?.enabled ? (
              <span className="ml-auto inline-flex items-center gap-1 text-[11px] text-emerald-400"><CheckCircle size={13}/> Enabled</span>
            ) : (
              <span className="ml-auto inline-flex items-center gap-1 text-[11px] text-slate-500"><XCircle size={13}/> Disabled</span>
            )}
          </div>

          <ol className="text-[12px] text-slate-400 space-y-2 mb-5 list-decimal list-inside leading-relaxed">
            <li>Create a Slack app at <span className="text-blue-300">api.slack.com/apps</span> (from scratch, in your workspace)</li>
            <li>Under <b>Features → Slash Commands</b>, create a command — e.g. <code className="font-mono bg-black/30 px-1 rounded">/vulnops</code></li>
            <li>Set its <b>Request URL</b> to the endpoint below</li>
            <li>Under <b>Basic Information</b>, copy the <b>Signing Secret</b> and paste it here</li>
            <li>Install the app to your workspace</li>
          </ol>

          <div className="mb-4">
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Request URL</label>
            <div className="flex gap-2">
              <input readOnly value={endpointUrl} className="flex-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[11.5px] text-slate-300 font-mono"/>
              <button onClick={copyEndpoint} className="h-9 w-9 flex items-center justify-center text-slate-400 hover:text-slate-200 rounded border border-[#30363D]">
                <Copy size={14}/>
              </button>
            </div>
          </div>

          <div className="mb-4">
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Signing Secret</label>
            <div className="flex gap-2">
              <input
                type={showSecret ? "text" : "password"}
                value={signingSecret}
                onChange={e => setSigningSecret(e.target.value)}
                placeholder={config?.signing_secret_set ? "•••••••••••••••• (already set — paste to replace)" : "Paste your Slack app's signing secret"}
                className="flex-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100 font-mono"
              />
              <button onClick={() => setShowSecret(s => !s)} className="h-9 w-9 flex items-center justify-center text-slate-400 hover:text-slate-200 rounded border border-[#30363D]">
                {showSecret ? <EyeSlash size={14}/> : <Eye size={14}/>}
              </button>
            </div>
          </div>

          <div className="mb-5">
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Workspace label (optional)</label>
            <input value={workspaceLabel} onChange={e => setWorkspaceLabel(e.target.value)}
              placeholder="e.g. Acme Corp Slack"
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100"/>
          </div>

          <div className="flex gap-2">
            <button onClick={save} disabled={saving}
              className="h-9 px-4 text-[12.5px] bg-blue-500 hover:bg-blue-400 disabled:opacity-40 text-white rounded">
              {saving ? "Saving…" : config?.configured ? "Update & Enable" : "Enable ChatOps"}
            </button>
            {config?.enabled && (
              <button onClick={disable} className="h-9 px-4 text-[12.5px] text-slate-400 hover:text-slate-200 rounded border border-[#30363D]">
                Disable
              </button>
            )}
          </div>

          <div className="mt-5 border border-amber-500/30 bg-amber-500/5 rounded-md px-3 py-2.5 text-[11.5px] text-amber-200 leading-relaxed">
            Anyone who can run this command in your Slack workspace gets full read/write access to findings —
            there's no per-person mapping back to VulnOps accounts. Restrict the slash command to a trusted
            channel in Slack's own settings, and treat the signing secret like a credential.
          </div>
        </div>

        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-5">
          <div className="text-[14px] text-slate-100 font-medium mb-4">Available Commands</div>
          <div className="space-y-3 text-[12.5px]">
            {[
              { cmd: "/vulnops status", desc: "Open finding counts + current security score" },
              { cmd: "/vulnops top [n]", desc: "Top N open findings by risk score (default 5)" },
              { cmd: "/vulnops find <query>", desc: "Natural-language search, e.g. \"critical kev on windows\"" },
              { cmd: "/vulnops assign <id> <team>", desc: "Assign a finding to an owner team" },
              { cmd: "/vulnops fix <id>", desc: "Mark a finding Fixed pending validation" },
              { cmd: "/vulnops help", desc: "Show this list in Slack" },
            ].map(c => (
              <div key={c.cmd} className="border-b border-[#30363D]/50 last:border-0 pb-3 last:pb-0">
                <code className="text-blue-300 font-mono text-[12px]">{c.cmd}</code>
                <div className="text-slate-500 text-[11.5px] mt-0.5">{c.desc}</div>
              </div>
            ))}
          </div>
          <div className="mt-4 text-[11px] text-slate-500 leading-relaxed">
            For <code className="font-mono">&lt;id&gt;</code>, the first 6-8 characters of a finding ID are enough,
            as long as they're unambiguous — VulnOps will ask you to be more specific if there's more than one match.
          </div>
        </div>
      </div>
    </Layout>
  );
}
