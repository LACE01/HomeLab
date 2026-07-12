import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import {
  Devices, Desktop, DeviceMobile, Globe, SignOut, Key, ShieldCheck, Clock,
  DeviceMobileCamera, Copy, Check, Warning, X,
} from "@phosphor-icons/react";

// Self-service security settings -- every authenticated user gets this regardless
// of role (it's not in rbac.py's MODULE_REGISTRY, same reasoning as
// /change-password: managing your own sessions/password/MFA isn't a
// module-permission question, it's inherent to having an account at all).
function deviceIcon(userAgent) {
  const ua = (userAgent || "").toLowerCase();
  if (ua.includes("mobile") || ua.includes("android") || ua.includes("iphone")) return DeviceMobile;
  return Desktop;
}

function SessionsSection() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [revokingId, setRevokingId] = useState(null);

  const load = () => {
    setLoading(true);
    api.get("/v1/auth/sessions").then(r => setItems(r.data.items || [])).finally(() => setLoading(false));
  };
  useEffect(() => { load(); }, []);

  const revoke = async (session) => {
    if (session.is_current) {
      if (!window.confirm("This is your current session -- revoking it will sign you out right now. Continue?")) return;
    }
    setRevokingId(session.id);
    try {
      await api.delete(`/v1/auth/sessions/${session.id}`);
      if (session.is_current) {
        window.location.href = "/login";
        return;
      }
      toast.success("Session signed out");
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to revoke session");
    } finally { setRevokingId(null); }
  };

  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
      <div className="flex items-center gap-2 mb-1">
        <Devices size={16} className="text-slate-400"/>
        <div className="text-[13.5px] text-slate-100 font-medium">Active Sessions</div>
      </div>
      <div className="text-[11.5px] text-slate-500 mb-3">
        Every device currently signed into your account. If you see one you don't recognize, sign it out here --
        it takes effect immediately, no matter what that session is in the middle of doing.
      </div>
      {loading ? (
        <div className="text-[12px] text-slate-500 py-4 text-center">Loading…</div>
      ) : items.length === 0 ? (
        <div className="text-[12px] text-slate-500 py-4 text-center">No active sessions.</div>
      ) : (
        <div className="divide-y divide-[#30363D]">
          {items.map(it => {
            const Icon = deviceIcon(it.user_agent);
            return (
              <div key={it.id} className="py-3 flex items-start justify-between gap-3">
                <div className="min-w-0 flex items-start gap-2.5">
                  <Icon size={18} className="text-slate-500 shrink-0 mt-0.5"/>
                  <div className="min-w-0">
                    <div className="text-[12.5px] text-slate-200 flex items-center gap-2">
                      {it.user_agent || "Unknown client"}
                      {it.is_current && (
                        <span className="text-[10px] uppercase tracking-wider font-mono text-emerald-400 border border-emerald-500/30 bg-emerald-500/10 rounded px-1.5 py-0.5">This device</span>
                      )}
                    </div>
                    <div className="text-[11px] text-slate-500 mt-0.5 flex items-center gap-2 flex-wrap">
                      <span className="inline-flex items-center gap-1"><Globe size={11}/> {it.ip || "unknown ip"}</span>
                      <span className="inline-flex items-center gap-1"><Clock size={11}/> Signed in {it.created_at ? new Date(it.created_at).toLocaleString() : "—"}</span>
                    </div>
                  </div>
                </div>
                <button onClick={() => revoke(it)} disabled={revokingId === it.id}
                  className="h-8 px-2.5 text-[11.5px] border border-[#30363D] hover:border-red-500/50 hover:text-red-300 text-slate-300 rounded inline-flex items-center gap-1.5 disabled:opacity-40 shrink-0">
                  <SignOut size={13}/> {revokingId === it.id ? "Signing out…" : "Sign out"}
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function CopyableCode({ text }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard?.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <button onClick={copy} title="Copy" className="inline-flex items-center gap-1.5 text-slate-400 hover:text-slate-200">
      {copied ? <Check size={13} className="text-emerald-400"/> : <Copy size={13}/>}
    </button>
  );
}

function MfaSetupFlow({ secret, otpauthUrl, onDone, onCancel }) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState(null);

  const confirm = async (e) => {
    e.preventDefault();
    setErr(""); setBusy(true);
    try {
      const r = await api.post("/auth/mfa/confirm", { code: code.trim() });
      setRecoveryCodes(r.data.recovery_codes);
    } catch (ex) {
      setErr(ex.response?.data?.detail || "That code didn't work");
    } finally { setBusy(false); }
  };

  if (recoveryCodes) {
    return (
      <div>
        <div className="flex items-center gap-2 mb-2 text-emerald-300">
          <Check size={16}/>
          <div className="text-[13px] font-medium">Two-factor authentication is now on</div>
        </div>
        <div className="border border-amber-500/30 bg-amber-500/5 rounded-md px-3 py-2.5 text-[12px] text-amber-200 mb-3 flex items-start gap-2">
          <Warning size={15} className="shrink-0 mt-0.5"/>
          <div>Save these recovery codes somewhere safe -- each one works once, and is the only way back into your
            account if you lose access to your authenticator app. They will not be shown again.</div>
        </div>
        <div className="grid grid-cols-2 gap-2 font-mono text-[12px] text-slate-200 bg-[#161B22] border border-[#30363D] rounded-md p-3 mb-3">
          {recoveryCodes.map(c => <div key={c}>{c}</div>)}
        </div>
        <button onClick={onDone} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">
          Done
        </button>
      </div>
    );
  }

  return (
    <div>
      <div className="text-[12px] text-slate-400 mb-2">
        Scan this into an authenticator app (Google Authenticator, Authy, 1Password, etc.), or enter the secret manually:
      </div>
      <div className="flex items-center gap-2 bg-[#161B22] border border-[#30363D] rounded-md px-3 py-2 mb-1 font-mono text-[12.5px] text-slate-200">
        {secret} <CopyableCode text={secret}/>
      </div>
      <div className="text-[10.5px] text-slate-600 font-mono break-all mb-3">{otpauthUrl}</div>
      <form onSubmit={confirm} className="space-y-2.5">
        <input value={code} onChange={e=>setCode(e.target.value)} autoFocus placeholder="6-digit code from your app"
          inputMode="numeric"
          className="w-full h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100 font-mono tracking-widest"/>
        {err && <div className="text-[12px] text-red-400">{err}</div>}
        <div className="flex gap-2">
          <button type="submit" disabled={busy || !code.trim()}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">
            {busy ? "Verifying…" : "Verify & enable"}
          </button>
          <button type="button" onClick={onCancel} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

function MfaSection() {
  const [enabled, setEnabled] = useState(null);
  const [setupData, setSetupData] = useState(null); // {secret, otpauth_url}
  const [disabling, setDisabling] = useState(false);
  const [disablePassword, setDisablePassword] = useState("");
  const [busy, setBusy] = useState(false);

  const load = () => api.get("/auth/mfa/status").then(r => setEnabled(r.data.enabled));
  useEffect(() => { load(); }, []);

  const startSetup = async () => {
    const r = await api.post("/auth/mfa/setup");
    setSetupData(r.data);
  };

  const submitDisable = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post("/auth/mfa/disable", { password: disablePassword });
      toast.success("Two-factor authentication turned off");
      setDisabling(false); setDisablePassword("");
      load();
    } catch (ex) {
      toast.error(ex.response?.data?.detail || "Failed to disable");
    } finally { setBusy(false); }
  };

  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
      <div className="flex items-center gap-2 mb-1">
        <DeviceMobileCamera size={16} className="text-slate-400"/>
        <div className="text-[13.5px] text-slate-100 font-medium">Two-Factor Authentication</div>
      </div>
      <div className="text-[11.5px] text-slate-500 mb-3">
        Require a code from an authenticator app in addition to your password when signing in.
      </div>

      {enabled === null ? null : setupData ? (
        <MfaSetupFlow secret={setupData.secret} otpauthUrl={setupData.otpauth_url}
          onDone={() => { setSetupData(null); load(); }} onCancel={() => setSetupData(null)}/>
      ) : enabled ? (
        disabling ? (
          <form onSubmit={submitDisable} className="space-y-2.5 max-w-xs">
            <input type="password" value={disablePassword} onChange={e=>setDisablePassword(e.target.value)}
              placeholder="Confirm your password" autoFocus
              className="w-full h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100"/>
            <div className="flex gap-2">
              <button type="submit" disabled={busy || !disablePassword}
                className="h-8 px-3 text-[12px] bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-200 rounded disabled:opacity-50">
                {busy ? "Turning off…" : "Confirm turn off"}
              </button>
              <button type="button" onClick={() => { setDisabling(false); setDisablePassword(""); }}
                className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
            </div>
          </form>
        ) : (
          <div className="flex items-center gap-3">
            <span className="text-[11px] uppercase tracking-wider font-mono text-emerald-400 border border-emerald-500/30 bg-emerald-500/10 rounded px-2 py-1 inline-flex items-center gap-1">
              <Check size={11}/> Enabled
            </span>
            <button onClick={() => setDisabling(true)} className="text-[12px] text-slate-400 hover:text-red-300">Turn off</button>
          </div>
        )
      ) : (
        <button onClick={startSetup} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
          <DeviceMobileCamera size={14}/> Set up two-factor authentication
        </button>
      )}
    </div>
  );
}

export default function Security() {
  return (
    <Layout title="Security" subtitle="Manage your password, two-factor authentication, and active sessions">
      <div className="max-w-2xl space-y-4">
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <div className="flex items-center gap-2 mb-1">
            <Key size={16} className="text-slate-400"/>
            <div className="text-[13.5px] text-slate-100 font-medium">Password</div>
          </div>
          <div className="text-[11.5px] text-slate-500 mb-3">
            Change your password at any time -- you'll need your current one.
          </div>
          <Link to="/change-password"
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
            <ShieldCheck size={14}/> Change password
          </Link>
        </div>

        <MfaSection/>
        <SessionsSection/>
      </div>
    </Layout>
  );
}
