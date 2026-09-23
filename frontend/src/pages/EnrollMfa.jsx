import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { webauthnSupported, startRegistration } from "@/lib/webauthnBrowser";

// First-login forced MFA enrollment gate (#67/#68). Offers a phishing-resistant
// security key / passkey (preferred, and REQUIRED for roles in phishing_resistant_
// roles) and an authenticator-app (TOTP) fallback. Unskippable: after enrolling it
// re-checks /auth/me and only proceeds once the server clears must_enroll_mfa.
export default function EnrollMfa() {
  const { user, setUser, logout } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState(null);           // null | "totp" | "webauthn"
  const [waConfigured, setWaConfigured] = useState(false);
  const [setup, setSetup] = useState(null);         // TOTP {secret, otpauth_url}
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState(null);

  useEffect(() => {
    api.get("/auth/webauthn/credentials").then(r => setWaConfigured(!!r.data?.configured)).catch(() => {});
  }, []);

  const refreshGate = async () => {
    try {
      const me = (await api.get("/auth/me")).data;
      setUser(me);
      if (!me.must_enroll_mfa) { navigate("/"); return true; }
      toast.message("Your role requires a phishing-resistant security key or passkey.");
      setMode("webauthn");
      return false;
    } catch { navigate("/"); return true; }
  };

  const startTotp = async () => {
    setMode("totp");
    try { setSetup((await api.post("/auth/mfa/setup")).data); }
    catch { toast.error("Could not start authenticator setup"); }
  };

  const confirmTotp = async () => {
    if (!code.trim()) return;
    setBusy(true);
    try {
      const r = await api.post("/auth/mfa/confirm", { code: code.trim() });
      setRecoveryCodes(r.data.recovery_codes || []);
    } catch (e) {
      toast.error(e.response?.data?.detail || "That code didn't match — check your app's clock and retry");
    } finally { setBusy(false); }
  };

  const enrollWebauthn = async () => {
    if (!webauthnSupported()) { toast.error("This browser doesn't support security keys / passkeys"); return; }
    setBusy(true);
    try {
      const opts = (await api.post("/auth/webauthn/register/begin")).data;
      const cred = await startRegistration(opts);
      const name = window.prompt("Name this security key / passkey:", "My security key") || "Security key";
      await api.post("/auth/webauthn/register/complete", { credential: cred, name });
      toast.success("Security key registered");
      await refreshGate();
    } catch (e) {
      toast.error(e.response?.data?.detail || e.message || "Registration failed or was cancelled");
    } finally { setBusy(false); }
  };

  const Wrap = (children) => (
    <div className="min-h-screen flex items-center justify-center bg-[#090C10] px-4">
      <div className="w-full max-w-md border border-[#30363D] bg-[#0D1117] rounded-lg p-6">
        <div className="text-[15px] font-semibold text-slate-100 mb-1">Set up two-factor authentication</div>
        <div className="text-[12.5px] text-slate-400 mb-4 leading-relaxed">
          Your role requires MFA before you can use the app.
        </div>
        {children}
        <button onClick={logout} className="w-full h-9 mt-3 text-[12px] text-slate-500 hover:text-slate-300">Sign out</button>
      </div>
    </div>
  );

  if (recoveryCodes) {
    return Wrap(
      <div>
        <div className="text-[12.5px] text-amber-200 bg-amber-500/10 border border-amber-500/30 rounded p-3 mb-3 leading-relaxed">
          Save these recovery codes — each works once and is the only way back in if you lose your authenticator.
        </div>
        <div className="font-mono text-[12.5px] text-slate-200 grid grid-cols-2 gap-1 mb-4">
          {recoveryCodes.map(c => <div key={c}>{c}</div>)}
        </div>
        <button onClick={refreshGate} className="w-full h-9 text-[13px] rounded bg-blue-500/20 border border-blue-500/40 text-blue-200 hover:bg-blue-500/30">
          I've saved them — continue
        </button>
      </div>
    );
  }

  if (mode === "totp" && setup) {
    return Wrap(
      <div>
        <div className="text-[12px] text-slate-400 mb-2">Scan in an authenticator app, or enter the secret manually:</div>
        <div className="font-mono text-[13px] text-slate-100 bg-[#161B22] border border-[#30363D] rounded px-3 py-2 mb-2 break-all">{setup.secret}</div>
        <div className="text-[10px] text-slate-600 font-mono break-all mb-3">{setup.otpauth_url}</div>
        <input value={code} onChange={e => setCode(e.target.value)} inputMode="numeric" placeholder="6-digit code"
          onKeyDown={e => e.key === "Enter" && confirmTotp()}
          className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[13px] text-slate-100 mb-3" />
        <button onClick={confirmTotp} disabled={busy || !code.trim()}
          className="w-full h-9 text-[13px] rounded bg-blue-500/20 border border-blue-500/40 text-blue-200 hover:bg-blue-500/30 disabled:opacity-50">
          {busy ? "Verifying…" : "Verify & enable"}
        </button>
        <button onClick={() => { setMode(null); setSetup(null); }} className="w-full h-8 mt-2 text-[12px] text-slate-500 hover:text-slate-300">Back</button>
      </div>
    );
  }

  // method chooser
  return Wrap(
    <div className="space-y-2">
      {waConfigured && (
        <button onClick={enrollWebauthn} disabled={busy}
          className="w-full text-left border border-blue-500/40 bg-blue-500/10 hover:bg-blue-500/20 rounded p-3 disabled:opacity-50">
          <div className="text-[13px] text-blue-100 font-medium">Security key or passkey {busy ? "…" : "(recommended)"}</div>
          <div className="text-[11.5px] text-slate-400">Phishing-resistant — YubiKey, Touch ID/Windows Hello, or a phone passkey.</div>
        </button>
      )}
      <button onClick={startTotp} disabled={busy}
        className="w-full text-left border border-[#30363D] hover:border-slate-500 rounded p-3 disabled:opacity-50">
        <div className="text-[13px] text-slate-100 font-medium">Authenticator app (TOTP)</div>
        <div className="text-[11.5px] text-slate-400">Google Authenticator, Authy, 1Password, etc.</div>
      </button>
    </div>
  );
}
