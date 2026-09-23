import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";

// First-login forced MFA enrollment gate (#67/#68). Unskippable: the Protected
// router sends users here whenever their role requires MFA and they haven't enrolled.
export default function EnrollMfa() {
  const { user, setUser, logout } = useAuth();
  const navigate = useNavigate();
  const [setup, setSetup] = useState(null);      // {secret, otpauth_url}
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState(null);

  useEffect(() => {
    api.post("/auth/mfa/setup").then(r => setSetup(r.data))
      .catch(() => toast.error("Could not start MFA setup"));
  }, []);

  const confirm = async () => {
    if (!code.trim()) return;
    setBusy(true);
    try {
      const r = await api.post("/auth/mfa/confirm", { code: code.trim() });
      setRecoveryCodes(r.data.recovery_codes || []);
    } catch (e) {
      toast.error(e.response?.data?.detail || "That code didn't match — check your app's clock and retry");
    } finally { setBusy(false); }
  };

  const finish = () => {
    if (typeof setUser === "function") setUser({ ...user, must_enroll_mfa: false, mfa_enabled: true });
    navigate("/");
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#090C10] px-4">
      <div className="w-full max-w-md border border-[#30363D] bg-[#0D1117] rounded-lg p-6">
        <div className="text-[15px] font-semibold text-slate-100 mb-1">Set up two-factor authentication</div>
        <div className="text-[12.5px] text-slate-400 mb-4 leading-relaxed">
          Your role requires MFA. Add this account to an authenticator app, then enter a code to finish. This is
          required before you can use the app.
        </div>

        {recoveryCodes ? (
          <div>
            <div className="text-[12.5px] text-amber-200 bg-amber-500/10 border border-amber-500/30 rounded p-3 mb-3 leading-relaxed">
              Save these recovery codes somewhere safe — each works once and is the only way back in if you lose your
              authenticator.
            </div>
            <div className="font-mono text-[12.5px] text-slate-200 grid grid-cols-2 gap-1 mb-4">
              {recoveryCodes.map(c => <div key={c}>{c}</div>)}
            </div>
            <button onClick={finish} className="w-full h-9 text-[13px] rounded bg-blue-500/20 border border-blue-500/40 text-blue-200 hover:bg-blue-500/30">
              I've saved them — continue
            </button>
          </div>
        ) : setup ? (
          <div>
            <div className="text-[12px] text-slate-400 mb-2">Scan in Google Authenticator / Authy / 1Password, or enter the secret manually:</div>
            <div className="font-mono text-[13px] text-slate-100 bg-[#161B22] border border-[#30363D] rounded px-3 py-2 mb-2 break-all">{setup.secret}</div>
            <div className="text-[10px] text-slate-600 font-mono break-all mb-3">{setup.otpauth_url}</div>
            <input value={code} onChange={e => setCode(e.target.value)} inputMode="numeric" placeholder="6-digit code"
              onKeyDown={e => e.key === "Enter" && confirm()}
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[13px] text-slate-100 mb-3"/>
            <button onClick={confirm} disabled={busy || !code.trim()}
              className="w-full h-9 text-[13px] rounded bg-blue-500/20 border border-blue-500/40 text-blue-200 hover:bg-blue-500/30 disabled:opacity-50">
              {busy ? "Verifying…" : "Verify & enable"}
            </button>
          </div>
        ) : (
          <div className="text-[12.5px] text-slate-500">Starting setup…</div>
        )}

        <button onClick={logout} className="w-full h-9 mt-3 text-[12px] text-slate-500 hover:text-slate-300">Sign out</button>
      </div>
    </div>
  );
}
