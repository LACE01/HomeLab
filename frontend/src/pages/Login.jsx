import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import { useNavigate } from "react-router-dom";
import { Binoculars, ShieldStar, DeviceMobile, ArrowLeft, WindowsLogo } from "@phosphor-icons/react";
import { FcGoogle } from "react-icons/fc";
import { api, API } from "@/lib/api";

export default function Login() {
  const { login, verifyMfa } = useAuth();
  const nav = useNavigate();
  const [email, setEmail] = useState("");
  const [pwd, setPwd] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [entraConfigured, setEntraConfigured] = useState(false);

  // Set once the password step succeeds on an MFA-enabled account -- switches the
  // form to the "enter your 6-digit code (or a recovery code)" step instead of
  // finishing the login. mfaToken is short-lived (5 min) and is only good for
  // /auth/mfa/verify, nothing else.
  const [mfaToken, setMfaToken] = useState(null);
  const [mfaCode, setMfaCode] = useState("");

  useEffect(() => {
    // Whether to show "Sign in with Microsoft" at all -- depends on both
    // ENTRA_SSO_ENABLED and the Microsoft Entra ID connector's app registration
    // actually being configured, so ask the backend rather than guessing from an
    // env var alone (see routes/auth.py's /auth/entra/status).
    api.get("/auth/entra/status").then(r => setEntraConfigured(!!r.data?.configured)).catch(() => {});

    if (new URLSearchParams(window.location.search).get("error") === "entra_sso") {
      setErr("Microsoft sign-in didn't complete -- try again, or use email/password below.");
    }
  }, []);

  const onSubmit = async (e) => {
    e.preventDefault();
    setErr(""); setBusy(true);
    try {
      const result = await login(email, pwd);
      if (result?.mfaRequired) { setMfaToken(result.mfaToken); }
      else { nav("/"); }
    }
    catch (ex) { setErr(ex.response?.data?.detail || "Login failed"); }
    finally { setBusy(false); }
  };

  const onSubmitMfa = async (e) => {
    e.preventDefault();
    setErr(""); setBusy(true);
    try { await verifyMfa(mfaToken, mfaCode.trim()); nav("/"); }
    catch (ex) { setErr(ex.response?.data?.detail || "Invalid code"); }
    finally { setBusy(false); }
  };

  // REMINDER: DO NOT HARDCODE THE URL, OR ADD ANY FALLBACKS OR REDIRECT URLS, THIS BREAKS THE AUTH
  const signInWithGoogle = () => {
    const redirectUrl = window.location.origin + "/";
    window.location.href = `https://auth.emergentagent.com/?redirect=${encodeURIComponent(redirectUrl)}`;
  };

  // Full-page navigation (not an XHR) -- the backend handles the entire OAuth
  // authorization-code exchange server-side and redirects back to "/" with a
  // session cookie already set. See routes/auth.py's entra_sso_login/_callback.
  const signInWithMicrosoft = () => {
    window.location.href = `${API}/auth/entra/login`;
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#090C10] px-4">
      <div className="w-full max-w-[440px]">
        <div className="flex items-center gap-2 mb-6">
          <Binoculars size={28} weight="duotone" className="text-blue-400" />
          <div>
            <div className="text-[20px] font-semibold tracking-tight text-slate-100">Nightwatch</div>
            <div className="text-[11px] font-mono text-slate-500 uppercase tracking-wider">Security Operations Platform</div>
          </div>
        </div>

        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-6">
          {mfaToken ? (
            <>
              <div className="flex items-center gap-2 mb-1">
                <DeviceMobile size={18} className="text-slate-400" />
                <h2 className="text-[14px] font-medium text-slate-200">Enter your authenticator code</h2>
              </div>
              <div className="text-[11.5px] text-slate-500 mb-4">
                Open your authenticator app for the 6-digit code, or use one of your recovery codes if you've lost the device.
              </div>
              <form onSubmit={onSubmitMfa} className="space-y-3">
                <div>
                  <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Code</label>
                  <input data-testid="mfa-code" autoFocus value={mfaCode} onChange={(e)=>setMfaCode(e.target.value)}
                    placeholder="123456" inputMode="numeric"
                    className="w-full mt-1 px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100 font-mono tracking-widest focus:outline-none focus:ring-1 focus:ring-blue-500" />
                </div>
                {err && <div data-testid="login-error" className="text-[12px] text-red-400">{err}</div>}
                <button data-testid="mfa-submit" disabled={busy || !mfaCode.trim()}
                  className="w-full h-9 bg-blue-500 hover:bg-blue-400 text-white text-[13px] font-medium rounded transition-colors disabled:opacity-50">
                  {busy ? "Verifying…" : "Verify"}
                </button>
                <button type="button" onClick={() => { setMfaToken(null); setMfaCode(""); setErr(""); }}
                  className="w-full h-8 text-[12px] text-slate-500 hover:text-slate-300 inline-flex items-center justify-center gap-1.5">
                  <ArrowLeft size={12}/> Back to sign in
                </button>
              </form>
            </>
          ) : (
            <>
              <div className="flex items-center gap-2 mb-4">
                <ShieldStar size={18} className="text-slate-400" />
                <h2 className="text-[14px] font-medium text-slate-200">Sign in</h2>
              </div>

              {/* Google sign-in disabled for self-hosted deployments: it originally
                  redirected to Emergent's own hosted OAuth page (auth.emergentagent.com),
                  which this instance no longer depends on. Email/password below is the
                  primary login path. Set REACT_APP_ENABLE_GOOGLE_SIGNIN=true and wire a
                  real Google OAuth client to bring this back. */}
              {process.env.REACT_APP_ENABLE_GOOGLE_SIGNIN === "true" && (
                <>
                  <button
                    data-testid="google-signin"
                    type="button"
                    onClick={signInWithGoogle}
                    className="w-full h-9 bg-white hover:bg-slate-100 text-slate-900 text-[13px] font-medium rounded transition-colors flex items-center justify-center gap-2"
                  >
                    <FcGoogle size={18}/> Continue with Google
                  </button>

                  <div className="flex items-center gap-3 my-4">
                    <div className="flex-1 h-px bg-[#30363D]"/>
                    <span className="text-[10px] font-mono text-slate-600 uppercase tracking-wider">or email</span>
                    <div className="flex-1 h-px bg-[#30363D]"/>
                  </div>
                </>
              )}

              {/* Microsoft Entra ID SSO -- shown only once the backend confirms
                  ENTRA_SSO_ENABLED + a redirect URI + the Entra ID connector's app
                  registration are all actually configured (see /auth/entra/status). */}
              {entraConfigured && (
                <>
                  <button
                    data-testid="microsoft-signin"
                    type="button"
                    onClick={signInWithMicrosoft}
                    className="w-full h-9 bg-[#2F2F2F] hover:bg-[#3a3a3a] text-white text-[13px] font-medium rounded transition-colors flex items-center justify-center gap-2"
                  >
                    <WindowsLogo size={18} weight="fill" className="text-blue-400"/> Sign in with Microsoft
                  </button>

                  <div className="flex items-center gap-3 my-4">
                    <div className="flex-1 h-px bg-[#30363D]"/>
                    <span className="text-[10px] font-mono text-slate-600 uppercase tracking-wider">or email</span>
                    <div className="flex-1 h-px bg-[#30363D]"/>
                  </div>
                </>
              )}

              <form onSubmit={onSubmit} className="space-y-3">
                <div>
                  <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Email</label>
                  <input data-testid="login-email" type="email" value={email} onChange={(e)=>setEmail(e.target.value)}
                    className="w-full mt-1 px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100 focus:outline-none focus:ring-1 focus:ring-blue-500" />
                </div>
                <div>
                  <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Password</label>
                  <input data-testid="login-password" type="password" value={pwd} onChange={(e)=>setPwd(e.target.value)}
                    className="w-full mt-1 px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100 focus:outline-none focus:ring-1 focus:ring-blue-500" />
                </div>
                {err && <div data-testid="login-error" className="text-[12px] text-red-400">{err}</div>}
                <button data-testid="login-submit" disabled={busy}
                  className="w-full h-9 bg-blue-500 hover:bg-blue-400 text-white text-[13px] font-medium rounded transition-colors disabled:opacity-50">
                  {busy ? "Signing in…" : "Sign in"}
                </button>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
