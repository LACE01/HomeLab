import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { ShieldStar, Warning } from "@phosphor-icons/react";

// Forced first-login password change: an admin-created account starts with
// must_change_password=true (see backend/routes/admin.py create_user), and
// App.js's Protected wrapper redirects here for every route until it's cleared --
// there is no way to reach the rest of the app with a temp password still active.
// New password is entered twice specifically to catch typos, since there's no
// "forgot password" self-service flow yet -- a typo here otherwise locks the user
// out with no way back in except an admin resetting it again.
export default function ChangePassword() {
  const { user, setUser, logout } = useAuth();
  const navigate = useNavigate();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const forced = !!user?.must_change_password;

  const submit = async (e) => {
    e.preventDefault();
    setErr("");
    if (next.length < 8) { setErr("New password must be at least 8 characters."); return; }
    if (next !== confirm) { setErr("New password entries don't match — check for typos and try again."); return; }
    if (next === current) { setErr("New password must be different from your current one."); return; }
    setBusy(true);
    try {
      await api.post("/auth/change-password", { current_password: current, new_password: next });
      // Reflect the cleared flag immediately so Protected stops redirecting here,
      // without requiring a full re-login.
      if (typeof setUser === "function") setUser({ ...user, must_change_password: false });
      navigate("/");
    } catch (ex) {
      setErr(ex.response?.data?.detail || "Could not change password");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#090C10] px-4">
      <div className="w-full max-w-[440px]">
        <div className="flex items-center gap-2 mb-6">
          <ShieldStar size={28} weight="duotone" className="text-blue-400" />
          <div>
            <div className="text-[20px] font-semibold tracking-tight text-slate-100">
              {forced ? "Set a new password" : "Change password"}
            </div>
            <div className="text-[11px] font-mono text-slate-500 uppercase tracking-wider">
              {forced ? "Required before you can continue" : "VulnOps account"}
            </div>
          </div>
        </div>

        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-6">
          {forced && (
            <div className="border border-amber-500/30 bg-amber-500/5 rounded-md px-3 py-2.5 mb-4 text-[12px] text-amber-200 leading-relaxed flex items-start gap-2">
              <Warning size={15} className="shrink-0 mt-0.5"/>
              <span>You're signed in with a temporary password. Set your own before continuing — you won't be able to use any other part of VulnOps until this is done.</span>
            </div>
          )}
          <form onSubmit={submit} className="space-y-3.5">
            <div>
              <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">
                {forced ? "Temporary password" : "Current password"}
              </label>
              <input data-testid="cp-current" type="password" value={current} onChange={(e)=>setCurrent(e.target.value)}
                autoFocus required className="w-full mt-1 h-10 bg-[#161B22] border border-[#30363D] rounded px-3 text-[13px] text-slate-100"/>
            </div>
            <div>
              <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">New password</label>
              <input data-testid="cp-new" type="password" value={next} onChange={(e)=>setNext(e.target.value)}
                required minLength={8} className="w-full mt-1 h-10 bg-[#161B22] border border-[#30363D] rounded px-3 text-[13px] text-slate-100"/>
              <div className="text-[10.5px] text-slate-500 mt-1">At least 8 characters.</div>
            </div>
            <div>
              <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Confirm new password</label>
              <input data-testid="cp-confirm" type="password" value={confirm} onChange={(e)=>setConfirm(e.target.value)}
                required minLength={8} className="w-full mt-1 h-10 bg-[#161B22] border border-[#30363D] rounded px-3 text-[13px] text-slate-100"/>
            </div>
            {err && <div className="text-[12.5px] text-red-400">{err}</div>}
            <button data-testid="cp-submit" type="submit" disabled={busy}
              className="w-full h-10 bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white text-[13px] font-medium rounded transition-colors">
              {busy ? "Saving…" : "Set new password"}
            </button>
            {!forced && (
              <button type="button" onClick={()=>navigate(-1)} className="w-full h-9 text-[12.5px] text-slate-400 hover:text-slate-200">
                Cancel
              </button>
            )}
          </form>
        </div>

        {forced && (
          <button onClick={logout} className="w-full mt-3 text-[12px] text-slate-500 hover:text-slate-300 text-center">
            Sign out instead
          </button>
        )}
      </div>
    </div>
  );
}
