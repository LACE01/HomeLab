import { useState } from "react";
import { useAuth } from "@/lib/auth";
import { useNavigate } from "react-router-dom";
import { Bug, ShieldStar } from "@phosphor-icons/react";

export default function Login() {
  const { login } = useAuth();
  const nav = useNavigate();
  const [email, setEmail] = useState("admin@vulnops.io");
  const [pwd, setPwd] = useState("admin123");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const onSubmit = async (e) => {
    e.preventDefault();
    setErr(""); setBusy(true);
    try { await login(email, pwd); nav("/"); }
    catch (ex) { setErr(ex.response?.data?.detail || "Login failed"); }
    finally { setBusy(false); }
  };

  const demoLogins = [
    { email: "admin@vulnops.io", pwd: "admin123", role: "Admin" },
    { email: "analyst@vulnops.io", pwd: "analyst123", role: "Analyst" },
    { email: "manager@vulnops.io", pwd: "manager123", role: "Manager" },
    { email: "exec@vulnops.io", pwd: "exec123", role: "Executive" },
  ];

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#090C10] px-4">
      <div className="w-full max-w-[440px]">
        <div className="flex items-center gap-2 mb-6">
          <Bug size={28} weight="duotone" className="text-blue-400" />
          <div>
            <div className="text-[20px] font-semibold tracking-tight text-slate-100">VulnOps</div>
            <div className="text-[11px] font-mono text-slate-500 uppercase tracking-wider">Vulnerability Operations Platform</div>
          </div>
        </div>

        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-6">
          <div className="flex items-center gap-2 mb-4">
            <ShieldStar size={18} className="text-slate-400" />
            <h2 className="text-[14px] font-medium text-slate-200">Sign in</h2>
          </div>
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
        </div>

        <div className="mt-4 border border-[#30363D] bg-[#0D1117] rounded-md p-3">
          <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-2">Demo accounts</div>
          <div className="grid grid-cols-2 gap-1.5">
            {demoLogins.map((d) => (
              <button key={d.email} type="button" data-testid={`demo-${d.role.toLowerCase()}`}
                onClick={() => { setEmail(d.email); setPwd(d.pwd); }}
                className="text-left px-2 py-1.5 rounded bg-[#161B22] hover:bg-[#1f2630] border border-[#30363D]">
                <div className="text-[11px] text-slate-200">{d.role}</div>
                <div className="text-[10px] font-mono text-slate-500 truncate">{d.email}</div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
