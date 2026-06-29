import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "@/lib/api";

// REMINDER: DO NOT HARDCODE THE URL, OR ADD ANY FALLBACKS OR REDIRECT URLS, THIS BREAKS THE AUTH
export default function AuthCallback() {
  const nav = useNavigate();
  const processed = useRef(false);

  useEffect(() => {
    if (processed.current) return;
    processed.current = true;

    const hash = window.location.hash || "";
    const m = hash.match(/session_id=([^&]+)/);
    if (!m) { nav("/login", { replace: true }); return; }
    const session_id = decodeURIComponent(m[1]);

    api.post("/auth/google/session", { session_id })
      .then((r) => {
        // Clear hash so we don't reprocess
        window.history.replaceState({}, document.title, window.location.pathname);
        nav("/", { replace: true, state: { user: r.data.user } });
      })
      .catch(() => nav("/login?error=oauth", { replace: true }));
  }, [nav]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#090C10] text-slate-400">
      <div className="text-center">
        <div className="text-[13px]">Completing sign-in…</div>
        <div className="text-[11px] font-mono text-slate-600 mt-1">verifying Google session</div>
      </div>
    </div>
  );
}
