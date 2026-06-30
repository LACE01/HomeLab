import { createContext, useContext, useEffect, useState } from "react";
import { api } from "@/lib/api";

const AuthCtx = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // CRITICAL: Skip /me check if we're returning from OAuth (hash contains session_id).
    // AuthCallback will exchange the session_id and establish the session first.
    if (typeof window !== "undefined" && window.location.hash?.includes("session_id=")) {
      setLoading(false);
      return;
    }
    const token = localStorage.getItem("vulnops_token");
    const hasSessionCookie = typeof document !== "undefined" && document.cookie.includes("session_token=");
    // Skip the /me probe entirely when there's no token AND no session cookie —
    // it would just produce a noisy 401 in the console on the initial login page.
    if (!token && !hasSessionCookie) {
      setLoading(false);
      return;
    }
    // Try /auth/me — works with either JWT token OR session_token cookie
    api.get("/auth/me")
      .then((r) => setUser(r.data))
      .catch(() => { if (token) localStorage.removeItem("vulnops_token"); })
      .finally(() => setLoading(false));
  }, []);

  const login = async (email, password) => {
    const r = await api.post("/auth/login", { email, password });
    localStorage.setItem("vulnops_token", r.data.token);
    setUser(r.data.user);
    return r.data.user;
  };

  const logout = async () => {
    try { await api.post("/auth/logout"); } catch {}
    localStorage.removeItem("vulnops_token");
    setUser(null);
  };

  return (
    <AuthCtx.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthCtx.Provider>
  );
};

export const useAuth = () => useContext(AuthCtx);
