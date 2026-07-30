import axios from "axios";

// REACT_APP_BACKEND_URL is baked in at BUILD time, not read at runtime. If the
// build ran without frontend/.env present, this is `undefined` and every request
// in the app goes to the literal string "undefined/api" -- which fails as a
// network error, with no response object. The login page then falls back to
// "Login failed", which reads exactly like a wrong password. That is a bad
// failure mode: an infrastructure problem disguised as a credential problem.
//
// So we detect it here and say so, rather than letting it masquerade.
const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

/** True when the frontend was built without REACT_APP_BACKEND_URL. Nothing can
 *  work in this state, and no amount of retrying the password will help. */
export const BACKEND_URL_MISSING =
  !BACKEND_URL || BACKEND_URL === "undefined" || BACKEND_URL === "null";

if (BACKEND_URL_MISSING && typeof console !== "undefined") {
  console.error(
    "[VulnOps] REACT_APP_BACKEND_URL was not set when this frontend was built, so " +
    "every API call will fail. Fix: ensure frontend/.env contains REACT_APP_BACKEND_URL " +
    "and rebuild the frontend image (the value is compiled in, not read at runtime)."
  );
}

export const API = BACKEND_URL_MISSING ? "/api" : `${BACKEND_URL}/api`;

export const api = axios.create({
  baseURL: API,
  withCredentials: true,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("vulnops_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401 && !window.location.pathname.startsWith("/login")) {
      localStorage.removeItem("vulnops_token");
      window.location.href = "/login";
    }
    return Promise.reject(err);
  }
);

/** Is the API process up and can it reach Mongo?
 *
 *  /api/v1/healthz needs no auth, so this answers "is the backend there" without
 *  a valid session -- which is the whole point: it lets a failed login say
 *  whether the credentials were rejected or the request never arrived. */
export async function probeBackend() {
  if (BACKEND_URL_MISSING) {
    return { reachable: false, reason: "config" };
  }
  try {
    const r = await api.get("/v1/healthz", { timeout: 8000 });
    if (r.data?.status === "ok") return { reachable: true, reason: "ok" };
    return { reachable: true, reason: "database", detail: r.data?.error };
  } catch (e) {
    if (!e.response) return { reachable: false, reason: "unreachable" };
    if ([502, 503, 504].includes(e.response.status)) {
      return { reachable: false, reason: "gateway", status: e.response.status };
    }
    // Something answered on the API path but it isn't our API -- typically a
    // proxy error page or an auth interstitial in front of the backend.
    return { reachable: false, reason: "not_api", status: e.response.status };
  }
}

/** Turn a failed sign-in into a sentence that names what actually went wrong.
 *
 *  A login can fail for reasons that have nothing to do with the password, and
 *  they need different actions: the backend being down is a `docker compose`
 *  problem, a rate-limit is a wait, a bad password is a retype. Collapsing all of
 *  them into "Login failed" costs real debugging time. `probe` is the result of
 *  probeBackend(), passed in so the caller controls whether to spend that
 *  round-trip. */
export function describeLoginError(ex, probe) {
  const status = ex?.response?.status;
  const detail = ex?.response?.data?.detail;

  // No response at all: the request never reached the API.
  if (!ex?.response) {
    if (probe?.reason === "config") {
      return "This app was built without its backend URL configured, so it can't reach the API at " +
             "all — your password is not the problem. Set REACT_APP_BACKEND_URL in frontend/.env " +
             "and rebuild the frontend.";
    }
    if (probe?.reason === "gateway") {
      return `The API is not responding (HTTP ${probe.status} from the proxy). The backend container ` +
             "is most likely down or still starting — check its logs.";
    }
    if (probe?.reason === "not_api") {
      return `Something answered at the API address with HTTP ${probe.status}, but it wasn't this ` +
             "platform's API. Check the reverse proxy / tunnel route for /api.";
    }
    return "Couldn't reach the server, so your credentials were never checked. The backend may be " +
           "down, still starting, or blocked by the network between here and it.";
  }

  if (probe?.reason === "database") {
    return "The API is up but can't reach its database, so logins can't be verified. " +
           (probe.detail ? `Database error: ${probe.detail}` : "Check the MongoDB container.");
  }
  if (status === 401) return detail || "Invalid credentials.";
  if (status === 429) return detail || "Too many failed attempts — wait a few minutes and try again.";
  if ([502, 503, 504].includes(status)) {
    return `The API returned HTTP ${status} — the backend is down or restarting, not a credential problem.`;
  }
  if (status >= 500) {
    return `The server errored (HTTP ${status}) while checking the login. ${detail || "Check the backend logs."}`;
  }
  return detail || `Sign-in failed (HTTP ${status}).`;
}
