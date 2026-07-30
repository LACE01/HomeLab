import axios from "axios";

// REACT_APP_BACKEND_URL is substituted in at BUILD time, not read at runtime, and
// it has THREE meaningful states -- conflating them is a trap:
//
//   ""         -> deliberate. docker-compose.yml passes an empty string so the
//                 app calls same-origin "/api" and the frontend's nginx proxies
//                 to the backend. This is the normal self-hosted setup and is
//                 completely valid. An empty string is falsy, so a naive
//                 truthiness check flags the standard deployment as broken.
//   a URL      -> deliberate. Cross-origin backend.
//   undefined  -> a mistake. The build ran with no value at all, so the bundle
//                 contains the literal string "undefined" and every request goes
//                 to "undefined/api", failing as a network error with no
//                 response object. The login page then says "Login failed",
//                 which reads exactly like a wrong password -- an infrastructure
//                 problem wearing a credential problem's costume.
//
// Only the third state is a fault, so only the third state is reported.
const RAW_BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

/** True only when the build had NO value for REACT_APP_BACKEND_URL. An empty
 *  string is a valid same-origin configuration, not a fault. */
export const BACKEND_URL_MISSING =
  RAW_BACKEND_URL === undefined || RAW_BACKEND_URL === null ||
  RAW_BACKEND_URL === "undefined" || RAW_BACKEND_URL === "null";

const BACKEND_URL = BACKEND_URL_MISSING ? "" : RAW_BACKEND_URL;

if (BACKEND_URL_MISSING && typeof console !== "undefined") {
  console.error(
    "[VulnOps] REACT_APP_BACKEND_URL had no value when this frontend was built. " +
    "Pass it as a build arg (docker-compose passes \"\" for same-origin) -- the value " +
    "is compiled into the bundle, not read at runtime."
  );
}

// Same-origin when empty: "/api", which is what the frontend nginx proxies.
export const API = `${BACKEND_URL}/api`;

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

  // A failure with no response is NOT automatically a network problem. If the
  // error didn't come from axios at all, it's a bug in our own code that threw
  // before or after the call (for example the post-login profile/module-access
  // fetch failing, which rejects login() even though the password was accepted).
  // Blaming the network for that sends you to inspect infrastructure that is
  // working fine.
  if (ex && !ex.response && !ex.request && ex.isAxiosError !== true) {
    if (typeof console !== "undefined") console.error("[VulnOps] sign-in threw:", ex);
    return `Sign-in hit an error in the app itself, not a rejected password: ` +
           `${ex.name || "Error"}: ${ex.message || String(ex)}. The browser console has the stack.`;
  }

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
