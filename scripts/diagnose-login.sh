#!/usr/bin/env bash
# Where does a login actually break?
#
# "Login failed" in the browser is the same sentence for a dead backend, a
# proxy that isn't proxying, a frontend built pointing at the wrong URL, a
# rate-limit lockout, and a genuinely wrong password. This walks the chain from
# the outside in and prints which link is broken, so you stop guessing.
#
# Run it ON THE DOCKER HOST:
#     bash scripts/diagnose-login.sh                       # infrastructure only
#     bash scripts/diagnose-login.sh you@example.com        # also test a real account
#
# It never asks for your password. The account test deliberately sends a
# wrong one: a 401 proves the whole path works, which is all we need to know.
set -uo pipefail

PORT="${HOST_PORT:-6969}"
BASE="http://localhost:${PORT}"
EMAIL="${1:-}"

pass() { printf '  \033[32mOK\033[0m    %s\n' "$1"; }
fail() { printf '  \033[31mBROKEN\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m?\033[0m     %s\n' "$1"; }
note() { printf '        %s\n' "$1"; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

command -v curl >/dev/null || { echo "curl is required"; exit 1; }
DC="docker compose"; $DC version >/dev/null 2>&1 || DC="docker-compose"

# ---------------------------------------------------------------- 1. containers
step "1. Containers"
$DC ps --format '  {{.Service}}\t{{.State}}\t{{.Status}}' 2>/dev/null || $DC ps
note "'unhealthy' on backend alone does not block traffic -- keep reading."

# ------------------------------------------------------------------- 2. frontend
step "2. Frontend (nginx) is serving the app"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$BASE/login")
if [ "$code" = "200" ]; then pass "GET $BASE/login -> 200"
else fail "GET $BASE/login -> ${code:-no response}"
     note "The frontend container isn't serving. Check: $DC logs frontend"
     exit 1
fi

# ---------------------------------------------------- 3. which API URL was baked
# REACT_APP_BACKEND_URL is substituted into the bundle at BUILD time. If the build
# ran with no value, the bundle contains the literal string "undefined/api" and
# every request goes somewhere that does not exist -- with the page itself loading
# fine, which is what makes this so confusing. Grep the shipped JS for it.
step "3. What API URL is compiled into the shipped bundle?"
if bundle=$($DC exec -T frontend sh -c 'cat /usr/share/nginx/html/static/js/*.js 2>/dev/null' 2>/dev/null); then
  if printf '%s' "$bundle" | grep -q 'undefined/api'; then
    fail 'the bundle contains "undefined/api"'
    note "The frontend was built with no REACT_APP_BACKEND_URL. Rebuild it:"
    note "  $DC build --no-cache frontend && $DC up -d frontend"
    note "docker-compose.yml passes \"\" on purpose (same-origin) -- don't set it to a URL."
  elif printf '%s' "$bundle" | grep -qE 'https?://[^\"'\'']+/api'; then
    warn "the bundle has an ABSOLUTE backend URL compiled in:"
    printf '%s' "$bundle" | grep -oE 'https?://[^"'\'' ]+/api' | sort -u | head -3 | sed 's/^/          /'
    note "Loaded from $BASE, the browser will send API calls to that host instead"
    note "of this one -- so a LAN login goes out to the internet and can be blocked"
    note "there. For same-origin, rebuild with REACT_APP_BACKEND_URL=\"\"."
  else
    pass "same-origin (relative /api) -- correct for this compose file"
  fi
else
  warn "couldn't read the bundle ($DC exec failed); skipping"
fi

# ------------------------------------------------- 4. nginx -> backend proxy
step "4. nginx is proxying /api to the backend"
body=$(curl -s --max-time 10 "$BASE/api/v1/healthz")
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$BASE/api/v1/healthz")
case "$code" in
  200)
    if printf '%s' "$body" | grep -q '"status": *"ok"'; then
      pass "GET /api/v1/healthz -> 200 {\"status\":\"ok\"} (API up, database reachable)"
    elif printf '%s' "$body" | grep -qi '<!doctype html\|<html'; then
      # The most deceptive outcome: nginx's SPA fallback (try_files ... /index.html)
      # answers 200 with the app's own HTML, so the request "succeeds" and the JSON
      # parse fails later somewhere unrelated.
      fail "GET /api/v1/healthz -> 200 but returned HTML, not JSON"
      note "nginx served the SPA fallback instead of proxying to the backend, so"
      note "NOTHING under /api is reaching the API. Check the 'location /api/' block"
      note "in frontend/nginx.conf survived the last build:"
      note "  $DC exec frontend cat /etc/nginx/conf.d/default.conf"
      exit 1
    else
      fail "healthz answered 200 but not ok: $body"
      note "The API is running but cannot reach MongoDB. No login can succeed."
      note "Check: $DC logs mongo"
      exit 1
    fi ;;
  502|503|504)
    fail "GET /api/v1/healthz -> $code"
    note "nginx can't reach the backend container. Check: $DC logs backend"
    exit 1 ;;
  404)
    fail "GET /api/v1/healthz -> 404"
    note "nginx isn't proxying /api/. Check the location /api/ block in nginx.conf."
    exit 1 ;;
  *)
    fail "GET /api/v1/healthz -> ${code:-no response}"; exit 1 ;;
esac

# --------------------------------------------------- 5. the login endpoint itself
step "5. The login endpoint accepts and answers a POST"
resp=$(curl -s -w '\n%{http_code}' --max-time 10 -X POST "$BASE/api/auth/login" \
        -H 'Content-Type: application/json' \
        -d '{"email":"diagnostic-probe@invalid.local","password":"deliberately-wrong"}')
code=$(printf '%s' "$resp" | tail -n1)
body=$(printf '%s' "$resp" | sed '$d')
case "$code" in
  401)
    pass "POST /api/auth/login -> 401 $(printf '%s' "$body" | head -c 120)"
    note "The full chain browser -> nginx -> backend -> Mongo works. A 'Login failed'"
    note "in the browser at this point is NOT infrastructure." ;;
  429)
    fail "POST /api/auth/login -> 429 (rate-limited)"
    note "$body"
    note "Repeated failed attempts locked this out. It clears on its own; the window"
    note "is LOCKOUT_WINDOW_MINUTES in backend/routes/auth.py."
    note "To clear it now: $DC exec mongo mongo \${DB_NAME:-vulnops} \\"
    note "  --eval 'db.login_audit.deleteMany({success:false})'" ;;
  405) fail "POST -> 405: something is answering that isn't the API (proxy misroute)" ;;
  ""|000) fail "POST got no response at all -- the request never completed" ;;
  *) warn "POST /api/auth/login -> $code"; note "$body" ;;
esac

# --------------------------------------------------------- 6. the actual account
if [ -n "$EMAIL" ]; then
  step "6. The account $EMAIL"
  db="${DB_NAME:-vulnops}"
  out=$($DC exec -T mongo mongo --quiet "$db" --eval "
    var u = db.users.findOne({email: '${EMAIL,,}'});
    if (!u) { print('MISSING'); } else {
      print(['FOUND', u.active === false ? 'INACTIVE' : 'active',
             u.mfa_enabled ? 'MFA-ON' : 'no-mfa',
             u.password_hash ? 'has-password' : 'NO-PASSWORD-HASH',
             u.must_change_password ? 'must-change-password' : ''].join(' '));
    }" 2>/dev/null | tr -d '\r')
  case "$out" in
    *MISSING*)
      fail "no user with that email exists in database '$db'"
      note "If you expected one, the deployment may be pointed at a different DB_NAME."
      note "Users present:"
      $DC exec -T mongo mongo --quiet "$db" --eval \
        'db.users.find({},{email:1,role:1,_id:0}).forEach(function(u){print("          "+u.email+"  "+u.role)})' 2>/dev/null ;;
    *NO-PASSWORD-HASH*)
      fail "$out"
      note "This account has no password set -- it can only sign in via SSO." ;;
    *INACTIVE*)
      fail "$out"
      note "A disabled account returns 401 'Account disabled'." ;;
    *FOUND*)
      pass "$out"
      case "$out" in *MFA-ON*)
        note "MFA is on: the password step returns mfa_required and the UI must then"
        note "ask for a 6-digit code. If it doesn't, that's the bug." ;;
      esac ;;
    *) warn "couldn't query Mongo: ${out:-no output}" ;;
  esac

  step "Recent login attempts for this account (newest first)"
  $DC exec -T mongo mongo --quiet "$db" --eval "
    db.login_audit.find({email:'${EMAIL,,}'}).sort({\$natural:-1}).limit(8).forEach(function(a){
      print('          ' + (a.timestamp||a.created_at||'?') + '  ' +
            (a.success ? 'SUCCESS' : 'FAILED') + '  ' + (a.reason||'') + '  ip=' + (a.ip||'?'));
    })" 2>/dev/null | grep . || note "no attempts recorded"
  note "IMPORTANT: if your failed browser attempts are NOT listed here, the request"
  note "never reached the backend -- look at the browser's Network tab, not the server."
fi

step "Summary"
note "Everything above OK but the browser still says 'Login failed'?"
note "Then the request is dying in the browser. Open devtools -> Network, click"
note "Sign in, and look at the auth/login row: the URL it went to and the status."
note "A red/failed row with no status, or a URL pointing at a different host, is"
note "the answer. The Console tab will show a JS error if one was thrown."
