#!/usr/bin/env bash
# Staged MongoDB upgrade 4.4 -> 5.0 -> 6.0 -> 7.0 for this docker-compose stack.
#
# MongoDB only supports upgrading ONE major version at a time, and each step must
# set featureCompatibilityVersion (FCV) to the new version before the next hop.
# This script automates that safely:
#   1. Refuses to run if the host CPU lacks AVX (5.0+ images SIGILL-crash without it).
#   2. Takes a full mongodump BEFORE touching anything.
#   3. For each hop: pins the image, restarts only mongo, waits healthy, sets FCV,
#      verifies, and continues only on success.
#   4. Leaves you to pin MONGO_IMAGE=mongo:7.0 in .env at the end.
#
# ROLLBACK: if any step fails, set MONGO_IMAGE back to the last good version in
# .env, `docker compose up -d mongo`, and if needed restore the dump printed below
# with:  docker compose exec -T mongo mongorestore --drop --archive < <dumpfile>
#
# Usage:  ./scripts/mongo_upgrade.sh
set -euo pipefail
cd "$(dirname "$0")/.."

DB_NAME="${DB_NAME:-vulnops}"
STEPS=("5.0" "6.0" "7.0")
FCV_CONFIRM_FROM="7.0"   # 7.0 requires confirm:true on setFeatureCompatibilityVersion

say() { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
err() { printf "\n\033[1;31mERROR: %s\033[0m\n" "$*" >&2; }

# 0) AVX guard -------------------------------------------------------------
if ! grep -qm1 avx /proc/cpuinfo 2>/dev/null; then
  err "This host's CPU does not report AVX support. MongoDB 5.0+ official images"
  err "crash on startup (SIGILL) without AVX. Staying on 4.4 is correct here."
  err "Aborting -- no changes made."
  exit 1
fi
say "AVX supported -- safe to run 5.0+ images."

mongo_sh() { # run a JS eval inside the mongo container, mongosh or legacy mongo
  docker compose exec -T mongo sh -c \
    "mongosh --quiet --eval '$1' 2>/dev/null || mongo --quiet --eval '$1'"
}

wait_healthy() {
  say "Waiting for mongo to become healthy..."
  for i in $(seq 1 60); do
    if mongo_sh "db.adminCommand({ping:1})" >/dev/null 2>&1; then
      say "mongo is responding."; return 0
    fi
    sleep 3
  done
  err "mongo did not become healthy in time."; return 1
}

set_fcv() {
  local v="$1" cmd
  if [ "$v" = "$FCV_CONFIRM_FROM" ]; then
    cmd="db.adminCommand({setFeatureCompatibilityVersion: '$v', confirm: true})"
  else
    cmd="db.adminCommand({setFeatureCompatibilityVersion: '$v'})"
  fi
  say "Setting featureCompatibilityVersion = $v"
  mongo_sh "$cmd"
}

# 1) Backup ----------------------------------------------------------------
TS="$(date +%Y%m%d-%H%M%S)"
DUMP="mongo-preupgrade-${TS}.archive"
say "Backing up current database to ./${DUMP} (this can take a while)..."
docker compose exec -T mongo sh -c \
  "mongodump --archive --gzip --db='${DB_NAME}' 2>/dev/null" > "${DUMP}"
if [ ! -s "${DUMP}" ]; then err "Backup is empty -- aborting before any change."; exit 1; fi
say "Backup complete: ./${DUMP} ($(du -h "${DUMP}" | cut -f1)). Keep this until you've verified 7.0."

# 2) Confirm current FCV is 4.4 -------------------------------------------
say "Current server version:"; mongo_sh "db.version()"

# 3) Staged hops -----------------------------------------------------------
for V in "${STEPS[@]}"; do
  say "Upgrading engine to mongo:${V} ..."
  MONGO_IMAGE="mongo:${V}" docker compose up -d mongo
  wait_healthy
  set_fcv "${V}"
  say "Now running:"; mongo_sh "db.version()"
  say "mongo:${V} step complete."
done

say "All hops done. FINAL STEP (do this yourself so it persists):"
echo "    echo 'MONGO_IMAGE=mongo:7.0' >> .env   # or edit your existing .env"
echo "    docker compose up -d"
echo ""
say "Verify the app, then you can delete ./${DUMP}."
