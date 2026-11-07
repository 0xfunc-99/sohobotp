#!/bin/sh
# Runs the portal unit and end-to-end checks in throwaway containers:
# PHP 8.4 (with ldap/bcmath) plus a test OpenLDAP directory on a private network.
# Usage (from the repository root):  sh portal/tests/run-in-docker.sh
set -eu
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DOCKERDIR="$REPO/portal/tests/docker"
RUN="portal-test-$$"

docker build -q -t multiotp-portal-php -f "$DOCKERDIR/php.Dockerfile" "$DOCKERDIR" >/dev/null
docker build -q -t multiotp-test-ldap "$DOCKERDIR/ldap" >/dev/null
docker network create "$RUN" >/dev/null
cleanup() { docker rm -f "$RUN-ldap" >/dev/null 2>&1 || true; docker network rm "$RUN" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run -d --name "$RUN-ldap" --network "$RUN" --network-alias ldap multiotp-test-ldap >/dev/null

docker run --rm --network "$RUN" -v "$REPO":/src:ro multiotp-portal-php sh -euc '
  cp -R /src /app
  mkdir -p /tmp/etc/config /tmp/etc/users /tmp/etc/tokens /tmp/log /tmp/portal
  export MULTIOTP_ETC_DIR=/tmp/etc MULTIOTP_LOG_DIR=/tmp/log MULTIOTP_PORTAL_DATA=/tmp/portal
  cd /app

  echo "== PHP syntax"
  for f in $(find portal -name "*.php") multiotp.class.php multiotp.server.php contrib/MultiotpAdLdap.php; do php -l "$f" >/dev/null; done
  echo "all files parse"

  echo "== unit checks"
  php portal/tests/unit.php

  echo "== end-to-end checks"
  rm -rf /tmp/portal/* /tmp/etc/users/* && mkdir -p /tmp/portal
  TEMP=$(php portal/bin/portal-admin.php create --username=root --role=superadmin | sed -n "s/^Temporary password.*: //p")
  MULTIOTP_PORTAL_ALLOW_HTTP=1 php -d display_errors=stderr -S 127.0.0.1:8080 -t /app >/tmp/server.log 2>&1 &
  php portal/bin/worker.php --loop >/tmp/worker.log 2>&1 &
  sleep 1
  STATUS=0
  php portal/tests/e2e.php http://127.0.0.1:8080 "$TEMP" || STATUS=$?
  echo "== CLI"
  php portal/bin/portal-admin.php list
  php portal/bin/portal-admin.php verify-audit
  echo "== worker log"; cat /tmp/worker.log
  if grep -qiE "fatal|warning|notice|multiOTP portal" /tmp/server.log; then
    echo "== PHP messages from the test server"; grep -iE "fatal|warning|notice|multiOTP portal" /tmp/server.log | sort | uniq -c | head -40
  fi
  exit $STATUS
'
