#!/bin/sh
# Linux agent end-to-end test against the production image (portal + nginx + FreeRADIUS +
# worker) and a Debian endpoint with SSH, sudo and pam_radius.
# Usage (from the repository root):  sh agent/tests/e2e-linux.sh
set -eu
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
RUN="sohobotp-e2e-$$"
APP="$RUN-portal"
CLI="$RUN-debian"
TMP="$(mktemp -d)"
STATUS=0

sh "$REPO/agent/tests/run-in-docker.sh" >/dev/null
case "$(docker info --format '{{.Architecture}}')" in
  aarch64|arm64) BIN="$REPO/agent/dist/sohobotp-agent-linux-arm64" ;;
  *) BIN="$REPO/agent/dist/sohobotp-agent-linux-amd64" ;;
esac
docker build -q -t multiotp-portal-appliance:dev "$REPO" >/dev/null
docker build -q -t sohobotp-test-debian "$REPO/agent/tests/docker/debian" >/dev/null
docker network create "$RUN" >/dev/null
cleanup() { docker rm -f "$APP" "$CLI" >/dev/null 2>&1 || true; docker network rm "$RUN" >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT

docker run -d --name "$APP" --network "$RUN" --network-alias portal.test multiotp-portal-appliance:dev >/dev/null
printf 'Waiting for the portal'
for i in $(seq 1 90); do
  docker exec "$APP" sh -c 'pidof freeradius >/dev/null && pidof nginx >/dev/null && pgrep -f "worker.php --loop" >/dev/null' 2>/dev/null && { echo " ready"; break; }
  printf '.'; sleep 2
done

# A test CA and a certificate for portal.test: the agent verifies TLS, never skips it
docker exec "$APP" sh -euc '
  cd /tmp
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=SohobOTP test CA" -keyout ca.key -out ca.pem \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj /CN=portal.test -keyout srv.key -out srv.csr 2>/dev/null
  printf "subjectAltName=DNS:portal.test\nextendedKeyUsage=serverAuth\n" > ext
  openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext -out srv.crt 2>/dev/null
  cp srv.crt /etc/multiotp/certificates/multiotp.crt && cp srv.key /etc/multiotp/certificates/multiotp.key
  nginx -s reload'
docker cp "$APP:/tmp/ca.pem" "$TMP/ca.pem"
docker cp "$REPO/agent/tests/e2e/portal.php" "$APP:/tmp/e2e-portal.php"
docker exec "$APP" chmod 0644 /tmp/e2e-portal.php
portal() { docker exec "$APP" su -s /bin/sh www-data -c "php /tmp/e2e-portal.php $*"; }
SETUP="$(portal setup)"
echo "$SETUP" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["seeds"]))' > "$TMP/seeds.json"
TOKEN="$(echo "$SETUP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
PIN="$(echo "$SETUP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["pin"])')"

docker run -d --name "$CLI" --network "$RUN" -v "$BIN":/opt/sohobotp-agent:ro -v "$TMP":/e2e:ro \
  -v "$REPO/agent/tests/e2e/client.py":/opt/client.py:ro sohobotp-test-debian >/dev/null
client() { docker exec "$CLI" python3 /opt/client.py "$1" /e2e/seeds.json || STATUS=1; }
agent() { docker exec "$CLI" /opt/sohobotp-agent "$@"; }
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; STATUS=1; fi; }

echo "== enrolment"
check "wrong pin refused, nothing enrolled" "! agent install --portal https://portal.test --token '$TOKEN' --pin 00$PIN --ca-file /e2e/ca.pem --no-service >/dev/null 2>&1 && ! docker exec $CLI test -e /etc/sohobotp-agent/agent.json"
# the refused attempt enrolled an endpoint the agent then rejected: delete it as an admin would
check "orphan endpoint of the refused install deleted" "portal delete-orphans | grep -q deleted"
TOKEN="$(portal token)"
check "install with token, pin and test CA" "agent install --portal https://portal.test --token '$TOKEN' --pin '$PIN' --ca-file /e2e/ca.pem --no-service"
check "state readable by root only" "[ \"\$(docker exec $CLI stat -c %a /etc/sohobotp-agent)\" = 700 ] && [ \"\$(docker exec $CLI stat -c %a /etc/sohobotp-agent/agent.json)\" = 600 ]"
check "first configuration applied" "agent status | grep -q 'version 1, applied'"
ENDPOINT="$(portal endpoint)"
echo "$ENDPOINT" | python3 -c 'import json,sys; e=json.load(sys.stdin); print("   portal: config", e.get("config"), "applied", e.get("applied"), "radius", e.get("radius_client_id"), e.get("radius_error"))'
check "portal sees the inventory and the applied version" "echo '$ENDPOINT' | python3 -c 'import json,sys; e=json.load(sys.stdin); sys.exit(0 if e[\"inventory\"][\"os_name\"].startswith(\"Debian\") and e[\"applied\"][\"version\"]==1 and e[\"applied\"][\"status\"]==\"applied\" and e[\"radius_client_id\"] else 1)'"
printf 'Waiting for FreeRADIUS to apply the endpoint client'
for i in $(seq 1 60); do
  [ "$(portal radius-applied)" = yes ] && { echo " ok"; break; }
  printf '.'; sleep 2
done

if [ "${E2E_STOP_AFTER_INSTALL:-}" = 1 ]; then
  trap - EXIT
  echo "kept for debugging: $APP $CLI (network $RUN, files $TMP)"
  exit 0
fi
echo "== logins"
client logins

echo "== RADIUS server down"
docker exec "$APP" sh -c 'pkill -x freeradius; sleep 1'
client radius-down
docker exec "$APP" sh -c '/etc/init.d/freeradius start >/dev/null 2>&1 || freeradius'
sleep 2
client radius-back

echo "== policy change from the portal: SSH only"
check "portal policy changed to SSH only" "portal policy ssh-only | grep -q 'policy saved'"
check "agent picks up version 2" "agent run --once | grep -q 'version 2, applied'"
client sudo-removed

echo "== 2FA turned off in the portal"
check "portal policy changed to 2FA off" "portal policy off | grep -q 'policy saved'"
check "agent picks up version 3" "agent run --once | grep -q 'version 3, applied'"
client disabled

echo "== uninstall"
check "uninstall removes the agent state" "docker exec $CLI sh -c '/opt/sohobotp-agent uninstall >/dev/null 2>&1; ! test -e /etc/sohobotp-agent'"
[ "$STATUS" = 0 ] && echo "All Linux agent end-to-end checks passed." || echo "Some Linux agent end-to-end checks FAILED."
exit $STATUS
