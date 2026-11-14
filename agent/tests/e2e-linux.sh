#!/bin/sh
# Linux agent end-to-end test against the production image (portal + nginx + FreeRADIUS +
# worker) and a Debian endpoint with SSH, sudo and pam_radius.
# Usage (from the repository root):  sh agent/tests/e2e-linux.sh            (Debian 12)
#                                     DISTRO=rocky sh agent/tests/e2e-linux.sh (Rocky Linux 9)
set -eu
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DISTRO="${DISTRO:-debian}"
RUN="sohobotp-e2e-$$"
APP="$RUN-portal"
CLI="$RUN-debian"
TMP="$(mktemp -d)"
STATUS=0

sh "$REPO/agent/tests/run-in-docker.sh" >/dev/null
case "$(docker info --format '{{.Architecture}}')" in
  aarch64|arm64) ARCH=arm64 ;;
  *) ARCH=amd64 ;;
esac
# Self-update test material: a TEST release key, agents 0.1.0 and 0.2.0 built with it,
# 0.2.0 signed with it, and a 0.3.0 signed with ANOTHER key (must be refused by the agent);
# 0.4.0 signed, passes its self-test, then crashes at every start (test-only build flag):
# must be rolled back; 0.5.0 signed but not a working program: refused by the self-test.
E2E="$REPO/agent/dist/e2e"
rm -rf "$E2E" && mkdir -p "$E2E"
docker run --rm -v "$REPO":/src -w /src/agent -e GOFLAGS=-buildvcs=false -e ARCH="$ARCH" \
  -v sohobotp-go-cache:/go/pkg/mod golang:1.22.10-bookworm sh -euc '
    go run ./cmd/sohobotp-agent release keygen --out dist/e2e | sed -n "s/^Public key (build agents with it): //p" > dist/e2e/release.pub
    mkdir -p dist/e2e/other && go run ./cmd/sohobotp-agent release keygen --out dist/e2e/other >/dev/null
    KEY=$(cat dist/e2e/release.pub)
    for v in 0.1.0 0.2.0 0.3.0; do
      CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath -ldflags "-s -w -X multiotp-portal/agent/internal/inventory.Version=$v -X multiotp-portal/agent/internal/release.PublicKey=$KEY" \
        -o dist/e2e/agent-$v ./cmd/sohobotp-agent
    done
    go run ./cmd/sohobotp-agent release sign --key dist/e2e/release-private.key --file dist/e2e/agent-0.2.0 --version 0.2.0 --os linux --arch $ARCH --out dist/e2e/agent-0.2.0.json
    go run ./cmd/sohobotp-agent release sign --key dist/e2e/other/release-private.key --file dist/e2e/agent-0.3.0 --version 0.3.0 --os linux --arch $ARCH --out dist/e2e/agent-0.3.0.json
    CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath -ldflags "-s -w -X multiotp-portal/agent/internal/inventory.Version=0.4.0 -X multiotp-portal/agent/internal/release.PublicKey=$KEY -X multiotp-portal/agent/internal/agent.crashAfterStartForTests=yes" \
      -o dist/e2e/agent-0.4.0 ./cmd/sohobotp-agent
    printf "#!/bin/sh\necho this release is broken >&2\nexit 1\n" > dist/e2e/agent-0.5.0
    for v in 0.4.0 0.5.0; do
      go run ./cmd/sohobotp-agent release sign --key dist/e2e/release-private.key --file dist/e2e/agent-$v --version $v --os linux --arch $ARCH --out dist/e2e/agent-$v.json
    done'
BIN="$E2E/agent-0.1.0"
docker build -q -t multiotp-portal-appliance:dev "$REPO" >/dev/null
docker build -q -t "sohobotp-test-$DISTRO" "$REPO/agent/tests/docker/$DISTRO" >/dev/null
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

docker run -d --name "$CLI" --network "$RUN" -v "$BIN":/opt/sohobotp-agent-0.1.0:ro -v "$TMP":/e2e:ro \
  -v "$REPO/agent/tests/e2e/client.py":/opt/client.py:ro "sohobotp-test-$DISTRO" >/dev/null
client() { docker exec "$CLI" python3 /opt/client.py "$1" /e2e/seeds.json || STATUS=1; }
docker exec "$CLI" install -m 0755 /opt/sohobotp-agent-0.1.0 /usr/local/sbin/sohobotp-agent
agent() { docker exec "$CLI" /usr/local/sbin/sohobotp-agent "$@"; }
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
check "portal sees the inventory and the applied version" "echo '$ENDPOINT' | python3 -c 'import json,sys; e=json.load(sys.stdin); sys.exit(0 if e[\"inventory\"][\"os_name\"].split()[0] in (\"Debian\", \"Rocky\") and e[\"applied\"][\"version\"]==1 and e[\"applied\"][\"status\"]==\"applied\" and e[\"radius_client_id\"] else 1)'"
check "the agent reports the machine's login accounts (root, no system accounts)" "portal endpoint | python3 -c 'import json,sys; a=[x[\"name\"] for x in json.load(sys.stdin)[\"inventory\"][\"accounts\"]]; sys.exit(0 if \"root\" in a and \"daemon\" not in a and \"nobody\" not in a else 1)'"
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

echo "== per computer, per user: code at sign-in but not for sudo"
check "the agent reported bob among the machine's accounts" "portal endpoint | grep -q '\"name\": *\"bob\"'"
check "portal: bob unticked for admin actions on this computer" "portal exempt admin bob | grep -q saved"
check "agent applies it" "agent run --once | grep -q 'version [0-9]*, applied'"
client per-user
check "portal: bob ticked again" "portal exempt none | grep -q saved"
check "agent applies it" "agent run --once | grep -q 'version [0-9]*, applied'"

echo "== policy change from the portal: SSH only"
check "portal policy changed to SSH only" "portal policy ssh-only | grep -q 'policy saved'"
check "agent picks up the new version" "agent run --once | grep -q 'version [0-9]*, applied'"
client sudo-removed

echo "== self-update with signed releases"
for v in 0.2.0 0.3.0 0.4.0 0.5.0; do
  docker cp "$E2E/agent-$v" "$APP:/tmp/agent-$v" && docker cp "$E2E/agent-$v.json" "$APP:/tmp/agent-$v.json"
  docker exec "$APP" chmod 0644 "/tmp/agent-$v" "/tmp/agent-$v.json"
  check "portal stores release $v" "docker exec $APP su -s /bin/sh www-data -c 'php /usr/local/bin/multiotp/portal/bin/portal-admin.php agent-release-add --file=/tmp/agent-$v --manifest=/tmp/agent-$v.json' | grep -q Added"
done
check "portal policy: target 0.3.0 (signed with another key)" "portal policy update-0.3.0 | grep -q 'policy saved'"
OUT="$(agent run --once 2>&1 || true)"
check "agent refuses the release signed with another key" "echo \"\$OUT\" | grep -q 'update to 0.3.0 refused: release signature' && agent version | grep -q 'sohobotp-agent 0.1.0'"
check "portal policy: target 0.2.0" "portal policy update-0.2.0 | grep -q 'policy saved'"
OUT="$(agent run --once 2>&1 || true)"
check "agent downloads, verifies and installs 0.2.0" "agent version | grep -q 'sohobotp-agent 0.2.0'"
agent run --once >/dev/null 2>&1 || true
check "portal sees the new agent version" "portal endpoint | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)[\"inventory\"][\"agent_version\"]==\"0.2.0\" else 1)'"
check "updated agent keeps working (SSH still needs the code)" "docker exec $CLI python3 /opt/client.py sudo-removed /e2e/seeds.json >/dev/null 2>&1"

echo "== self-update safety: self-test and roll back"
check "portal policy: target 0.5.0 (signed, but does not start)" "portal policy update-0.5.0 | grep -q 'policy saved'"
OUT="$(agent run --once 2>&1 || true)"
check "release that does not start refused by the self-test, 0.2.0 kept" "echo \"\$OUT\" | grep -q 'update to 0.5.0 refused: the new version does not start' && agent version | grep -q 'sohobotp-agent 0.2.0'"
check "portal policy: target 0.4.0 (starts, then crashes)" "portal policy update-0.4.0 | grep -q 'policy saved'"
OUT="$(agent run --once 2>&1 || true)"
check "0.4.0 passes its self-test and is installed" "agent version | grep -q 'sohobotp-agent 0.4.0'"
for i in 1 2 3; do agent run --once >/dev/null 2>&1 || true; done
OUT="$(agent run --once 2>&1 || true)"
check "after 3 starts without a check-in, the agent rolls back to 0.2.0 by itself" "echo \"\$OUT\" | grep -q 'rolled back' && agent version | grep -q 'sohobotp-agent 0.2.0'"
OUT="$(agent run --once 2>&1 || true)"
check "the rolled-back version is not installed again, 0.2.0 checks in" "agent version | grep -q 'sohobotp-agent 0.2.0' && agent status | grep -q 'Update blocked:  0.4.0'"
check "rolled-back agent keeps working (SSH still needs the code)" "docker exec $CLI python3 /opt/client.py sudo-removed /e2e/seeds.json >/dev/null 2>&1"
check "portal policy: target 0.2.0 again" "portal policy update-0.2.0 | grep -q 'policy saved'"

echo "== 2FA turned off in the portal"
check "portal policy changed to 2FA off" "portal policy off | grep -q 'policy saved'"
check "agent picks up the 2FA-off configuration" "agent run --once | grep -q 'version [0-9]*, applied'"
client disabled

echo "== uninstall"
check "uninstall removes the agent state and binary" "docker exec $CLI sh -c '/usr/local/sbin/sohobotp-agent uninstall >/dev/null 2>&1; ! test -e /etc/sohobotp-agent && ! test -e /usr/local/sbin/sohobotp-agent'"
echo "== agent downloaded from the portal: enrolment settings built in, nothing typed"
docker cp "$BIN" "$APP:/tmp/agent-plain" && docker exec "$APP" chmod 0644 /tmp/agent-plain
portal download /tmp/agent-plain /tmp/ca.pem > "$TMP/agent-download"
PLAIN_SUM=$(shasum -a 256 "$BIN" | cut -d" " -f1)
check "the download is the agent program plus its settings" "[ \$(wc -c < '$TMP/agent-download') -gt \$(wc -c < '$BIN') ] && tail -c 16 '$TMP/agent-download' | grep -q SOHOBOTP-BUNDLE1"
docker exec "$CLI" sh -c 'cp /e2e/agent-download /root/sohobotp-agent-download && chmod 0755 /root/sohobotp-agent-download'
# no systemd in the test container: the enrolment and the copy of the program are checked, the service step fails after them
OUT=$(docker exec "$CLI" /root/sohobotp-agent-download install 2>&1 || true)
check "install without options enrols with the built-in settings" "echo \"\$OUT\" | grep -q 'Enrolment settings built into this agent: portal https://portal.test' && echo \"\$OUT\" | grep -q 'Enrolled as endpoint'"
check "the built-in CA certificate is used for the portal connection" "docker exec $CLI cmp -s /etc/sohobotp-agent/portal-ca.pem /e2e/ca.pem && agent status | grep -q 'Portal: *https://portal.test'"
check "the installed agent is the plain program: the enrolment token is not kept" "[ \"\$(docker exec $CLI sha256sum /usr/local/sbin/sohobotp-agent | cut -d' ' -f1)\" = '$PLAIN_SUM' ] && [ \"\$(docker exec $CLI tail -c 16 /usr/local/sbin/sohobotp-agent)\" != SOHOBOTP-BUNDLE1 ]"
check "the installed agent checks in" "agent run --once | grep -q 'version [0-9]*, applied'"
check "the same download cannot enrol a second machine (token for 1)" "docker exec $CLI sh -c 'rm -rf /etc/sohobotp-agent && ! /root/sohobotp-agent-download install --no-service >/dev/null 2>&1'"
docker exec "$CLI" sh -c 'printf x | dd of=/root/sohobotp-agent-download bs=1 seek=$(( $(wc -c < /root/sohobotp-agent-download) - 60 )) conv=notrunc 2>/dev/null'
check "a damaged download is refused with a clear message" "docker exec $CLI /root/sohobotp-agent-download install 2>&1 | grep -q 'settings built into this program are damaged'"

if [ "$DISTRO" = debian ]; then
  echo "== Debian package from the portal: apt/dpkg install enrols, remove uninstalls"
  ARCH=$(docker exec "$CLI" dpkg --print-architecture)
  portal deb /tmp/agent-plain /tmp/ca.pem "$ARCH" > "$TMP/agent.deb"
  docker cp "$TMP/agent.deb" "$CLI:/root/sohobotp-agent.deb"
  # the test machine has no systemd (container): systemctl that succeeds; clean up the earlier installs
  docker exec "$CLI" sh -c 'printf "#!/bin/sh\nexit 0\n" > /usr/local/bin/systemctl && chmod 0755 /usr/local/bin/systemctl
    /usr/local/sbin/sohobotp-agent uninstall >/dev/null 2>&1 || true; rm -rf /etc/sohobotp-agent /usr/local/sbin/sohobotp-agent'
  check "dpkg reads the package (name, architecture, version)" "docker exec $CLI dpkg-deb -f /root/sohobotp-agent.deb Package Architecture Version | tr '\n' ' ' | grep -q 'Package: sohobotp-agent Architecture: $ARCH Version: 0.1.0'"
  portal delete-endpoints >/dev/null  # the earlier installs on this machine, deleted as an administrator would
  portal policy ssh-only >/dev/null   # 2FA on again (turned off above), so the install configures PAM
  OUT=$(docker exec "$CLI" dpkg -i --force-depends /root/sohobotp-agent.deb 2>&1 || true)
  check "installing the package enrols the machine with the built-in settings" "echo \"\$OUT\" | grep -q 'Enrolled as endpoint' && docker exec $CLI dpkg -s sohobotp-agent | grep -q 'Status: install ok installed'"
  check "the token does not stay on the machine (setup file deleted)" "! docker exec $CLI test -e /var/lib/sohobotp-agent/setup"
  check "the installed agent is the plain program" "[ \"\$(docker exec $CLI sha256sum /usr/local/sbin/sohobotp-agent | cut -d' ' -f1)\" = '$PLAIN_SUM' ]"
  # the portal sends the Linux configuration once the worker created this machine's RADIUS client
  # (seconds); the service checks in every minute, here: retry
  for i in $(seq 1 30); do agent run --once 2>/dev/null | grep -q 'version [0-9]*, applied' && break; sleep 2; done
  check "the agent receives and applies its configuration" "agent status | grep -q 'version [0-9]*, applied'"
  check "PAM configured by the policy" "docker exec $CLI test -f /etc/pam.d/sohobotp-2fa"
  OUT=$(docker exec "$CLI" dpkg -r sohobotp-agent 2>&1 || true)
  check "removing the package uninstalls the agent (state, binary, PAM changes)" "docker exec $CLI sh -c '! test -e /etc/sohobotp-agent && ! test -e /usr/local/sbin/sohobotp-agent && ! test -e /etc/pam.d/sohobotp-2fa' && ! docker exec $CLI dpkg -s sohobotp-agent >/dev/null 2>&1"
  docker exec "$CLI" rm -f /usr/local/bin/systemctl
fi
[ "$STATUS" = 0 ] && echo "All Linux agent end-to-end checks passed ($DISTRO)." || echo "Some Linux agent end-to-end checks FAILED ($DISTRO)."
exit $STATUS
