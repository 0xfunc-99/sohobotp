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
AD_CERT_DIR=""
cleanup() {
  docker rm -f "$RUN-ldap" "$RUN-ad" "$RUN-ad-php" >/dev/null 2>&1 || true
  docker network rm "$RUN" >/dev/null 2>&1 || true
  if [ -n "$AD_CERT_DIR" ]; then rm -rf "$AD_CERT_DIR"; fi
}
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

  echo "== FreeRADIUS helper: candidate file whitelist"
  mkdir -p /etc/multiotp/portal/radius /etc/freeradius/3.0 && touch /etc/freeradius/3.0/clients.conf
  cp /tmp/unit-radius-candidate.conf /etc/multiotp/portal/radius/clients.candidate.conf
  OUT=$(sh portal/bin/multiotp-portal-radius apply 2>&1 || true)
  if echo "$OUT" | grep -q "candidate file rejected"; then echo "FAIL generated file rejected by the helper: $OUT"; exit 1; fi
  echo "$OUT" | grep -q "configuration check FAILED" && echo "ok   generated file accepted, rollback when FreeRADIUS is missing"
  [ ! -f /etc/freeradius/3.0/multiotp-portal-clients.conf ] && echo "ok   nothing left installed after rollback"
  printf "\$INCLUDE /etc/shadow\n" >> /etc/multiotp/portal/radius/clients.candidate.conf
  OUT=$(sh portal/bin/multiotp-portal-radius apply 2>&1 || true)
  if echo "$OUT" | grep -q "candidate file rejected"; then echo "ok   injected \$INCLUDE line rejected"; else echo "FAIL injected line accepted: $OUT"; exit 1; fi
  echo "== FreeRADIUS helper: Symantec VIP file whitelist and site hooks"
  sed -i "/INCLUDE \/etc\/shadow/d" /etc/multiotp/portal/radius/clients.candidate.conf
  mkdir -p /etc/freeradius/3.0/sites-available /etc/freeradius/3.0/mods-enabled
  printf "authorize {\n\tpreprocess\n}\npost-auth {\n\texec\n\tPost-Auth-Type REJECT {\n\t\tattr_filter.access_reject\n\t}\n}\n" > /etc/freeradius/3.0/sites-available/default
  printf "proxy server {\n}\n" > /etc/freeradius/3.0/proxy.conf
  cp /etc/freeradius/3.0/sites-available/default /tmp/site.orig
  cp /tmp/unit-vip-candidate.conf /etc/multiotp/portal/radius/vip.candidate.conf
  OUT=$(sh portal/bin/multiotp-portal-radius apply 2>&1 || true)
  if echo "$OUT" | grep -q "candidate file rejected\|could not add"; then echo "FAIL generated VIP file or hooks rejected: $OUT"; exit 1; fi
  echo "$OUT" | grep -q "added the Symantec VIP forwarding hooks" && echo "ok   forwarding hooks added to the site"
  if cmp -s /etc/freeradius/3.0/sites-available/default /tmp/site.orig && [ ! -f /etc/freeradius/3.0/sohobotp-vip-proxy.conf ] && [ ! -f /etc/freeradius/3.0/mods-enabled/sohobotp_vip ] && ! grep -q sohobotp /etc/freeradius/3.0/proxy.conf; then
    echo "ok   VIP changes rolled back when FreeRADIUS refuses (missing here)"
  else echo "FAIL VIP changes left after a refused apply"; ls -l /etc/freeradius/3.0 /etc/freeradius/3.0/mods-enabled; exit 1; fi
  printf "home_server x {\n\tsecret = \"a%%{exec:/bin/id}b\"\n}\n" >> /etc/multiotp/portal/radius/vip.candidate.conf
  OUT=$(sh portal/bin/multiotp-portal-radius apply 2>&1 || true)
  if echo "$OUT" | grep -q "VIP candidate file rejected"; then echo "ok   injected VIP lines rejected"; else echo "FAIL injected VIP lines accepted: $OUT"; exit 1; fi
  rm -f /etc/multiotp/portal/radius/vip.candidate.conf
  OUT=$(sh portal/bin/multiotp-portal-radius apply extra 2>&1 || true)
  if echo "$OUT" | grep -q "no extra arguments"; then echo "ok   extra arguments refused"; else echo "FAIL extra arguments accepted"; exit 1; fi

  echo "== end-to-end checks"
  rm -rf /tmp/portal/* /tmp/etc/users/* && mkdir -p /tmp/portal
  # a stand-in agent program for the Download agent page (the real ones: agent/tests)
  # (ELF64 header for x86-64: e_machine 62; PE header for ARM64: machine 0xAA64)
  { printf "\177ELF\002\001\001\000\000\000\000\000\000\000\000\000\002\000\076\000"; head -c 1100000 /dev/zero; } > /tmp/fake-agent
  { printf MZ; head -c 58 /dev/zero; printf "\100\000\000\000PE\000\000\144\252"; head -c 1100000 /dev/zero; } > /tmp/fake-agent-win-arm64
  php portal/bin/portal-admin.php agent-program-add --file=/tmp/fake-agent --os=linux --arch=amd64 | grep -q "Agent program stored" && echo "ok   CLI: agent program added"
  if php portal/bin/portal-admin.php agent-program-add --file=/tmp/fake-agent --os=windows --arch=amd64 >/dev/null 2>&1; then echo "FAIL CLI stored a Linux program as Windows"; exit 1; else echo "ok   CLI: Linux program refused as Windows"; fi
  if php portal/bin/portal-admin.php agent-program-add --file=/tmp/fake-agent --os=linux --arch=arm64 2>&1 | grep -q "for Linux (Intel/AMD"; then echo "ok   CLI: x86-64 program refused as ARM64"; else echo "FAIL CLI stored an x86-64 program as ARM64"; exit 1; fi
  php portal/bin/portal-admin.php agent-program-add --file=/tmp/fake-agent-win-arm64 --os=windows --arch=arm64 | grep -q "Agent program stored" && echo "ok   CLI: Windows on ARM program added"
  if php portal/bin/portal-admin.php agent-program-add --file=/tmp/fake-agent-win-arm64 --os=windows --arch=amd64 >/dev/null 2>&1; then echo "FAIL CLI stored an ARM64 program as x64"; exit 1; else echo "ok   CLI: ARM64 Windows program refused as x64"; fi
  # stand-in SohobOTP Sign-in installers (Windows Installer header) for "install Sign-in automatically"
  { printf "\320\317\021\340\241\261\032\341"; head -c 300000 /dev/zero; } > /tmp/fake-signin.msi
  { printf "\320\317\021\340\241\261\032\341"; head -c 310000 /dev/zero; } > /tmp/fake-signin-arm64.msi
  # each with its signature file (test release key; the real one: sohobotp-agent release sign-package)
  php portal/tests/sign-package.php /tmp/fake-signin.msi signin amd64 1.0.2.0 > /tmp/fake-signin.msi.sig.json
  php portal/tests/sign-package.php /tmp/fake-signin-arm64.msi signin arm64 1.0.2.0 > /tmp/fake-signin-arm64.msi.sig.json
  php portal/tests/sign-package.php /tmp/fake-agent signin amd64 1.0.2.0 > /tmp/fake-agent.sig.json
  php portal/tests/sign-package.php /tmp/fake-signin.msi signin amd64 "1.0 /qn" > /tmp/fake-signin-badversion.sig.json
  php portal/bin/portal-admin.php signin-package-add --file=/tmp/fake-signin.msi --signature=/tmp/fake-signin.msi.sig.json | grep -q "Installer stored: SohobOTP Sign-in (Windows Intel/AMD) 1.0.2.0" && echo "ok   CLI: Sign-in installer added (x64)"
  php portal/bin/portal-admin.php signin-package-add --file=/tmp/fake-signin-arm64.msi --signature=/tmp/fake-signin-arm64.msi.sig.json | grep -q "Installer stored" && echo "ok   CLI: Sign-in installer added (ARM64)"
  if php portal/bin/portal-admin.php signin-package-add --file=/tmp/fake-signin.msi >/dev/null 2>&1; then echo "FAIL CLI stored an installer without its signature file"; exit 1; else echo "ok   CLI: an installer without its signature file refused"; fi
  if php portal/bin/portal-admin.php signin-package-add --file=/tmp/fake-signin-arm64.msi --signature=/tmp/fake-signin.msi.sig.json >/dev/null 2>&1; then echo "FAIL CLI stored an installer with the signature of another file"; exit 1; else echo "ok   CLI: the signature of another installer refused"; fi
  if php portal/bin/portal-admin.php signin-package-add --file=/tmp/fake-agent --signature=/tmp/fake-agent.sig.json >/dev/null 2>&1; then echo "FAIL CLI stored a program as a Sign-in installer"; exit 1; else echo "ok   CLI: a file that is not an .msi refused"; fi
  if php portal/bin/portal-admin.php signin-package-add --file=/tmp/fake-signin.msi --signature=/tmp/fake-signin-badversion.sig.json >/dev/null 2>&1; then echo "FAIL CLI accepted a version that is not numbers"; exit 1; else echo "ok   CLI: a version that is not numbers refused"; fi
  php portal/bin/portal-admin.php signin-package-list | grep -q "^signin/arm64 *1.0.2.0" && echo "ok   CLI: installers listed"
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

# Optional AD suite has its own PHP container/data and cannot affect the default suite.
if [ "${MULTIOTP_TEST_AD:-0}" = 1 ]; then
  docker build -q -t multiotp-test-samba "$DOCKERDIR/samba" >/dev/null
  AD_CERT_DIR=$(mktemp -d)
  docker run -d --name "$RUN-ad" --hostname dc --network "$RUN" \
    --network-alias dc.example.test --cap-add SYS_ADMIN multiotp-test-samba >/dev/null
  ready=0
  for attempt in $(seq 1 90); do
    if docker exec "$RUN-ad" sh -c 'LDAPTLS_REQCERT=never ldapsearch -x -o nettimeout=2 -H ldaps://dc.example.test:636 -D "svc-multiotp@EXAMPLE.TEST" -w "Test-Service-Password-42!" -b "OU=Staff,DC=example,DC=test" "(sAMAccountName=erin)" dn' 2>/dev/null | grep -qi '^dn: CN=erin,'; then
      ready=1
      break
    fi
    if [ "$(docker inspect -f '{{.State.Running}}' "$RUN-ad")" != true ]; then break; fi
    sleep 1
  done
  if [ "$ready" != 1 ]; then
    docker logs "$RUN-ad"
    echo "Samba AD did not become ready" >&2
    exit 1
  fi
  docker cp "$RUN-ad:/var/lib/samba/private/tls/cert.pem" "$AD_CERT_DIR/ad.pem"
  docker run --rm --name "$RUN-ad-php" --network "$RUN" \
    -v "$REPO":/src:ro -v "$AD_CERT_DIR":/ad-cert:ro multiotp-portal-php sh -euc '
      cp -R /src /app
      mkdir -p /tmp/etc/config /tmp/etc/users /tmp/etc/tokens /tmp/log /tmp/portal
      export MULTIOTP_ETC_DIR=/tmp/etc MULTIOTP_LOG_DIR=/tmp/log MULTIOTP_PORTAL_DATA=/tmp/portal
      export LDAPTLS_CACERT=/ad-cert/ad.pem
      cd /app
      php portal/tests/e2e-ad.php
      php portal/tests/e2e-ad-endpoints.php
    '
fi
