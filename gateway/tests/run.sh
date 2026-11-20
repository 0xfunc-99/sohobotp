#!/bin/sh
# Builds the gateway and tests it against a fake portal and a fake site (no real portal needed).
#   sh gateway/tests/run.sh
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
NET=sohobotp-gw-test-$$
cleanup() { docker rm -f gw-portal gw-site gw-gateway >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker build -q -t sohobotp-gateway:test "$HERE/.." >/dev/null
docker network create "$NET" >/dev/null
docker run -d --name gw-portal --network "$NET" --network-alias portal -v "$HERE":/t:ro php:8.4-cli php -S 0.0.0.0:8000 /t/fake-portal.php >/dev/null
docker run -d --name gw-site --network "$NET" --network-alias site -v "$HERE":/t:ro php:8.4-cli php -S 0.0.0.0:8000 /t/fake-site.php >/dev/null
docker run -d --name gw-gateway --network "$NET" --network-alias gateway -v "$HERE/sites.json":/etc/sohobotp-gateway/sites.json:ro \
  -e SOHOBOTP_PORTAL=http://portal:8000 -e SOHOBOTP_API_KEY=sohob_testkey_0123456789 sohobotp-gateway:test >/dev/null
i=0; until docker exec gw-gateway sh -c 'php -r "exit(@fsockopen(\"127.0.0.1\", 8081) ? 0 : 1);"' 2>/dev/null; do i=$((i+1)); [ $i -gt 40 ] && { docker logs gw-gateway; exit 1; }; sleep 0.5; done
status=0
docker run --rm --network "$NET" -v "$HERE":/t:ro php:8.4-cli php /t/checks.php || status=$?
if [ $status -ne 0 ]; then echo "--- gateway log"; docker logs gw-gateway 2>&1 | tail -30; fi
exit $status
