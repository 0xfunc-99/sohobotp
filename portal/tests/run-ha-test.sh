#!/bin/sh
# High availability with two appliances (stage 6b): A is the primary (MariaDB), B joins as
# secondary with the pairing code, replicates (TLS, pinned certificate) and copies the RADIUS
# configuration; logins through B work while A is up; A is stopped; B is promoted and answers
# with its own copy (replay protection kept).
# Usage (from the repository root):  sh portal/tests/run-ha-test.sh
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
NET="sohobotp-ha-$$"
A="sohobotp-ha-a-$$"
B="sohobotp-ha-b-$$"
IPA=172.30.88.10
IPB=172.30.88.11
docker build -q -t multiotp-portal-appliance:dev "$REPO" >/dev/null || exit 1
cleanup() { docker rm -f "$A" "$B" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; }
trap cleanup EXIT
docker network create --subnet 172.30.88.0/24 "$NET" >/dev/null || exit 1
docker run -d --name "$A" --network "$NET" --ip $IPA multiotp-portal-appliance:dev >/dev/null
docker run -d --name "$B" --network "$NET" --ip $IPB multiotp-portal-appliance:dev >/dev/null
for n in "$A" "$B"; do
  for i in $(seq 1 90); do
    docker exec "$n" sh -c 'pidof freeradius >/dev/null && pidof nginx >/dev/null && pgrep -f "worker.php --loop" >/dev/null' 2>/dev/null && break
    sleep 2
  done
done
STATUS=0
node() { docker exec "$1" su -s /bin/sh www-data -c "php /usr/local/bin/multiotp/portal/tests/ha-node.php $2" || STATUS=1; }

echo "== primary A ($IPA)"
node "$A" "primary $IPA $IPB"
for f in ha-code ha-seed ha-secret; do docker cp "$A:/tmp/$f" "/tmp/$NET-$f" && docker cp "/tmp/$NET-$f" "$B:/tmp/$f"; done
rm -f /tmp/$NET-*
docker exec "$B" chown www-data /tmp/ha-code /tmp/ha-seed /tmp/ha-secret

echo "== secondary B ($IPB) joins"
node "$B" join
node "$B" "check-replica ha.user"
node "$A" "add-user ha.later"
node "$B" "check-replica ha.later"
node "$B" "login accepted"
node "$B" "login rejected reuse"
docker exec "$A" php -r '$c = stream_context_create(["http" => ["ignore_errors" => true], "ssl" => ["verify_peer" => false, "verify_peer_name" => false]]); @file_get_contents("https://localhost/portal/ha.php", false, $c); echo $http_response_header[0] ?? "";' | grep -q 403 && echo "ok   ha.php refuses requests without the pairing key" || { echo "FAIL ha.php answered without the pairing key"; STATUS=1; }

echo "== primary A stops"
docker stop "$A" >/dev/null
node "$B" "login rejected"
node "$B" promote
node "$B" "login accepted"
node "$B" "login rejected reuse"

[ "$STATUS" = 0 ] && echo "All high-availability checks passed." || { echo "Some high-availability checks FAILED."; docker exec "$B" tail -n 20 /var/log/multiotp/portal-worker.log; }
exit $STATUS
