#!/bin/sh
# Builds the production image (Dockerfile at the repository root) and checks the portal in it:
# HTTPS behind nginx, the background worker started by newvm.sh, and RADIUS through real
# FreeRADIUS with the sudo helper (portal/tests/appliance-radius.php).
# The first build downloads the whole Debian stack and takes a while; later builds are cached.
# Usage (from the repository root):  sh portal/tests/run-appliance-test.sh
set -eu
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
NAME="multiotp-appliance-test-$$"

docker build -q -t multiotp-portal-appliance:dev "$REPO" >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run -d --name "$NAME" multiotp-portal-appliance:dev >/dev/null

printf 'Waiting for the appliance'
for i in $(seq 1 90); do
  if docker exec "$NAME" sh -c 'pidof freeradius >/dev/null && pidof nginx >/dev/null && pgrep -f "worker.php --loop" >/dev/null' 2>/dev/null; then
    echo " ready"; break
  fi
  printf '.'; sleep 2
done

STATUS=0
echo "== HTTPS portal behind nginx"
docker exec "$NAME" php -r '
  $failed = 0;
  $check = function (string $name, bool $ok) use (&$failed) { echo ($ok ? "ok   " : "FAIL ") . $name . "\n"; $failed += $ok ? 0 : 1; };
  $get = function (string $url): array {
    $ctx = stream_context_create(["http" => ["ignore_errors" => true, "follow_location" => 0], "ssl" => ["verify_peer" => false, "verify_peer_name" => false]]);
    $body = @file_get_contents($url, false, $ctx);
    $headers = $http_response_header ?? [];
    preg_match("{HTTP/\S+ (\d+)}", $headers[0] ?? "", $m);
    return [(int) ($m[1] ?? 0), implode("\n", $headers), (string) $body];
  };
  [$code, $headers, $body] = $get("https://localhost/portal/");
  $check("portal login page over HTTPS", 200 === $code && str_contains($body, "name=\"password\""));
  $check("security headers through nginx", (bool) preg_match("/content-security-policy/i", $headers));
  $check("__Host- session cookie over HTTPS", (bool) preg_match("/set-cookie: __Host-motp_portal/i", $headers));
  $check("HSTS header", (bool) preg_match("/strict-transport-security/i", $headers));
  foreach (["/portal/src/App.php", "/portal/templates/login.php", "/portal/bin/portal-admin.php", "/portal/bin/multiotp-portal-radius", "/portal/tests/appliance-radius.php"] as $p) {
    [$c] = $get("https://localhost" . $p);
    $check("$p refused by nginx ($c)", 404 === $c);
  }
  [$c] = $get("http://localhost/portal/");
  $check("plain HTTP redirected to HTTPS ($c)", 301 === $c);
  exit($failed > 0 ? 1 : 0);
' || STATUS=1
docker exec "$NAME" sh -c '
  ok() { echo "ok   $1"; }; fail() { echo "FAIL $1"; FAILED=1; }; FAILED=0
  pgrep -u www-data -f "^php .*worker.php --loop" >/dev/null && ok "worker runs as www-data" || fail "worker user"
  pgrep -u root -f "^php .*worker.php --loop" >/dev/null && fail "a worker runs as root" || ok "no worker running as root"
  [ "$(stat -c %U /usr/local/sbin/multiotp-portal-radius)" = root ] && ok "helper owned by root" || fail "helper owner"
  su -s /bin/sh www-data -c "sudo -n /usr/local/sbin/multiotp-portal-radius status" >/dev/null && ok "www-data may run the helper" || fail "sudo helper"
  su -s /bin/sh www-data -c "sudo -n /usr/local/sbin/multiotp-portal-radius apply /etc/shadow" >/dev/null 2>&1 && fail "helper accepted an extra argument" || ok "sudo refuses other arguments"
  exit $FAILED
' || STATUS=1

echo "== RADIUS through real FreeRADIUS"
docker exec "$NAME" su -s /bin/sh www-data -c "php /usr/local/bin/multiotp/portal/tests/appliance-radius.php" || STATUS=1

if [ "$STATUS" != 0 ]; then
  echo "== worker log"; docker exec "$NAME" tail -n 30 /var/log/multiotp/portal-worker.log || true
fi
exit $STATUS
