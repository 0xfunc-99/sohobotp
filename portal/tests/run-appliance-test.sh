#!/bin/sh
# Builds the production image (Dockerfile at the repository root) and checks the portal in it:
# HTTPS behind nginx, the background worker started by newvm.sh, and RADIUS through real
# FreeRADIUS with the sudo helper (portal/tests/appliance-radius.php), and the endpoint agent API
# (portal/tests/appliance-endpoints.php).
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
  foreach (["/portal/src/App.php", "/portal/templates/login.php", "/portal/bin/portal-admin.php", "/portal/bin/multiotp-portal-radius", "/portal/tests/appliance-radius.php", "/portal/README.md", "/portal/docs/endpoints.md", "/portal/tasks/codex-ad-tests.md", "/portal/tests/AgentSim.php", "/portal/bin/sohobotp-vip-route", "/portal/tests/fake-vip-radius.php", "/portal/src/Api.php", "/portal/tests/appliance-api.php", "/portal/bin/sohobotp-db", "/portal/src/Database.php", "/portal/src/Endpoints.php", "/portal/docs/agent-protocol-vectors.json"] as $p) {
    [$c] = $get("https://localhost" . $p);
    $check("$p refused by nginx ($c)", 404 === $c);
  }
  [$c, , $b] = $get("https://localhost/portal/assets/portal.css");
  $check("portal assets still served ($c)", 200 === $c && "" !== $b);
  [$c] = $get("http://localhost/portal/");
  $check("plain HTTP redirected to HTTPS ($c)", 301 === $c);
  [$c, $h] = $get("https://localhost/");
  $check("home page redirects to the portal ($c)", 302 === $c && str_contains($h, "/portal/"));
  foreach (["/index.php", "/multiotp.server.php", "/multiotp.proxy.php", "/test-tokens.csv", "/templates/template.html", "/readme_5.10.4.2.txt"] as $p) {
    [$c] = $get("https://localhost" . $p);
    $check("legacy $p refused by nginx ($c)", 404 === $c);
  }
  $ctx = stream_context_create(["http" => ["method" => "POST", "ignore_errors" => true, "header" => "Prefer: api=vuejs\r\nContent-Type: application/json", "content" => "{\"c\":\"getSalt\"}"], "ssl" => ["verify_peer" => false, "verify_peer_name" => false]]);
  @file_get_contents("https://localhost/", false, $ctx);
  preg_match("{HTTP/\S+ (\d+)}", $http_response_header[0] ?? "", $m);
  $check("legacy admin API not reachable (" . ($m[1] ?? "?") . ")", in_array((int) ($m[1] ?? 0), [302, 404], true));
  exit($failed > 0 ? 1 : 0);
' || STATUS=1
docker exec "$NAME" sh -c '
  ok() { echo "ok   $1"; }; fail() { echo "FAIL $1"; FAILED=1; }; FAILED=0
  pgrep -u www-data -f "^php .*worker.php --loop" >/dev/null && ok "worker runs as www-data" || fail "worker user"
  su -s /bin/sh www-data -c "php /usr/local/bin/multiotp/portal/bin/portal-admin.php anonymous-stats" | grep -q "statistics: off" && ok "anonymous statistics off at start" || fail "anonymous statistics still on"
  grep -q "^anonymous_stat=0" /etc/multiotp/config/multiotp.ini && ok "engine configuration has anonymous_stat=0" || fail "anonymous_stat not 0 in multiotp.ini"
  pgrep -u root -f "^php .*worker.php --loop" >/dev/null && fail "a worker runs as root" || ok "no worker running as root"
  [ "$(stat -c %U /usr/local/sbin/multiotp-portal-radius)" = root ] && ok "helper owned by root" || fail "helper owner"
  su -s /bin/sh www-data -c "sudo -n /usr/local/sbin/multiotp-portal-radius status" >/dev/null && ok "www-data may run the helper" || fail "sudo helper"
  su -s /bin/sh www-data -c "sudo -n /usr/local/sbin/multiotp-portal-radius apply /etc/shadow" >/dev/null 2>&1 && fail "helper accepted an extra argument" || ok "sudo refuses other arguments"
  for cmd in "/bin/cp /etc/hostname /tmp/x" "/bin/chmod 0644 /etc/hostname" "/bin/chown root /etc/hostname" "/usr/bin/7za"; do
    su -s /bin/sh www-data -c "sudo -n $cmd" >/dev/null 2>&1 && fail "www-data may run sudo $cmd" || ok "www-data may not run sudo ${cmd%% *}"
  done
  sleep 2
  [ -s /etc/multiotp/engine.key ] && ok "private engine key created at first start" || fail "no engine key"
  grep -q "^encryption_key_full_path=/etc/multiotp/engine.key" /etc/multiotp/config/multiotp.ini && ok "engine settings point at the key" || fail "encryption_key_full_path not set"
  su -s /bin/sh www-data -c "php /usr/local/bin/multiotp/portal/bin/portal-admin.php engine-key --state=status" | grep -q "private key" && ok "token secrets use the private key" || fail "token secrets still on the public key"
  su -s /bin/sh www-data -c "php /usr/local/bin/multiotp/portal/bin/portal-admin.php engine-key --state=status" | grep -q "admin password: random" && ok "legacy admin password is not 1234" || fail "legacy admin still accepts 1234"
  exit $FAILED
' || STATUS=1

echo "== RADIUS through real FreeRADIUS"
docker exec "$NAME" su -s /bin/sh www-data -c "php /usr/local/bin/multiotp/portal/tests/appliance-radius.php" || STATUS=1

echo "== Endpoint agent API through nginx, RADIUS client in real FreeRADIUS"
docker exec "$NAME" su -s /bin/sh www-data -c "php /usr/local/bin/multiotp/portal/tests/appliance-endpoints.php" || STATUS=1

echo "== REST API through nginx"
docker exec "$NAME" su -s /bin/sh www-data -c "php /usr/local/bin/multiotp/portal/tests/appliance-api.php" || STATUS=1

echo "== Symantec VIP migration: forwarding through real FreeRADIUS to a stand-in gateway"
docker exec -d "$NAME" su -s /bin/sh www-data -c "php /usr/local/bin/multiotp/portal/tests/fake-vip-radius.php 18121 Vip-Gateway-Secret-0123 /tmp/fake-vip.count"
sleep 1
docker exec "$NAME" su -s /bin/sh www-data -c "php /usr/local/bin/multiotp/portal/tests/appliance-vip.php" || STATUS=1

echo "== Database: MariaDB on the appliance, migration, 100,000 users (last: the appliance stays on MariaDB)"
docker exec "$NAME" su -s /bin/sh www-data -c "php /usr/local/bin/multiotp/portal/tests/appliance-db.php" || STATUS=1
docker exec "$NAME" sh -c '[ "$(stat -c %U /usr/local/sbin/sohobotp-db)" = root ]' && echo "ok   database helper owned by root" || { echo "FAIL database helper owner"; STATUS=1; }

if [ "$STATUS" != 0 ]; then
  echo "== worker log"; docker exec "$NAME" tail -n 30 /var/log/multiotp/portal-worker.log || true
fi
exit $STATUS
