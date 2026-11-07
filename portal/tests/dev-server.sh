#!/bin/sh
# Local preview of the portal on http://localhost:8080/portal/ (plain HTTP, for testing only).
# Code is mounted live from this checkout; data persists in the Docker volume "multiotp-portal-dev-data".
# A test OpenLDAP directory runs next to it (host "ldap", see portal/tests/docker/ldap/seed.ldif),
# and the background worker runs inside the portal container.
#
#   sh portal/tests/dev-server.sh start                   start (or restart) the preview, worker and test directory
#   sh portal/tests/dev-server.sh admin <username> [role] create an administrator, prints a temporary password
#   sh portal/tests/dev-server.sh cli <portal-admin args>  any portal-admin.php command (list, unlock --username=..)
#   sh portal/tests/dev-server.sh demo-users               create a few local multiOTP users
#   sh portal/tests/dev-server.sh logs                     web server and worker output
#   sh portal/tests/dev-server.sh stop                     stop (data kept)
#   sh portal/tests/dev-server.sh reset                    stop and delete all preview data
set -eu
NAME=multiotp-portal-dev
LDAP=multiotp-test-ldap
NETWORK=multiotp-dev
VOLUME=multiotp-portal-dev-data
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DOCKERDIR="$REPO/portal/tests/docker"

case "${1:-start}" in
  start)
    echo "Building images (first time takes a minute)..."
    docker build -q -t multiotp-portal-php -f "$DOCKERDIR/php.Dockerfile" "$DOCKERDIR" >/dev/null
    docker build -q -t multiotp-test-ldap "$DOCKERDIR/ldap" >/dev/null
    docker network create "$NETWORK" >/dev/null 2>&1 || true
    docker rm -f "$NAME" "$LDAP" >/dev/null 2>&1 || true
    docker run -d --name "$LDAP" --network "$NETWORK" --network-alias ldap multiotp-test-ldap >/dev/null
    docker run -d --name "$NAME" --network "$NETWORK" \
      -p 127.0.0.1:8080:8080 \
      -v "$REPO":/app:ro -v "$VOLUME":/data \
      -e MULTIOTP_ETC_DIR=/data/etc -e MULTIOTP_LOG_DIR=/data/log -e MULTIOTP_PORTAL_DATA=/data/portal \
      -e MULTIOTP_PORTAL_ALLOW_HTTP=1 -e MULTIOTP_PORTAL_ISSUER="multiOTP portal (dev)" \
      multiotp-portal-php sh -c '
        mkdir -p /data/etc/config /data/etc/users /data/etc/tokens /data/etc/devices /data/etc/groups /data/etc/ddns /data/log /data/portal
        php /app/portal/bin/worker.php --loop >/data/log/worker.log 2>&1 &
        echo READY
        exec php -d display_errors=stderr -S 0.0.0.0:8080 -t /app' >/dev/null
    printf 'Starting'
    until docker logs "$NAME" 2>&1 | grep -q READY; do printf '.'; sleep 1; done
    sleep 1
    echo " ready: http://localhost:8080/portal/"
    echo "Test directory for Directory settings: type Generic LDAP, server ldap, port 389, base DN dc=example,dc=test,"
    echo "  users DN ou=people,dc=example,dc=test, bind DN cn=multiotp-sync,ou=service,dc=example,dc=test, password sync-test-password"
    ;;
  admin)
    docker exec "$NAME" php /app/portal/bin/portal-admin.php create --username="${2:?username}" --role="${3:-superadmin}"
    ;;
  cli)
    shift
    docker exec "$NAME" php /app/portal/bin/portal-admin.php "$@"
    ;;
  demo-users)
    docker exec "$NAME" php -r '
      define("PORTAL_ROOT", "/app/portal");
      require PORTAL_ROOT . "/src/bootstrap.php";
      $m = Portal\MultiotpService::get();
      foreach (["anna.demo", "ben.demo", "chloe.demo", "david.demo"] as $u) {
        if (!$m->CheckUserExists($u)) { $m->CreateUser($u, 0, "totp", bin2hex(random_bytes(20)), "", 6, 30, "", "", "Demo user"); }
      }
      $m->SetUser("david.demo"); $m->LockUser();
      echo "Demo users: anna.demo, ben.demo, chloe.demo, david.demo (locked)\n";'
    ;;
  logs)
    docker logs --tail 60 "$NAME"
    echo "--- worker"
    docker exec "$NAME" tail -n 40 /data/log/worker.log
    ;;
  stop)
    docker rm -f "$NAME" "$LDAP" >/dev/null && echo stopped
    ;;
  reset)
    docker rm -f "$NAME" "$LDAP" >/dev/null 2>&1 || true
    docker volume rm "$VOLUME" >/dev/null 2>&1 || true
    echo "preview stopped and data deleted"
    ;;
  *)
    sed -n '2,15p' "$0"
    exit 1
    ;;
esac
