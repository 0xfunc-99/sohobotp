#!/bin/sh
# Local preview of the portal on http://localhost:8080/portal/ (plain HTTP, for testing only).
# Code is mounted live from this checkout; data persists in the Docker volume "multiotp-portal-dev-data".
#
#   sh portal/tests/dev-server.sh start                   start (or restart) the preview
#   sh portal/tests/dev-server.sh admin <username> [role] create an administrator, prints a temporary password
#   sh portal/tests/dev-server.sh cli <portal-admin args>  any portal-admin.php command (list, unlock --username=..)
#   sh portal/tests/dev-server.sh demo-users               create a few multiOTP users so the dashboard has data
#   sh portal/tests/dev-server.sh logs                     PHP server output
#   sh portal/tests/dev-server.sh stop                     stop (data kept)
#   sh portal/tests/dev-server.sh reset                    stop and delete all preview data
set -eu
NAME=multiotp-portal-dev
VOLUME=multiotp-portal-dev-data
REPO="$(cd "$(dirname "$0")/../.." && pwd)"

case "${1:-start}" in
  start)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" \
      -p 127.0.0.1:8080:8080 \
      -v "$REPO":/app:ro -v "$VOLUME":/data \
      -e MULTIOTP_ETC_DIR=/data/etc -e MULTIOTP_LOG_DIR=/data/log -e MULTIOTP_PORTAL_DATA=/data/portal \
      -e MULTIOTP_PORTAL_ALLOW_HTTP=1 -e MULTIOTP_PORTAL_ISSUER="multiOTP portal (dev)" \
      php:8.4-cli sh -c '
        docker-php-ext-install bcmath >/dev/null 2>&1
        mkdir -p /data/etc/config /data/etc/users /data/etc/tokens /data/etc/devices /data/etc/groups /data/etc/ddns /data/log /data/portal
        echo READY
        exec php -d display_errors=stderr -S 0.0.0.0:8080 -t /app' >/dev/null
    printf 'Starting'
    until docker logs "$NAME" 2>&1 | grep -q READY; do printf '.'; sleep 1; done
    sleep 1
    echo " ready: http://localhost:8080/portal/"
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
    docker logs --tail 100 "$NAME"
    ;;
  stop)
    docker rm -f "$NAME" >/dev/null && echo stopped
    ;;
  reset)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker volume rm "$VOLUME" >/dev/null 2>&1 || true
    echo "preview stopped and data deleted"
    ;;
  *)
    sed -n '2,13p' "$0"
    exit 1
    ;;
esac
