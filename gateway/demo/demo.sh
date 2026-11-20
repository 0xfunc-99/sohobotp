#!/bin/sh
# Demo: Prometheus and Grafana that can only be opened through the SohobOTP login gateway.
#   sh gateway/demo/demo.sh start | stop
# Needs the portal's API key (permission "Check a user's code") and CA in the Docker volume
# sohobotp-demo-data (api-key, portal-ca.pem): the web-login example's first run saves them there.
# Prometheus and Grafana have NO published port: only the gateway reaches them.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
PORTAL="${SOHOBOTP_PORTAL:-https://172.16.196.1}"
BIND="${GATEWAY_BIND:-172.16.196.1}"   # also on 127.0.0.1
NET=sohobotp-gateway-demo
case "${1:-}" in
  stop)
    docker rm -f sohobotp-gateway demo-prometheus demo-grafana >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    echo stopped; exit 0 ;;
  start) ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
docker build -q -t sohobotp-gateway:latest "$HERE/.." >/dev/null
docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
docker rm -f sohobotp-gateway demo-prometheus demo-grafana >/dev/null 2>&1 || true
docker run -d --name demo-prometheus --network "$NET" --network-alias prometheus --restart unless-stopped \
  -v "$HERE/prometheus.yml":/etc/prometheus/prometheus.yml:ro prom/prometheus:v2.55.1 >/dev/null
docker run -d --name demo-grafana --network "$NET" --network-alias grafana --restart unless-stopped \
  -e GF_AUTH_PROXY_ENABLED=true -e GF_AUTH_PROXY_HEADER_NAME=X-WEBAUTH-USER -e GF_AUTH_PROXY_HEADER_PROPERTY=username \
  -e GF_AUTH_PROXY_AUTO_SIGN_UP=true -e GF_AUTH_DISABLE_LOGIN_FORM=true -e GF_AUTH_DISABLE_SIGNOUT_MENU=true \
  -e GF_USERS_AUTO_ASSIGN_ORG_ROLE=Editor -e GF_ANALYTICS_REPORTING_ENABLED=false -e GF_ANALYTICS_CHECK_FOR_UPDATES=false \
  -v "$HERE/grafana-datasource.yml":/etc/grafana/provisioning/datasources/prometheus.yml:ro grafana/grafana:11.3.0 >/dev/null
docker run -d --name sohobotp-gateway --network "$NET" --restart unless-stopped \
  -p 127.0.0.1:9091:9091 -p 127.0.0.1:3001:3001 -p "$BIND":9091:9091 -p "$BIND":3001:3001 \
  -v "$HERE/sites.json":/etc/sohobotp-gateway/sites.json:ro -v sohobotp-gateway-data:/data -v sohobotp-demo-data:/portal:ro \
  -e SOHOBOTP_PORTAL="$PORTAL" -e SOHOBOTP_API_KEY_FILE=/portal/api-key -e SOHOBOTP_CA=/portal/portal-ca.pem sohobotp-gateway:latest >/dev/null
echo "Prometheus: http://$BIND:9091   Grafana: http://$BIND:3001   (and 127.0.0.1)"
