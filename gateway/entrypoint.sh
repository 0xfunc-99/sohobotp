#!/bin/sh
# SohobOTP login gateway: render the nginx configuration, then run PHP-FPM and nginx.
set -eu
mkdir -p /data
if [ ! -s /data/gateway.key ]; then
  head -c 32 /dev/urandom > /data/gateway.key   # signs the session cookies; a new key signs everyone out
fi
chown www-data:www-data /data /data/gateway.key
chmod 0700 /data
chmod 0600 /data/gateway.key
php /app/render.php
nginx -t -q
php-fpm -D
exec nginx -g 'daemon off;'
