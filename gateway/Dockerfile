# SohobOTP login gateway: sign-in with a SohobOTP code in front of web sites (README.md).
FROM php:8.4-fpm-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends nginx \
 && rm -rf /var/lib/apt/lists/* /etc/nginx/sites-enabled/default \
 && mkdir -p /etc/sohobotp-gateway /data \
 && sed -i 's/^;\?clear_env.*/clear_env = yes/' /usr/local/etc/php-fpm.d/www.conf \
 && { echo 'expose_php = Off'; echo 'log_errors = On'; echo 'error_log = /proc/self/fd/2'; } > /usr/local/etc/php/conf.d/gateway.ini \
 && ln -sf /dev/stdout /var/log/nginx/access.log && ln -sf /dev/stderr /var/log/nginx/error.log
COPY gateway.php render.php entrypoint.sh /app/
RUN chmod 0755 /app/entrypoint.sh && chmod 0644 /app/gateway.php /app/render.php
VOLUME /data
ENTRYPOINT ["/app/entrypoint.sh"]
