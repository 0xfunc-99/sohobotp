# PHP 8.4 with the extensions multiOTP and the portal need (ldap, bcmath, mysqli, sodium, mbstring).
# Used by tests/run-in-docker.sh and tests/dev-server.sh; not a production image.
FROM php:8.4-cli
RUN apt-get update \
 && apt-get install -y --no-install-recommends libldap2-dev ldap-utils \
 && docker-php-ext-install ldap bcmath mysqli \
 && rm -rf /var/lib/apt/lists/*
