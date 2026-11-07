# Throwaway OpenLDAP directory for portal development and tests (NOT for production).
# Domain dc=example,dc=test, memberOf overlay enabled, sample users and groups from seed.ldif.
# Service account for multiOTP:  cn=multiotp-sync,ou=service,dc=example,dc=test / sync-test-password
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN echo "slapd slapd/no_configuration boolean false" | debconf-set-selections \
 && echo "slapd slapd/domain string example.test" | debconf-set-selections \
 && echo "slapd shared/organization string Example Test" | debconf-set-selections \
 && echo "slapd slapd/password1 password admin-test-password" | debconf-set-selections \
 && echo "slapd slapd/password2 password admin-test-password" | debconf-set-selections \
 && echo "slapd slapd/purge_database boolean true" | debconf-set-selections \
 && echo "slapd slapd/move_old_database boolean true" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends slapd ldap-utils \
 && rm -rf /var/lib/apt/lists/*
COPY memberof.ldif seed.ldif /seed/
RUN mkdir -p /run/slapd && chown openldap:openldap /run/slapd \
 && slapd -h "ldapi:///" -u openldap -g openldap \
 && sleep 1 \
 && ldapmodify -Q -Y EXTERNAL -H ldapi:/// -f /seed/memberof.ldif \
 && ldapadd -x -H ldapi:/// -D cn=admin,dc=example,dc=test -w admin-test-password -f /seed/seed.ldif \
 && kill "$(cat /run/slapd/slapd.pid)" && sleep 1
EXPOSE 389
CMD ["sh", "-c", "mkdir -p /run/slapd && chown openldap:openldap /run/slapd && exec slapd -d 0 -h 'ldap:/// ldapi:///' -u openldap -g openldap"]
